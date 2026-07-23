// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"masterdnsvpn-go/internal/logger"
)

func (s *Server) configureSocketBuffers(conn *net.UDPConn) {
	if err := conn.SetReadBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("\U0001F4E1 <yellow>UDP Read Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}

	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("\U0001F4E1 <yellow>UDP Write Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}
}

func (s *Server) openUDPListeners() ([]*net.UDPConn, error) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(s.cfg.UDPHost),
		Port: s.cfg.UDPPort,
	}
	desired := s.cfg.EffectiveUDPReaders()
	if desired < 1 {
		desired = 1
	}

	if desired > 1 {
		conns := make([]*net.UDPConn, 0, desired)
		for i := 0; i < desired; i++ {
			conn, err := listenUDPReusePort(addr)
			if err != nil {
				for _, opened := range conns {
					_ = opened.Close()
				}
				conns = nil
				break
			}
			s.configureSocketBuffers(conn)
			conns = append(conns, conn)
		}
		if len(conns) == desired {
			return conns, nil
		}
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	s.configureSocketBuffers(conn)
	return []*net.UDPConn{conn}, nil
}

func (s *Server) startDNSWorkers(ctx context.Context, conn *net.UDPConn, reqCh <-chan request, workerWG *sync.WaitGroup) {
	for i := range s.cfg.EffectiveDNSRequestWorkers() {
		workerWG.Add(1)
		go func(workerID int) {
			defer workerWG.Done()
			s.dnsWorker(ctx, conn, reqCh, workerID)
		}(i + 1)
	}
}

func (s *Server) startReaders(ctx context.Context, conns []*net.UDPConn, reqCh chan<- request, readErrCh chan<- error, readerWG *sync.WaitGroup) {
	if len(conns) == 0 {
		return
	}

	readerCount := s.cfg.EffectiveUDPReaders()
	if readerCount < 1 {
		readerCount = 1
	}

	if len(conns) > 1 {
		for i, conn := range conns {
			readerWG.Add(1)
			go func(readerID int, readerConn *net.UDPConn) {
				defer readerWG.Done()
				if err := s.readLoop(ctx, readerConn, reqCh, readerID); err != nil {
					select {
					case readErrCh <- err:
					default:
					}
				}
			}(i+1, conn)
		}
		return
	}

	conn := conns[0]
	for i := 0; i < readerCount; i++ {
		readerWG.Add(1)
		go func(readerID int) {
			defer readerWG.Done()
			if err := s.readLoop(ctx, conn, reqCh, readerID); err != nil {
				select {
				case readErrCh <- err:
				default:
				}
			}
		}(i + 1)
	}
}

func (s *Server) sessionCleanupLoop(ctx context.Context) {
	interval := s.cfg.SessionCleanupInterval()
	if interval <= 0 {
		interval = 30 * time.Second
	}
	recentlyClosedSweepInterval := 5 * time.Minute
	sessionTimeout := s.cfg.SessionTimeout()
	closedRetention := s.cfg.ClosedSessionRetention()
	invalidCookieWindow := s.invalidCookieWindow

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastRecentlyClosedSweep := time.Time{}

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			expired := s.sessions.Cleanup(now, sessionTimeout, closedRetention)
			idleDeferred := s.sessions.CollectIdleDeferredSessions(now, s.deferredIdleCleanupTimeout(interval, sessionTimeout))
			s.sessions.SweepTerminalStreams(now, s.cfg.TerminalStreamRetention())
			if lastRecentlyClosedSweep.IsZero() || now.Sub(lastRecentlyClosedSweep) >= recentlyClosedSweepInterval {
				s.sessions.SweepRecentlyClosedStreams(now)
				lastRecentlyClosedSweep = now
			}
			s.invalidCookieTracker.Cleanup(now, invalidCookieWindow)
			s.purgeDNSQueryFragments(now)
			s.purgeSOCKS5SynFragments(now)
			for _, idleSession := range idleDeferred {
				s.cleanupIdleDeferredSession(idleSession.ID, idleSession.lastActivityNano, now)
			}
			if len(expired) == 0 {
				continue
			}
			for _, expiredSession := range expired {
				s.cleanupClosedSession(expiredSession.ID, expiredSession.record)
			}
			s.log.Infof(
				"\U0001F4E1 <green>Expired Sessions Cleaned, Count: <cyan>%d</cyan></green>",
				len(expired),
			)
		}
	}
}

func (s *Server) deferredIdleCleanupTimeout(cleanupInterval time.Duration, sessionTimeout time.Duration) time.Duration {
	timeout := s.deferredConnectAttemptTimeout()
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 30 * time.Second
	}
	idle := timeout + cleanupInterval
	if sessionTimeout > 0 && sessionTimeout < idle {
		return sessionTimeout
	}
	return idle
}

func (s *Server) readLoop(ctx context.Context, conn *net.UDPConn, reqCh chan<- request, readerID int) error {
	for {
		buffer := s.packetPool.Get().([]byte)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			s.packetPool.Put(buffer)

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			s.log.Debugf(
				"\U0001F4A5 <yellow>UDP Read Error, Reader: <cyan>%d</cyan>, Error: <cyan>%v</cyan></yellow>",
				readerID,
				err,
			)
			return err
		}

		select {
		case reqCh <- request{buf: buffer, size: n, addr: addr, conn: conn}:
		case <-ctx.Done():
			s.packetPool.Put(buffer)
			return nil
		default:
			s.packetPool.Put(buffer)
			s.onDrop(addr, len(reqCh), cap(reqCh))
		}
	}
}

func (s *Server) dnsWorker(ctx context.Context, conn *net.UDPConn, reqCh <-chan request, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqCh:
			if !ok {
				return
			}

			response := s.safeHandlePacket(req.buf[:req.size])
			if len(response) != 0 {
				writeConn := conn
				if req.conn != nil {
					writeConn = req.conn
				}
				if _, err := writeConn.WriteToUDP(response, req.addr); err != nil {
					s.log.Debugf(
						"\U0001F4A5 <yellow>UDP Write Error, Worker: <cyan>%d</cyan>, Remote: <cyan>%v</cyan>, Error: <cyan>%v</cyan></yellow>",
						workerID,
						req.addr,
						err,
					)
				}
			}

			s.packetPool.Put(req.buf)
		}
	}
}

func (s *Server) safeHandlePacket(packet []byte) (response []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if s.log != nil {
				s.log.Errorf(
					"\U0001F4A5 <red>Packet Handler Panic Recovered, <yellow>%v</yellow></red>",
					recovered,
				)
			}
			response = nil
		}
	}()

	return s.handlePacket(packet)
}

func (s *Server) onDrop(addr *net.UDPAddr, queueLen int, queueCap int) {
	total := s.droppedPackets.Add(1)

	now := logger.NowUnixNano()
	last := s.lastDropLogUnix.Load()
	interval := s.dropLogIntervalNanos
	if interval <= 0 {
		interval = 2_000_000_000
	}
	if now-last < interval {
		return
	}
	if !s.lastDropLogUnix.CompareAndSwap(last, now) {
		return
	}

	s.log.Warnf(
		"\U0001F6A8 <yellow>Request Queue Overloaded</yellow> <magenta>|</magenta> <blue>Dropped</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Queue</blue>: <cyan>%d/%d</cyan> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%v</cyan>",
		total,
		queueLen,
		queueCap,
		addr,
	)
}
