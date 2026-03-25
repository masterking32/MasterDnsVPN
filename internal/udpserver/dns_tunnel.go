// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"net"
	"strings"
	"time"

	"masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/inflight"
)

var ErrInvalidDNSUpstream = errors.New("invalid dns upstream")

type dnsFragmentKey struct {
	sessionID   uint8
	sequenceNum uint16
}

type dnsResolveInflightEntry = inflight.Entry[[]byte]

type dnsResolveInflightManager struct {
	inner *inflight.Manager[[]byte]
}

func newDNSResolveInflightManager(timeout time.Duration) *dnsResolveInflightManager {
	return &dnsResolveInflightManager{
		inner: inflight.New(timeout, 16*time.Second, cloneInflightBytes),
	}
}

func (m *dnsResolveInflightManager) Acquire(cacheKey string, now time.Time) (*dnsResolveInflightEntry, bool) {
	if m == nil {
		return nil, false
	}
	return m.inner.Acquire(cacheKey, now)
}

func (m *dnsResolveInflightManager) Resolve(cacheKey string, response []byte) {
	if m == nil {
		return
	}
	m.inner.Resolve(cacheKey, response, len(response) != 0)
}

func (m *dnsResolveInflightManager) Wait(entry *dnsResolveInflightEntry, timeout time.Duration) ([]byte, bool) {
	if m == nil {
		return nil, false
	}
	return m.inner.Wait(entry, timeout)
}

func cloneInflightBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return append([]byte(nil), value...)
}

func (s *Server) buildDNSQueryResponsePayload(rawQuery []byte, sessionID uint8, sequenceNum uint16) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(rawQuery)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}
		response, responseErr := DnsParser.BuildFormatErrorResponse(rawQuery)
		if responseErr != nil {
			return nil
		}
		return response
	}

	if !parsed.HasQuestion {
		response, responseErr := DnsParser.BuildFormatErrorResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	if !DnsParser.IsSupportedTunnelDNSQuery(parsed.FirstQuestion.Type, parsed.FirstQuestion.Class) {
		response, responseErr := DnsParser.BuildNotImplementedResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	cacheKey := dnscache.BuildKey(parsed.FirstQuestion.Name, parsed.FirstQuestion.Type, parsed.FirstQuestion.Class)
	now := time.Now()
	if cached, ok := s.dnsCache.GetReady(cacheKey, rawQuery, now); ok {
		if s.log != nil {
			s.log.Debugf(
				"🧠 <green>Tunnel DNS Cache Hit</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		return cached
	}

	inflightEntry, leader := s.dnsResolveInflight.Acquire(cacheKey, now)
	if !leader {
		if s.log != nil {
			s.log.Debugf(
				"\U0001F9E9 <green>Tunnel DNS Inflight Reused</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		waitTimeout := s.cfg.DNSInflightWaitTimeout()
		if waitTimeout <= 0 {
			waitTimeout = 8 * time.Second
		}
		if resolved, ok := s.dnsResolveInflight.Wait(inflightEntry, waitTimeout); ok && len(resolved) != 0 {
			return dnscache.PatchResponseForQuery(resolved, rawQuery)
		}
		if cached, ok := s.dnsCache.GetReady(cacheKey, rawQuery, now); ok {
			return cached
		}
		response, responseErr := DnsParser.BuildServerFailureResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	resolved, err := s.resolveDNSUpstream(rawQuery)
	if s.log != nil {
		s.log.Debugf(
			"🔎 <green>Tunnel DNS Upstream Lookup</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
			parsed.FirstQuestion.Name,
			Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
			sessionID,
			sequenceNum,
		)
	}
	s.dnsResolveInflight.Resolve(cacheKey, resolved)
	if err != nil || len(resolved) == 0 {
		if s.log != nil {
			s.log.Debugf(
				"⚠️ <yellow>Tunnel DNS Upstream Failed</yellow> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		response, responseErr := DnsParser.BuildServerFailureResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	s.dnsCache.SetReady(
		cacheKey,
		parsed.FirstQuestion.Name,
		parsed.FirstQuestion.Type,
		parsed.FirstQuestion.Class,
		resolved,
		now,
	)
	if s.log != nil {
		s.log.Debugf(
			"🌍 <green>Tunnel DNS Resolved Upstream</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Bytes</blue>: <cyan>%d</cyan>",
			parsed.FirstQuestion.Name,
			Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
			sessionID,
			sequenceNum,
			len(resolved),
		)
	}
	return resolved
}

func (s *Server) collectDNSQueryFragments(sessionID uint8, sequenceNum uint16, payload []byte, fragmentID uint8, totalFragments uint8, now time.Time) ([]byte, bool, bool) {
	if totalFragments == 0 {
		totalFragments = 1
	}
	assembled, ready, completed := s.dnsFragments.Collect(
		dnsFragmentKey{
			sessionID:   sessionID,
			sequenceNum: sequenceNum,
		},
		payload,
		fragmentID,
		totalFragments,
		now,
		s.dnsFragmentTimeout,
	)
	return assembled, ready, completed
}

func (s *Server) purgeDNSQueryFragments(now time.Time) {
	if s == nil || s.dnsFragments == nil {
		return
	}
	s.dnsFragments.Purge(now, s.dnsFragmentTimeout)
}

func (s *Server) removeDNSQueryFragmentsForSession(sessionID uint8) {
	if s == nil || s.dnsFragments == nil || sessionID == 0 {
		return
	}
	s.dnsFragments.RemoveIf(func(key dnsFragmentKey) bool {
		return key.sessionID == sessionID
	})
}

func (s *Server) fragmentDNSResponsePayload(response []byte, mtu int) [][]byte {
	if len(response) == 0 {
		return nil
	}
	limit := mtu
	if limit < 1 {
		limit = 256
	}
	if len(response) <= limit {
		return [][]byte{response}
	}

	total := (len(response) + limit - 1) / limit
	if total > 255 {
		return nil
	}

	fragments := make([][]byte, 0, total)
	for start := 0; start < len(response); start += limit {
		end := start + limit
		if end > len(response) {
			end = len(response)
		}
		fragments = append(fragments, response[start:end])
	}
	return fragments
}

func (s *Server) resolveDNSUpstream(rawQuery []byte) ([]byte, error) {
	if s != nil && s.resolveDNSQueryFn != nil {
		return s.resolveDNSQueryFn(rawQuery)
	}
	if len(rawQuery) == 0 || len(s.dnsUpstreamServers) == 0 {
		return nil, ErrInvalidDNSUpstream
	}

	timeout := s.cfg.DNSUpstreamTimeout()
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	for _, upstream := range s.dnsUpstreamServers {
		conn, err := newUDPUpstreamConn(upstream)
		if err != nil {
			continue
		}

		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, writeErr := conn.Write(rawQuery)
		if writeErr != nil {
			_ = conn.Close()
			continue
		}

		buffer := s.dnsUpstreamBufferPool.Get().([]byte)
		n, readErr := conn.Read(buffer)
		_ = conn.Close()
		if readErr == nil && n > 0 {
			response := append([]byte(nil), buffer[:n]...)
			s.dnsUpstreamBufferPool.Put(buffer)
			return response, nil
		}
		s.dnsUpstreamBufferPool.Put(buffer)
	}

	return nil, ErrInvalidDNSUpstream
}

func newUDPUpstreamConn(endpoint string) (*net.UDPConn, error) {
	host, port, err := splitHostPortDefault53(endpoint)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, addr)
}

func splitHostPortDefault53(value string) (string, string, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return "", "", ErrInvalidDNSUpstream
	}

	if strings.HasPrefix(text, "[") {
		host, port, err := net.SplitHostPort(text)
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}

	if strings.Count(text, ":") == 0 {
		return text, "53", nil
	}
	if strings.Count(text, ":") == 1 {
		host, port, err := net.SplitHostPort(text)
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}

	return text, "53", nil
}
