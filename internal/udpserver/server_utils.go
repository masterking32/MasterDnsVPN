// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"encoding/binary"
	"fmt"

	"masterdnsvpn-go/internal/compression"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
)

func (s *Server) debugLoggingEnabled() bool {
	return s != nil && s.log != nil && s.log.Enabled(logger.LevelDebug)
}

func summarizeQName(name string) string {
	if len(name) <= 96 {
		return name
	}
	return fmt.Sprintf("%s...%s", name[:48], name[len(name)-24:])
}

func buildNoDataResponse(packet []byte) []byte {
	response, err := DnsParser.BuildEmptyNoErrorResponse(packet)
	if err != nil {
		return nil
	}
	return response
}

func buildNoDataResponseLite(packet []byte, parsed DnsParser.LitePacket) []byte {
	response, err := DnsParser.BuildEmptyNoErrorResponseFromLite(packet, parsed)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildNoDataResponseLogged(packet []byte, reason string) []byte {
	if s.debugLoggingEnabled() {
		s.log.Debugf("⚠️ <yellow>NoData response <magenta>|</magenta> Reason: <cyan>%s</cyan></yellow>", reason)
	}
	return buildNoDataResponse(packet)
}

func (s *Server) buildNoDataResponseLiteLogged(packet []byte, parsed DnsParser.LitePacket, reason string) []byte {
	if s.debugLoggingEnabled() {
		s.log.Debugf("⚠️ <yellow>NoData response <magenta>|</magenta> Reason: <cyan>%s</cyan></yellow>", reason)
	}
	return buildNoDataResponseLite(packet, parsed)
}

func isClosedStreamAwarePacketType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_SYN,
		Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_DATA_NACK,
		Enums.PACKET_STREAM_CLOSE_WRITE,
		Enums.PACKET_STREAM_CLOSE_READ,
		Enums.PACKET_STREAM_RST:
		return true
	default:
		return false
	}
}

func sessionResponseModeName(mode uint8) string {
	if mode == mtuProbeModeBase64 {
		return "BASE64"
	}
	return "RAW (Bytes)"
}

func buildCompressionMask(values []int) uint8 {
	var mask uint8 = 1 << compression.TypeOff
	for _, value := range values {
		if value < compression.TypeOff || value > compression.TypeZLIB || !compression.IsTypeAvailable(uint8(value)) {
			continue
		}
		mask |= 1 << uint8(value)
	}
	return mask
}

func parseMTUProbeBaseEncoding(mode uint8) (bool, bool) {
	switch mode {
	case mtuProbeModeRaw:
		return false, true
	case mtuProbeModeBase64:
		return true, true
	default:
		return false, false
	}
}

func buildMTUProbeMetaPayload(probeCode []byte, payloadLen int) [mtuProbeMetaLength]byte {
	var payload [mtuProbeMetaLength]byte
	copy(payload[:mtuProbeCodeLength], probeCode)
	binary.BigEndian.PutUint16(payload[mtuProbeCodeLength:], uint16(payloadLen))
	return payload
}

func buildMTUProbeFillPattern() [256]byte {
	var pattern [256]byte
	var state uint32 = 0x9E3779B9
	for i := range pattern {
		state = state*1664525 + 1013904223
		pattern[i] = byte(state >> 24)
	}
	return pattern
}

func fillMTUProbeBytes(dst []byte, pattern []byte) {
	if len(dst) == 0 || len(pattern) == 0 {
		return
	}

	copied := copy(dst, pattern)
	for copied < len(dst) {
		copied += copy(dst[copied:], dst[:copied])
	}
}
