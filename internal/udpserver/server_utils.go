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
	response, err := DnsParser.BuildNoDataResponse(packet)
	if err != nil {
		return nil
	}
	return response
}

func buildNoDataResponseLite(packet []byte, parsed DnsParser.LitePacket) []byte {
	response, err := DnsParser.BuildNoDataResponseFromLite(packet, parsed)
	if err != nil {
		return nil
	}
	return response
}

func buildNameErrorResponseLite(packet []byte, parsed DnsParser.LitePacket) []byte {
	response, err := DnsParser.BuildNameErrorResponseFromLite(packet, parsed)
	if err != nil {
		return nil
	}
	return response
}

func buildFormatErrorResponseLite(packet []byte, parsed DnsParser.LitePacket) []byte {
	response, err := DnsParser.BuildFormatErrorResponseFromLite(packet, parsed)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) buildNoDataResponseLogged(packet []byte, reason string) []byte {
	return buildNoDataResponse(packet)
}

func (s *Server) buildNoDataResponseLiteLogged(packet []byte, parsed DnsParser.LitePacket, reason string) []byte {
	return buildNoDataResponseLite(packet, parsed)
}

func (s *Server) buildNameErrorResponseLiteLogged(packet []byte, parsed DnsParser.LitePacket, reason string) []byte {
	return buildNameErrorResponseLite(packet, parsed)
}

func (s *Server) buildFormatErrorResponseLiteLogged(packet []byte, parsed DnsParser.LitePacket, reason string) []byte {
	return buildFormatErrorResponseLite(packet, parsed)
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

func fillMTUProbeBytes(dst []byte) {
	if len(dst) == 0 {
		return
	}
	clear(dst)
}
