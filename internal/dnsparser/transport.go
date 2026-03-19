// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package dnsparser

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"

	baseCodec "masterdnsvpn-go/internal/basecodec"
	"masterdnsvpn-go/internal/compression"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var (
	ErrTXTAnswerMissing   = errors.New("dns txt answer missing")
	ErrTXTAnswerMalformed = errors.New("dns txt answer malformed")
	ErrTXTAnswerTooLarge  = errors.New("dns txt answer too large")
)

const (
	maxDNSNameLen       = 253
	maxDNSLabelLen      = 63
	maxTXTAnswerPayload = 255
	maxTXTEncodedChunk  = 191
)

func BuildTXTQuestionPacket(name string, qType uint16, ednsUDPSize uint16) ([]byte, error) {
	qname, err := encodeDNSNameStrict(name)
	if err != nil {
		return nil, err
	}

	requestID, err := randomUint16()
	if err != nil {
		return nil, err
	}

	arCount := uint16(0)
	optLen := 0
	if ednsUDPSize > 0 {
		arCount = 1
		optLen = 11
	}

	packet := make([]byte, dnsHeaderSize+len(qname)+4+optLen)
	binary.BigEndian.PutUint16(packet[0:2], requestID)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qType)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	offset += 4

	if ednsUDPSize > 0 {
		packet[offset] = 0x00
		offset++
		binary.BigEndian.PutUint16(packet[offset:offset+2], Enums.DNS_RECORD_TYPE_OPT)
		offset += 2
		binary.BigEndian.PutUint16(packet[offset:offset+2], ednsUDPSize)
		offset += 2
		offset += 4
		binary.BigEndian.PutUint16(packet[offset:offset+2], 0)
	}

	return packet, nil
}

func BuildTXTResponsePacket(questionPacket []byte, answerName string, answerPayloads [][]byte) ([]byte, error) {
	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount := extractQuestionSection(questionPacket, header)
	optRecords := [][]byte(nil)
	if len(questionBytes) > 0 || header.QDCount == 0 {
		optRecords = extractOPTRecordsFromOffset(questionPacket, header, dnsHeaderSize+len(questionBytes))
	}

	nameBytes, err := encodeDNSNameStrict(answerName)
	if err != nil {
		return nil, err
	}

	answerLen := 0
	useAnswerNameCompression := len(answerPayloads) > 1
	for i, payload := range answerPayloads {
		nameLen := len(nameBytes)
		if useAnswerNameCompression && i > 0 {
			nameLen = 2
		}
		answerLen += nameLen + 10 + len(payload)
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+answerLen+rawRecordsLen(optRecords))
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answerPayloads)))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(len(optRecords)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	firstAnswerNameOffset := offset

	for i, payload := range answerPayloads {
		if useAnswerNameCompression && i > 0 && firstAnswerNameOffset <= 0x3FFF {
			binary.BigEndian.PutUint16(response[offset:offset+2], uint16(0xC000|firstAnswerNameOffset))
			offset += 2
		} else {
			offset += copy(response[offset:], nameBytes)
		}
		binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_TXT)
		binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
		binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
		binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(payload)))
		offset += 10
		offset += copy(response[offset:], payload)
	}

	for _, record := range optRecords {
		offset += copy(response[offset:], record)
	}

	return response, nil
}

func BuildVPNResponsePacket(questionPacket []byte, answerName string, packet VpnProto.Packet, baseEncode bool) ([]byte, error) {
	rawFrame, err := VpnProto.BuildRawAuto(VpnProto.BuildOptions{
		SessionID:       packet.SessionID,
		PacketType:      packet.PacketType,
		SessionCookie:   packet.SessionCookie,
		StreamID:        packet.StreamID,
		SequenceNum:     packet.SequenceNum,
		FragmentID:      packet.FragmentID,
		TotalFragments:  packet.TotalFragments,
		CompressionType: packet.CompressionType,
		Payload:         packet.Payload,
	}, compression.DefaultMinSize)

	if err != nil {
		return nil, err
	}

	answerPayloads, err := buildTXTAnswerChunks(rawFrame, baseEncode)
	if err != nil {
		return nil, err
	}

	return BuildTXTResponsePacket(questionPacket, answerName, answerPayloads)
}

func ExtractVPNResponse(packet []byte, baseEncoded bool) (VpnProto.Packet, error) {
	parsed, err := ParsePacket(packet)
	if err != nil {
		return VpnProto.Packet{}, err
	}

	rawAnswers := extractTXTAnswerPayloads(parsed)
	if len(rawAnswers) == 0 {
		return VpnProto.Packet{}, ErrTXTAnswerMissing
	}

	return assembleVPNResponse(rawAnswers, baseEncoded)
}

func CalculateMaxEncodedQNameChars(domain string) int {
	domainLen := len(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domainLen <= 0 {
		return maxDNSNameLen
	}

	low := 0
	high := maxDNSNameLen
	best := 0
	for low <= high {
		mid := (low + high) / 2
		if encodedQNameLen(mid, domainLen) <= maxDNSNameLen {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func EncodeDataToLabels(data string) string {
	if len(data) <= maxDNSLabelLen {
		return data
	}

	var b strings.Builder
	b.Grow(len(data) + len(data)/maxDNSLabelLen)
	for start := 0; start < len(data); start += maxDNSLabelLen {
		if start > 0 {
			b.WriteByte('.')
		}
		end := start + maxDNSLabelLen
		if end > len(data) {
			end = len(data)
		}
		b.WriteString(data[start:end])
	}
	return b.String()
}

func BuildTunnelQuestionName(domain string, encodedFrame string) (string, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return "", ErrInvalidName
	}
	if encodedFrame == "" {
		return domain, nil
	}

	name := EncodeDataToLabels(encodedFrame) + "." + domain
	if len(name) > maxDNSNameLen {
		return "", ErrInvalidName
	}
	return name, nil
}

func buildTXTAnswerChunks(rawFrame []byte, baseEncode bool) ([][]byte, error) {
	maxChunk := maxTXTAnswerPayload
	if baseEncode {
		maxChunk = maxTXTEncodedChunk
	}

	if len(rawFrame) == 0 {
		return [][]byte{appendLengthPrefixedTXT(nil)}, nil
	}

	if len(rawFrame) <= maxChunk {
		return [][]byte{buildTXTAnswerChunk(rawFrame, baseEncode)}, nil
	}

	header, err := VpnProto.Parse(rawFrame)
	if err != nil {
		return [][]byte{buildTXTAnswerChunk(rawFrame, baseEncode)}, nil
	}

	headerLen := header.HeaderLength
	chunk0PrefixLen := 2
	maxChunk0Data := max(maxChunk-chunk0PrefixLen-headerLen, 0)

	remaining := len(header.Payload) - maxChunk0Data
	maxChunkNData := maxChunk - 1
	totalChunks := 1
	if remaining > 0 {
		totalChunks += (remaining + maxChunkNData - 1) / maxChunkNData
	}
	if totalChunks > 255 {
		return nil, ErrTXTAnswerTooLarge
	}

	chunks := make([][]byte, 0, totalChunks)
	chunk0DataLen := min(maxChunk0Data, len(header.Payload))
	rawChunk0 := make([]byte, 2+headerLen+chunk0DataLen)
	rawChunk0[0] = 0x00
	rawChunk0[1] = byte(totalChunks)
	copy(rawChunk0[2:], rawFrame[:headerLen])
	copy(rawChunk0[2+headerLen:], header.Payload[:chunk0DataLen])

	if !baseEncode {
		chunks = append(chunks, appendLengthPrefixedTXT(rawChunk0))
		return appendRawTXTAnswerChunks(chunks, header.Payload, maxChunk0Data, maxChunkNData), nil
	}

	chunks = append(chunks, appendLengthPrefixedTXT(baseCodec.EncodeRawBase64(rawChunk0)))
	return appendBase64TXTAnswerChunks(chunks, header.Payload, maxChunk0Data, maxChunkNData), nil
}

func buildTXTAnswerChunk(data []byte, baseEncode bool) []byte {
	if !baseEncode {
		return appendLengthPrefixedTXT(data)
	}
	return appendLengthPrefixedBase64TXT(data)
}

func appendRawTXTAnswerChunks(chunks [][]byte, payload []byte, cursor int, maxChunkNData int) [][]byte {
	for chunkID := 1; cursor < len(payload); chunkID++ {
		end := min(cursor+maxChunkNData, len(payload))
		chunks = append(chunks, buildLengthPrefixedTXTChunk(byte(chunkID), payload[cursor:end]))
		cursor = end
	}
	return chunks
}

func appendBase64TXTAnswerChunks(chunks [][]byte, payload []byte, cursor int, maxChunkNData int) [][]byte {
	rawChunk := make([]byte, 1+maxChunkNData)
	for chunkID := 1; cursor < len(payload); chunkID++ {
		end := min(cursor+maxChunkNData, len(payload))
		rawChunk[0] = byte(chunkID)
		size := copy(rawChunk[1:], payload[cursor:end])
		chunks = append(chunks, appendLengthPrefixedBase64TXT(rawChunk[:1+size]))
		cursor = end
	}
	return chunks
}

func buildLengthPrefixedTXTChunk(prefix byte, data []byte) []byte {
	out := make([]byte, 2+len(data))
	out[0] = byte(1 + len(data))
	out[1] = prefix
	copy(out[2:], data)
	return out
}

func appendLengthPrefixedTXT(data []byte) []byte {
	if len(data) <= 255 {
		out := make([]byte, 1+len(data))
		out[0] = byte(len(data))
		copy(out[1:], data)
		return out
	}

	parts := 1 + (len(data)-1)/255
	out := make([]byte, 0, len(data)+parts)
	for start := 0; start < len(data); start += 255 {
		end := start + 255
		if end > len(data) {
			end = len(data)
		}
		out = append(out, byte(end-start))
		out = append(out, data[start:end]...)
	}
	return out
}

func appendLengthPrefixedBase64TXT(data []byte) []byte {
	encodedLen := baseCodec.EncodedRawBase64Len(len(data))
	out := make([]byte, 1, 1+encodedLen)
	out[0] = byte(encodedLen)
	return baseCodec.EncodeRawBase64To(out, data)
}

func extractTXTAnswerPayloads(parsed Packet) [][]byte {
	if len(parsed.Answers) == 0 {
		return nil
	}

	payloads := make([][]byte, 0, len(parsed.Answers))
	for _, answer := range parsed.Answers {
		if answer.Type != Enums.DNS_RECORD_TYPE_TXT {
			continue
		}
		raw := extractTXTBytes(answer.RData)
		if len(raw) == 0 {
			continue
		}
		payloads = append(payloads, raw)
	}
	return payloads
}

func extractTXTBytes(rData []byte) []byte {
	if len(rData) == 0 {
		return nil
	}
	if int(rData[0])+1 == len(rData) {
		return rData[1:]
	}

	out := make([]byte, 0, len(rData))
	for offset := 0; offset < len(rData); {
		size := int(rData[offset])
		offset++
		if size == 0 {
			continue
		}
		if offset+size > len(rData) {
			out = append(out, rData[offset:]...)
			break
		}
		out = append(out, rData[offset:offset+size]...)
		offset += size
	}
	return out
}

func assembleVPNResponse(rawAnswers [][]byte, baseEncoded bool) (VpnProto.Packet, error) {
	if len(rawAnswers) == 1 {
		raw := rawAnswers[0]
		if baseEncoded {
			decoded, err := baseCodec.DecodeRawBase64(raw)
			if err != nil {
				return VpnProto.Packet{}, err
			}
			raw = decoded
		}
		return VpnProto.ParseInflated(raw)
	}

	var chunks [256][]byte
	totalExpected := 0
	seenChunks := 0
	var header VpnProto.Packet
	headerSeen := false

	for _, raw := range rawAnswers {
		if baseEncoded {
			decoded, err := baseCodec.DecodeRawBase64(raw)
			if err != nil {
				return VpnProto.Packet{}, err
			}
			raw = decoded
		}
		if len(raw) == 0 {
			continue
		}

		if raw[0] == 0x00 {
			if len(raw) < 3 {
				return VpnProto.Packet{}, ErrTXTAnswerMalformed
			}
			totalExpected = int(raw[1])
			if totalExpected <= 0 || totalExpected > len(chunks) {
				return VpnProto.Packet{}, ErrTXTAnswerMalformed
			}
			parsed, err := VpnProto.ParseAtOffset(raw, 2)
			if err != nil {
				return VpnProto.Packet{}, err
			}
			header = parsed
			headerSeen = true
			if chunks[0] == nil {
				seenChunks++
			}
			chunks[0] = parsed.Payload
			continue
		}

		chunkID := int(raw[0])
		if chunkID >= len(chunks) {
			return VpnProto.Packet{}, ErrTXTAnswerMalformed
		}
		if chunks[chunkID] == nil {
			seenChunks++
		}
		chunks[chunkID] = raw[1:]
	}

	if !headerSeen || totalExpected <= 0 || seenChunks != totalExpected {
		return VpnProto.Packet{}, ErrTXTAnswerMalformed
	}
	for i := range totalExpected {
		if chunks[i] == nil {
			return VpnProto.Packet{}, ErrTXTAnswerMalformed
		}
	}
	for i := totalExpected; i < len(chunks); i++ {
		if chunks[i] != nil {
			return VpnProto.Packet{}, ErrTXTAnswerMalformed
		}
	}

	payloadLen := 0
	for i := range totalExpected {
		payloadLen += len(chunks[i])
	}

	payload := make([]byte, 0, payloadLen)
	for i := range totalExpected {
		payload = append(payload, chunks[i]...)
	}
	header.Payload = payload
	return VpnProto.InflatePayload(header)
}

func encodeDNSNameStrict(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}, nil
	}
	if len(name) > maxDNSNameLen {
		return nil, ErrInvalidName
	}

	labels := strings.Split(name, ".")
	encoded := make([]byte, 0, len(name)+2)
	for _, label := range labels {
		if label == "" || len(label) > maxDNSLabelLen {
			return nil, ErrInvalidName
		}
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	encoded = append(encoded, 0)
	return encoded, nil
}

func encodedQNameLen(encodedChars int, domainLen int) int {
	if encodedChars <= 0 {
		return domainLen
	}
	labelSplits := (encodedChars - 1) / maxDNSLabelLen
	return encodedChars + labelSplits + 1 + domainLen
}

func randomUint16() (uint16, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
