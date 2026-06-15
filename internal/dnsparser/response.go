// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package dnsparser

import (
	"encoding/binary"

	Enums "masterdnsvpn-go/internal/enums"
)

const (
	maxLikelyQuestions  = 64
	maxLikelyAnswers    = 256
	maxLikelyAuthority  = 256
	maxLikelyAdditional = 256
)

func BuildEmptyNoErrorResponse(request []byte) ([]byte, error) {
	return buildResponseWithRCode(request, Enums.DNSR_CODE_NO_ERROR)
}

func BuildEmptyNoErrorResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_NO_ERROR)
}

func BuildNoDataResponse(request []byte) ([]byte, error) {
	parsed, err := ParseDNSRequestLite(request)
	if err != nil {
		return nil, err
	}
	return BuildNoDataResponseFromLite(request, parsed)
}

func BuildNoDataResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildNoDataResponseLite(request, parsed)
}

func BuildNameErrorResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildAuthoritativeResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_NAME_ERROR)
}

func BuildFormatErrorResponse(request []byte) ([]byte, error) {
	return buildResponseWithRCode(request, Enums.DNSR_CODE_FORMAT_ERROR)
}

func BuildFormatErrorResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_FORMAT_ERROR)
}

func BuildRefusedResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_REFUSED)
}

func BuildServerFailureResponse(request []byte) ([]byte, error) {
	return buildResponseWithRCode(request, Enums.DNSR_CODE_SERVER_FAILURE)
}

func BuildServerFailureResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_SERVER_FAILURE)
}

func BuildNotImplementedResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_NOT_IMPLEMENTED)
}

func buildResponseWithRCode(request []byte, rcode uint8) ([]byte, error) {
	if len(request) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(request)
	if !isLikelyDNSRequestHeader(header) {
		return nil, ErrNotDNSRequest
	}

	questionEndOffset, err := skipQuestions(request, dnsHeaderSize, int(header.QDCount))
	questionLen := 0
	questionCount := uint16(0)
	if err == nil && questionEndOffset >= dnsHeaderSize && questionEndOffset <= len(request) {
		questionLen = questionEndOffset - dnsHeaderSize
		questionCount = header.QDCount
	}

	optStart, optLen := findOPTRecordRange(request, header, questionEndOffset)

	response := make([]byte, dnsHeaderSize+questionLen+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, rcode))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	// ANCount, NSCount are 0
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	if questionLen > 0 {
		copy(response[dnsHeaderSize:], request[dnsHeaderSize:questionEndOffset])
	}
	if optLen > 0 {
		copy(response[dnsHeaderSize+questionLen:], request[optStart:optStart+optLen])
	}

	return response, nil
}

func buildResponseWithRCodeLite(request []byte, parsed LitePacket, rcode uint8) ([]byte, error) {
	return buildResponseWithFlagsLite(request, parsed, buildResponseFlags(parsed.Header.Flags, rcode))
}

func buildAuthoritativeResponseWithRCodeLite(request []byte, parsed LitePacket, rcode uint8) ([]byte, error) {
	return buildResponseWithFlagsLite(request, parsed, buildAuthoritativeResponseFlags(parsed.Header.Flags, rcode))
}

func buildResponseWithFlagsLite(request []byte, parsed LitePacket, flags uint16) ([]byte, error) {
	if len(request) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}
	if !isLikelyDNSRequestHeader(parsed.Header) {
		return nil, ErrNotDNSRequest
	}

	optStart, optLen := findOPTRecordRange(request, parsed.Header, parsed.QuestionEndOffset)

	questionLen := 0
	if parsed.QuestionEndOffset >= dnsHeaderSize && parsed.QuestionEndOffset <= len(request) {
		questionLen = parsed.QuestionEndOffset - dnsHeaderSize
	}

	response := make([]byte, dnsHeaderSize+questionLen+optLen)
	binary.BigEndian.PutUint16(response[0:2], parsed.Header.ID)
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], parsed.Header.QDCount)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	if questionLen > 0 {
		copy(response[dnsHeaderSize:], request[dnsHeaderSize:parsed.QuestionEndOffset])
	}
	if optLen > 0 {
		copy(response[dnsHeaderSize+questionLen:], request[optStart:optStart+optLen])
	}

	return response, nil
}

func buildNoDataResponseLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_NO_ERROR)
}

func getARCount(optLen int) int {
	if optLen > 0 {
		return 1
	}
	return 0
}

func isLikelyDNSRequestHeader(header Header) bool {
	if header.QR != 0 {
		return false
	}
	if header.QDCount == 0 || header.QDCount > maxLikelyQuestions {
		return false
	}
	if header.OpCode > 6 {
		return false
	}
	if header.ANCount > maxLikelyAnswers {
		return false
	}
	if header.NSCount > maxLikelyAuthority {
		return false
	}
	if header.ARCount > maxLikelyAdditional {
		return false
	}
	return true
}

func buildResponseFlags(requestFlags uint16, rcode uint8) uint16 {
	const (
		flagQR     uint16 = 1 << 15
		flagAA     uint16 = 1 << 10
		flagTC     uint16 = 1 << 9
		flagRD     uint16 = 1 << 8
		flagRA     uint16 = 1 << 7
		flagCD     uint16 = 1 << 4
		opcodeMask uint16 = 0x7800
	)

	flags := flagQR | flagRA | (requestFlags & opcodeMask) | uint16(rcode&0x0F)
	if requestFlags&flagRD != 0 {
		flags |= flagRD
	}
	if requestFlags&flagCD != 0 {
		flags |= flagCD
	}

	// Resolver-generated local answers should look recursive, not authoritative.
	// AA/TC are intentionally cleared unless we are relaying an upstream answer
	// verbatim, in which case those bits come from the upstream packet itself.
	flags &^= flagAA | flagTC
	return flags
}

func buildAuthoritativeResponseFlags(requestFlags uint16, rcode uint8) uint16 {
	const (
		flagQR     uint16 = 1 << 15
		flagAA     uint16 = 1 << 10
		flagTC     uint16 = 1 << 9
		flagRD     uint16 = 1 << 8
		flagRA     uint16 = 1 << 7
		flagCD     uint16 = 1 << 4
		opcodeMask uint16 = 0x7800
	)

	flags := flagQR | flagAA | (requestFlags & opcodeMask) | uint16(rcode&0x0F)
	if requestFlags&flagRD != 0 {
		flags |= flagRD
	}
	if requestFlags&flagCD != 0 {
		flags |= flagCD
	}

	flags &^= flagRA | flagTC
	return flags
}

func extractQuestionSection(request []byte, header Header) ([]byte, uint16, int) {
	if header.QDCount == 0 {
		return nil, 0, dnsHeaderSize
	}

	offset, err := skipQuestions(request, dnsHeaderSize, int(header.QDCount))
	if err != nil {
		return nil, 0, 0
	}

	return request[dnsHeaderSize:offset], header.QDCount, offset
}

func extractOPTRecordsFromRequest(request []byte, header Header, canWalk bool) ([][]byte, int) {
	if !canWalk || header.ARCount == 0 {
		return nil, 0
	}

	offset, err := skipQuestions(request, dnsHeaderSize, int(header.QDCount))
	if err != nil {
		return nil, 0
	}

	return extractOPTRecordsFromOffset(request, header, offset)
}

func extractOPTRecordsFromOffset(request []byte, header Header, questionEndOffset int) ([][]byte, int) {
	start, length := findOPTRecordRange(request, header, questionEndOffset)
	if length == 0 {
		return nil, 0
	}
	return [][]byte{request[start : start+length]}, length
}

func findOPTRecordRange(request []byte, header Header, questionEndOffset int) (int, int) {
	if header.ARCount == 0 || questionEndOffset < dnsHeaderSize || questionEndOffset > len(request) {
		return 0, 0
	}

	offset := questionEndOffset
	if header.ANCount > 0 {
		var err error
		offset, err = skipResourceRecords(request, offset, int(header.ANCount))
		if err != nil {
			return 0, 0
		}
	}

	if header.NSCount > 0 {
		var err error
		offset, err = skipResourceRecords(request, offset, int(header.NSCount))
		if err != nil {
			return 0, 0
		}
	}

	return findFirstOPTRecordInAdditional(request, offset, int(header.ARCount))
}

func findFirstOPTRecordInAdditional(data []byte, offset int, count int) (int, int) {
	for range count {
		recordStart := offset

		nextOffset, err := skipName(data, offset)
		if err != nil {
			return 0, 0
		}
		if nextOffset+10 > len(data) {
			return 0, 0
		}

		recordType := binary.BigEndian.Uint16(data[nextOffset : nextOffset+2])
		rdLen := int(binary.BigEndian.Uint16(data[nextOffset+8 : nextOffset+10]))
		recordEnd := nextOffset + 10 + rdLen
		if recordEnd > len(data) {
			return 0, 0
		}

		if recordType == Enums.DNS_RECORD_TYPE_OPT {
			return recordStart, recordEnd - recordStart
		}

		offset = recordEnd
	}

	return 0, 0
}

func skipQuestions(data []byte, offset int, count int) (int, error) {
	for range count {
		nextOffset, err := skipName(data, offset)
		if err != nil {
			return offset, ErrInvalidQuestion
		}
		if nextOffset+4 > len(data) {
			return offset, ErrInvalidQuestion
		}
		offset = nextOffset + 4
	}

	return offset, nil
}

func skipResourceRecords(data []byte, offset int, count int) (int, error) {
	for range count {
		nextOffset, err := skipName(data, offset)
		if err != nil {
			return offset, ErrInvalidAnswer
		}
		if nextOffset+10 > len(data) {
			return offset, ErrInvalidAnswer
		}

		rdLen := int(binary.BigEndian.Uint16(data[nextOffset+8 : nextOffset+10]))
		recordEnd := nextOffset + 10 + rdLen
		if recordEnd > len(data) {
			return offset, ErrInvalidAnswer
		}

		offset = recordEnd
	}

	return offset, nil
}

func extractRawOPTRecords(data []byte, offset int, count int) ([][]byte, int, int, error) {
	if count == 0 {
		return nil, 0, offset, nil
	}

	records := make([][]byte, 0, count)
	recordsLen := 0
	for range count {
		recordStart := offset

		nextOffset, err := skipName(data, offset)
		if err != nil {
			return nil, 0, offset, ErrInvalidAnswer
		}
		if nextOffset+10 > len(data) {
			return nil, 0, offset, ErrInvalidAnswer
		}

		recordType := binary.BigEndian.Uint16(data[nextOffset : nextOffset+2])
		rdLen := int(binary.BigEndian.Uint16(data[nextOffset+8 : nextOffset+10]))
		recordEnd := nextOffset + 10 + rdLen
		if recordEnd > len(data) {
			return nil, 0, offset, ErrInvalidAnswer
		}

		if recordType == Enums.DNS_RECORD_TYPE_OPT {
			record := data[recordStart:recordEnd]
			records = append(records, record)
			recordsLen += len(record)
		}

		offset = recordEnd
	}

	return records, recordsLen, offset, nil
}

func skipName(data []byte, offset int) (int, error) {
	dataLen := len(data)
	for {
		if offset >= dataLen {
			return offset, ErrInvalidName
		}

		length := int(data[offset])
		if length == 0 {
			return offset + 1, nil
		}

		if length >= 192 { // 0xC0
			if offset+1 >= dataLen {
				return offset, ErrInvalidName
			}
			return offset + 2, nil
		}

		if length > 63 {
			return offset, ErrInvalidName
		}

		offset += length + 1
	}
}
