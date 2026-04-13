// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package dnsparser

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrPacketTooShort  = errors.New("dns packet too short")
	ErrInvalidName     = errors.New("invalid dns name")
	ErrInvalidQuestion = errors.New("invalid dns question section")
	ErrInvalidAnswer   = errors.New("invalid dns resource record section")
	ErrSectionCountTooLarge = errors.New("dns section count too large")
	ErrNotDNSRequest   = errors.New("packet does not look like a supported dns request")
)

const (
	dnsHeaderSize = 12
	maxNameJumps  = 10
	maxSectionCount = 256
)

type Header struct {
	ID      uint16
	Flags   uint16
	QR      uint8
	OpCode  uint8
	AA      uint8
	TC      uint8
	RD      uint8
	RA      uint8
	Z       uint8
	RCode   uint8
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RDLen uint16
	RData []byte
}

type Packet struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additional  []ResourceRecord
}

type LitePacket struct {
	Header            Header
	Questions         []Question
	FirstQuestion     Question
	HasQuestion       bool
	QuestionEndOffset int
}

func ParsePacketLite(data []byte) (LitePacket, error) {
	if len(data) < dnsHeaderSize {
		return LitePacket{}, ErrPacketTooShort
	}

	header := parseHeader(data)
	return parsePacketLiteWithHeader(data, header)
}

func ParseDNSRequestLite(data []byte) (LitePacket, error) {
	if len(data) < dnsHeaderSize {
		return LitePacket{}, ErrPacketTooShort
	}

	header := parseHeader(data)
	if !isLikelyDNSRequestHeader(header) {
		return LitePacket{}, ErrNotDNSRequest
	}

	return parsePacketLiteWithHeader(data, header)
}

func parsePacketLiteWithHeader(data []byte, header Header) (LitePacket, error) {
	packet := LitePacket{Header: header}
	if header.QDCount == 0 {
		packet.QuestionEndOffset = dnsHeaderSize
		return packet, nil
	}

	questions, offset, err := parseQuestions(data, dnsHeaderSize, int(header.QDCount))
	if err != nil {
		return LitePacket{}, ErrInvalidQuestion
	}

	packet.Questions = questions
	packet.QuestionEndOffset = offset
	packet.HasQuestion = len(questions) > 0
	if packet.HasQuestion {
		packet.FirstQuestion = questions[0]
	}
	return packet, nil
}

func ParsePacket(data []byte) (Packet, error) {
	if len(data) < dnsHeaderSize {
		return Packet{}, ErrPacketTooShort
	}

	header := parseHeader(data)
	offset := dnsHeaderSize

	questions, nextOffset, err := parseQuestions(data, offset, int(header.QDCount))
	if err != nil {
		return Packet{}, err
	}
	offset = nextOffset

	answers, nextOffset, err := parseResourceRecords(data, offset, int(header.ANCount))
	if err != nil {
		return Packet{}, err
	}
	offset = nextOffset

	authorities, nextOffset, err := parseResourceRecords(data, offset, int(header.NSCount))
	if err != nil {
		return Packet{}, err
	}
	offset = nextOffset

	additional, _, err := parseResourceRecords(data, offset, int(header.ARCount))
	if err != nil {
		return Packet{}, err
	}

	return Packet{
		Header:      header,
		Questions:   questions,
		Answers:     answers,
		Authorities: authorities,
		Additional:  additional,
	}, nil
}

func parseHeader(data []byte) Header {
	flags := binary.BigEndian.Uint16(data[2:4])
	return Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   flags,
		QR:      uint8((flags >> 15) & 0x1),
		OpCode:  uint8((flags >> 11) & 0xF),
		AA:      uint8((flags >> 10) & 0x1),
		TC:      uint8((flags >> 9) & 0x1),
		RD:      uint8((flags >> 8) & 0x1),
		RA:      uint8((flags >> 7) & 0x1),
		Z:       uint8((flags >> 4) & 0x7),
		RCode:   uint8(flags & 0xF),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}
}

func parseQuestions(data []byte, offset int, count int) ([]Question, int, error) {
	if count == 0 {
		return nil, offset, nil
	}
	if count > maxSectionCount {
		return nil, offset, ErrSectionCountTooLarge
	}

	questions := make([]Question, count)
	for i := range count {
		name, nextOffset, err := parseName(data, offset)
		if err != nil {
			return nil, offset, ErrInvalidQuestion
		}
		offset = nextOffset

		if offset+4 > len(data) {
			return nil, offset, ErrInvalidQuestion
		}

		questions[i] = Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		}
		offset += 4
	}

	return questions, offset, nil
}

func parseResourceRecords(data []byte, offset int, count int) ([]ResourceRecord, int, error) {
	if count == 0 {
		return nil, offset, nil
	}
	if count > maxSectionCount {
		return nil, offset, ErrSectionCountTooLarge
	}

	records := make([]ResourceRecord, count)
	for i := range count {
		name, nextOffset, err := parseName(data, offset)
		if err != nil {
			return nil, offset, ErrInvalidAnswer
		}
		offset = nextOffset

		if offset+10 > len(data) {
			return nil, offset, ErrInvalidAnswer
		}

		rType := binary.BigEndian.Uint16(data[offset : offset+2])
		rClass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdLen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		end := offset + int(rdLen)
		if end > len(data) {
			return nil, offset, ErrInvalidAnswer
		}

		records[i] = ResourceRecord{
			Name:  name,
			Type:  rType,
			Class: rClass,
			TTL:   ttl,
			RDLen: rdLen,
			RData: data[offset:end],
		}
		offset = end
	}

	return records, offset, nil
}

func parseName(data []byte, offset int) (string, int, error) {
	dataLen := len(data)
	if offset >= dataLen {
		return "", offset, ErrInvalidName
	}

	var (
		jumped   bool
		jumps    int
		origNext = offset
		name     strings.Builder
		hasLabel bool
	)

	for {
		if offset >= dataLen {
			return "", origNext, ErrInvalidName
		}

		length := int(data[offset])
		if length == 0 {
			offset++
			if !jumped {
				origNext = offset
			}
			break
		}

		if length >= 192 { // 0xC0
			if offset+1 >= dataLen || jumps >= maxNameJumps {
				return "", origNext, ErrInvalidName
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if ptr >= dataLen {
				return "", origNext, ErrInvalidName
			}
			if !jumped {
				origNext = offset + 2
				jumped = true
			}
			offset = ptr
			jumps++
			continue
		}

		if length > 63 {
			return "", origNext, ErrInvalidName
		}

		offset++
		end := offset + length
		if end > dataLen {
			return "", origNext, ErrInvalidName
		}

		if name.Len() == 0 {
			name.Grow(64)
		} else {
			name.WriteByte('.')
		}

		writeLowerASCIILabel(&name, data[offset:end])
		hasLabel = true
		offset = end
		if !jumped {
			origNext = offset
		}
	}

	if !hasLabel {
		return ".", origNext, nil
	}
	return name.String(), origNext, nil
}

func writeLowerASCIILabel(dst *strings.Builder, label []byte) {
	upperIndex := -1
	for i := range label {
		if label[i] >= 'A' && label[i] <= 'Z' {
			upperIndex = i
			break
		}
	}

	if upperIndex == -1 {
		dst.Write(label)
		return
	}

	dst.Write(label[:upperIndex])
	for i := upperIndex; i < len(label); i++ {
		ch := label[i]
		if ch >= 'A' && ch <= 'Z' {
			dst.WriteByte(ch + ('a' - 'A'))
		} else {
			dst.WriteByte(ch)
		}
	}
}
