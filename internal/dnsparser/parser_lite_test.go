// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package dnsparser

import (
	"encoding/binary"
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestParsePacketLiteParsesAllQuestions(t *testing.T) {
	request := buildMultiQuestionDNSQuery(
		0x4242,
		[]liteQuestionSpec{
			{Name: "example.com", Type: Enums.DNS_RECORD_TYPE_A, Class: Enums.DNSQ_CLASS_IN},
			{Name: "example.org", Type: Enums.DNS_RECORD_TYPE_AAAA, Class: Enums.DNSQ_CLASS_IN},
		},
		true,
	)

	parsed, err := ParsePacketLite(request)
	if err != nil {
		t.Fatalf("ParsePacketLite returned error: %v", err)
	}

	if !parsed.HasQuestion {
		t.Fatal("expected HasQuestion to be true")
	}
	if len(parsed.Questions) != 2 {
		t.Fatalf("unexpected question count: got=%d want=2", len(parsed.Questions))
	}
	if parsed.FirstQuestion.Name != "example.com" {
		t.Fatalf("unexpected first question name: got=%q want=%q", parsed.FirstQuestion.Name, "example.com")
	}
	if parsed.Questions[1].Name != "example.org" {
		t.Fatalf("unexpected second question name: got=%q want=%q", parsed.Questions[1].Name, "example.org")
	}
	if parsed.QuestionEndOffset <= dnsHeaderSize {
		t.Fatalf("unexpected QuestionEndOffset: got=%d want>%d", parsed.QuestionEndOffset, dnsHeaderSize)
	}
}

func TestParseDNSDatagramLiteRequiresCompleteMessage(t *testing.T) {
	query := buildMultiQuestionDNSQuery(
		0x5151,
		[]liteQuestionSpec{{Name: "example.com", Type: Enums.DNS_RECORD_TYPE_A, Class: Enums.DNSQ_CLASS_IN}},
		false,
	)
	response := append([]byte(nil), query...)
	response[2] |= 0x80

	compressedResponse := append([]byte(nil), response...)
	binary.BigEndian.PutUint16(compressedResponse[6:8], 1)
	compressedResponse = append(compressedResponse,
		0xC0, 0x0C,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3C,
		0x00, 0x04,
		192, 0, 2, 1,
	)

	multipleQuestions := buildMultiQuestionDNSQuery(
		0x5252,
		[]liteQuestionSpec{
			{Name: "example.com", Type: Enums.DNS_RECORD_TYPE_A, Class: Enums.DNSQ_CLASS_IN},
			{Name: "example.org", Type: Enums.DNS_RECORD_TYPE_AAAA, Class: Enums.DNSQ_CLASS_IN},
		},
		false,
	)
	withOPT := buildMultiQuestionDNSQuery(
		0x5353,
		[]liteQuestionSpec{{Name: "example.com", Type: Enums.DNS_RECORD_TYPE_A, Class: Enums.DNSQ_CLASS_IN}},
		true,
	)

	incompleteQuestions := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(incompleteQuestions[4:6], 2)
	missingAnswer := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(missingAnswer[6:8], 1)
	missingAuthority := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(missingAuthority[8:10], 1)
	missingAdditional := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(missingAdditional[10:12], 1)
	oversizedRData := append([]byte(nil), compressedResponse...)
	binary.BigEndian.PutUint16(oversizedRData[len(query)+10:len(query)+12], 5)
	trailingData := append(append([]byte(nil), query...), 0)

	emptyQuestion := append([]byte(nil), query[:dnsHeaderSize]...)
	binary.BigEndian.PutUint16(emptyQuestion[4:6], 0)
	emptyResponse := append([]byte(nil), emptyQuestion...)
	emptyResponse[2] |= 0x80
	invalidOpcode := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(invalidOpcode[2:4], 0x3900)
	reservedHeaderBit := append([]byte(nil), query...)
	reservedHeaderBit[3] |= 0x40

	badQuestionPointer := make([]byte, dnsHeaderSize+6)
	binary.BigEndian.PutUint16(badQuestionPointer[2:4], 0x0100)
	binary.BigEndian.PutUint16(badQuestionPointer[4:6], 1)
	copy(badQuestionPointer[dnsHeaderSize:], []byte{0xC0, 0xFF, 0x00, 0x01, 0x00, 0x01})
	headerQuestionPointer := append([]byte(nil), badQuestionPointer...)
	headerQuestionPointer[dnsHeaderSize+1] = 0
	cyclicQuestionPointer := append([]byte(nil), badQuestionPointer...)
	cyclicQuestionPointer[dnsHeaderSize+1] = dnsHeaderSize

	cyclicAnswerPointer := append([]byte(nil), response...)
	binary.BigEndian.PutUint16(cyclicAnswerPointer[6:8], 1)
	answerOffset := len(cyclicAnswerPointer)
	cyclicAnswerPointer = append(cyclicAnswerPointer,
		byte(0xC0|answerOffset>>8), byte(answerOffset),
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	)

	tooManyQuestionSpecs := make([]liteQuestionSpec, maxLikelyQuestions+1)
	for i := range tooManyQuestionSpecs {
		tooManyQuestionSpecs[i] = liteQuestionSpec{Name: ".", Type: Enums.DNS_RECORD_TYPE_A, Class: Enums.DNSQ_CLASS_IN}
	}
	tooManyQuestions := buildMultiQuestionDNSQuery(0x5454, tooManyQuestionSpecs, false)

	tooManyAnswers := append([]byte(nil), response...)
	binary.BigEndian.PutUint16(tooManyAnswers[6:8], maxLikelyAnswers+1)
	for range maxLikelyAnswers + 1 {
		tooManyAnswers = append(tooManyAnswers,
			0x00,
			0x00, 0x01,
			0x00, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		)
	}

	tests := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{name: "query", packet: query, want: true},
		{name: "response", packet: response, want: true},
		{name: "compressed response", packet: compressedResponse, want: true},
		{name: "multiple questions", packet: multipleQuestions, want: true},
		{name: "EDNS OPT", packet: withOPT, want: true},
		{name: "missing declared question", packet: incompleteQuestions},
		{name: "missing declared answer", packet: missingAnswer},
		{name: "missing declared authority", packet: missingAuthority},
		{name: "missing declared additional", packet: missingAdditional},
		{name: "oversized RDATA", packet: oversizedRData},
		{name: "trailing data", packet: trailingData},
		{name: "empty question", packet: emptyQuestion},
		{name: "empty-question response", packet: emptyResponse, want: true},
		{name: "invalid opcode", packet: invalidOpcode},
		{name: "reserved header bit", packet: reservedHeaderBit},
		{name: "out of range question pointer", packet: badQuestionPointer},
		{name: "question pointer into header", packet: headerQuestionPointer},
		{name: "cyclic question pointer", packet: cyclicQuestionPointer},
		{name: "cyclic answer pointer", packet: cyclicAnswerPointer},
		{name: "too many questions", packet: tooManyQuestions},
		{name: "too many answers", packet: tooManyAnswers},
		{name: "short packet", packet: []byte("not DNS")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseDNSDatagramLite(tt.packet)
			if got := err == nil; got != tt.want {
				t.Fatalf("ParseDNSDatagramLite() success=%t want=%t err=%v", got, tt.want, err)
			}
			if tt.want && parsed.Header.QDCount > 0 && (!parsed.HasQuestion || parsed.QuestionEndOffset <= dnsHeaderSize) {
				t.Fatalf("successful parse returned incomplete question metadata: %+v", parsed)
			}
		})
	}
}

type liteQuestionSpec struct {
	Name  string
	Type  uint16
	Class uint16
}

func buildMultiQuestionDNSQuery(id uint16, questions []liteQuestionSpec, withOPT bool) []byte {
	totalQuestionLen := 0
	for _, question := range questions {
		totalQuestionLen += len(encodeDNSName(question.Name)) + 4
	}

	arCount := uint16(0)
	opt := []byte(nil)
	if withOPT {
		arCount = 1
		opt = []byte{
			0x00,
			0x00, 0x29,
			0x10, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}
	}

	packet := make([]byte, dnsHeaderSize+totalQuestionLen+len(opt))
	packet[0] = byte(id >> 8)
	packet[1] = byte(id)
	packet[2] = 0x01
	packet[3] = 0x00
	packet[4] = byte(len(questions) >> 8)
	packet[5] = byte(len(questions))
	packet[10] = byte(arCount >> 8)
	packet[11] = byte(arCount)

	offset := dnsHeaderSize
	for _, question := range questions {
		qname := encodeDNSName(question.Name)
		offset += copy(packet[offset:], qname)
		packet[offset] = byte(question.Type >> 8)
		packet[offset+1] = byte(question.Type)
		packet[offset+2] = byte(question.Class >> 8)
		packet[offset+3] = byte(question.Class)
		offset += 4
	}

	copy(packet[offset:], opt)
	return packet
}
