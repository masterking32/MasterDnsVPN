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

func TestBuildEmptyNoErrorResponsePreservesIDAndQuestion(t *testing.T) {
	request := buildDNSQuery(0xBEEF, "example.com", Enums.DNS_RECORD_TYPE_A, false)

	response, err := BuildEmptyNoErrorResponse(request)
	if err != nil {
		t.Fatalf("BuildEmptyNoErrorResponse returned error: %v", err)
	}

	if got := binary.BigEndian.Uint16(response[0:2]); got != 0xBEEF {
		t.Fatalf("unexpected response id: got=%#x want=%#x", got, 0xBEEF)
	}

	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&(1<<15) == 0 {
		t.Fatalf("response must set QR bit")
	}
	if flags&0x000F != 0 {
		t.Fatalf("response must use RCODE=NOERROR, got=%d", flags&0x000F)
	}
	if got := binary.BigEndian.Uint16(response[4:6]); got != 1 {
		t.Fatalf("unexpected qdcount: got=%d want=1", got)
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 0 {
		t.Fatalf("unexpected ancount: got=%d want=0", got)
	}
	if got := binary.BigEndian.Uint16(response[8:10]); got != 0 {
		t.Fatalf("unexpected nscount: got=%d want=0", got)
	}
	if got := binary.BigEndian.Uint16(response[10:12]); got != 0 {
		t.Fatalf("unexpected arcount: got=%d want=0", got)
	}

	parsed, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("ParsePacket(response) returned error: %v", err)
	}
	if len(parsed.Questions) != 1 {
		t.Fatalf("unexpected question count: got=%d want=1", len(parsed.Questions))
	}
	if parsed.Questions[0].Name != "example.com" {
		t.Fatalf("unexpected qname: got=%q want=%q", parsed.Questions[0].Name, "example.com")
	}
}

func TestBuildEmptyNoErrorResponseMirrorsOPTRecord(t *testing.T) {
	request := buildDNSQuery(0x1234, "example.com", Enums.DNS_RECORD_TYPE_TXT, true)

	response, err := BuildEmptyNoErrorResponse(request)
	if err != nil {
		t.Fatalf("BuildEmptyNoErrorResponse returned error: %v", err)
	}

	if got := binary.BigEndian.Uint16(response[10:12]); got != 1 {
		t.Fatalf("unexpected arcount: got=%d want=1", got)
	}

	parsed, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("ParsePacket(response) returned error: %v", err)
	}
	if len(parsed.Additional) != 1 {
		t.Fatalf("unexpected additional record count: got=%d want=1", len(parsed.Additional))
	}
	if parsed.Additional[0].Type != Enums.DNS_RECORD_TYPE_OPT {
		t.Fatalf("unexpected additional record type: got=%d want=%d", parsed.Additional[0].Type, Enums.DNS_RECORD_TYPE_OPT)
	}
}

func TestBuildEmptyNoErrorResponseFromLitePreservesAllQuestions(t *testing.T) {
	request := buildMultiQuestionDNSQuery(
		0x7777,
		[]liteQuestionSpec{
			{Name: "example.com", Type: Enums.DNS_RECORD_TYPE_A, Class: Enums.DNSQ_CLASS_IN},
			{Name: "example.net", Type: Enums.DNS_RECORD_TYPE_AAAA, Class: Enums.DNSQ_CLASS_IN},
		},
		true,
	)

	parsed, err := ParsePacketLite(request)
	if err != nil {
		t.Fatalf("ParsePacketLite returned error: %v", err)
	}

	response, err := BuildEmptyNoErrorResponseFromLite(request, parsed)
	if err != nil {
		t.Fatalf("BuildEmptyNoErrorResponseFromLite returned error: %v", err)
	}

	full, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("ParsePacket(response) returned error: %v", err)
	}

	if len(full.Questions) != 2 {
		t.Fatalf("unexpected question count: got=%d want=2", len(full.Questions))
	}
	if full.Questions[0].Name != "example.com" || full.Questions[1].Name != "example.net" {
		t.Fatalf("unexpected question names: got=%q,%q", full.Questions[0].Name, full.Questions[1].Name)
	}
	if len(full.Additional) != 1 || full.Additional[0].Type != Enums.DNS_RECORD_TYPE_OPT {
		t.Fatalf("response must preserve the OPT record")
	}
}

func TestBuildEmptyNoErrorResponseFallsBackToHeaderOnly(t *testing.T) {
	request := []byte{
		0xCA, 0xFE,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x07, 'e', 'x', 'a',
	}

	response, err := BuildEmptyNoErrorResponse(request)
	if err != nil {
		t.Fatalf("BuildEmptyNoErrorResponse returned error: %v", err)
	}

	if got := binary.BigEndian.Uint16(response[0:2]); got != 0xCAFE {
		t.Fatalf("unexpected response id: got=%#x want=%#x", got, 0xCAFE)
	}
	if got := binary.BigEndian.Uint16(response[4:6]); got != 0 {
		t.Fatalf("malformed request should fall back to header-only qdcount, got=%d want=0", got)
	}
	if len(response) != dnsHeaderSize {
		t.Fatalf("malformed request should fall back to a header-only response, got len=%d want=%d", len(response), dnsHeaderSize)
	}
}

func TestBuildEmptyNoErrorResponseRejectsNonDNS(t *testing.T) {
	request := []byte{
		0x12, 0x34,
		0xF8, 0x00,
		0x00, 0x40,
		0x00, 0x40,
		0x00, 0x40,
		0x00, 0x40,
	}

	if _, err := BuildEmptyNoErrorResponse(request); err == nil {
		t.Fatal("BuildEmptyNoErrorResponse should reject packets that do not look like supported DNS requests")
	}
}

func TestBuildFormatErrorResponseUsesFORMERR(t *testing.T) {
	request := []byte{
		0xAB, 0xCD,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x07, 'e', 'x',
	}

	response, err := BuildFormatErrorResponse(request)
	if err != nil {
		t.Fatalf("BuildFormatErrorResponse returned error: %v", err)
	}

	flags := binary.BigEndian.Uint16(response[2:4])
	if got := flags & 0x000F; got != Enums.DNSR_CODE_FORMAT_ERROR {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, Enums.DNSR_CODE_FORMAT_ERROR)
	}
	if got := binary.BigEndian.Uint16(response[0:2]); got != 0xABCD {
		t.Fatalf("unexpected response id: got=%#x want=%#x", got, 0xABCD)
	}
}

func TestBuildEmptyNoErrorResponseBuildsResolverLikeFlags(t *testing.T) {
	request := buildDNSQuery(0x1357, "example.com", Enums.DNS_RECORD_TYPE_A, false)
	binary.BigEndian.PutUint16(request[2:4], 0x0700)
	request[2] |= 0x02 // AA
	request[2] |= 0x01 // TC
	request[3] |= 0x10 // CD

	response, err := BuildEmptyNoErrorResponse(request)
	if err != nil {
		t.Fatalf("BuildEmptyNoErrorResponse returned error: %v", err)
	}

	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&(1<<15) == 0 {
		t.Fatal("response must set QR")
	}
	if flags&(1<<7) == 0 {
		t.Fatal("response must set RA")
	}
	if flags&(1<<8) == 0 {
		t.Fatal("response must preserve RD")
	}
	if flags&(1<<4) == 0 {
		t.Fatal("response must preserve CD")
	}
	if flags&(1<<10) != 0 {
		t.Fatal("resolver-like synthetic response must clear AA")
	}
	if flags&(1<<9) != 0 {
		t.Fatal("resolver-like synthetic response must clear TC")
	}
	if got := (flags >> 11) & 0xF; got != 0 {
		t.Fatalf("unexpected opcode bits: got=%d want=0", got)
	}
}

func TestBuildRefusedResponseFromLiteUsesREFUSED(t *testing.T) {
	request := buildDNSQuery(0x9999, "blocked.example", Enums.DNS_RECORD_TYPE_TXT, true)

	parsed, err := ParsePacketLite(request)
	if err != nil {
		t.Fatalf("ParsePacketLite returned error: %v", err)
	}

	response, err := BuildRefusedResponseFromLite(request, parsed)
	if err != nil {
		t.Fatalf("BuildRefusedResponseFromLite returned error: %v", err)
	}

	flags := binary.BigEndian.Uint16(response[2:4])
	if got := flags & 0x000F; got != Enums.DNSR_CODE_REFUSED {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, Enums.DNSR_CODE_REFUSED)
	}

	full, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("ParsePacket(response) returned error: %v", err)
	}
	if len(full.Questions) != 1 {
		t.Fatalf("unexpected question count: got=%d want=1", len(full.Questions))
	}
	if len(full.Additional) != 1 || full.Additional[0].Type != Enums.DNS_RECORD_TYPE_OPT {
		t.Fatalf("response must preserve the OPT record")
	}
}

func TestBuildEmptyNoErrorResponseHandlesManyLabels(t *testing.T) {
	request := buildDNSQuery(0x2020, "a.b.c.d.e.f.g.h.i.j.k.example", Enums.DNS_RECORD_TYPE_A, true)

	response, err := BuildEmptyNoErrorResponse(request)
	if err != nil {
		t.Fatalf("BuildEmptyNoErrorResponse returned error: %v", err)
	}

	parsed, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("ParsePacket(response) returned error: %v", err)
	}
	if len(parsed.Questions) != 1 {
		t.Fatalf("unexpected question count: got=%d want=1", len(parsed.Questions))
	}
	if parsed.Questions[0].Name != "a.b.c.d.e.f.g.h.i.j.k.example" {
		t.Fatalf("unexpected qname: got=%q", parsed.Questions[0].Name)
	}
	if len(parsed.Additional) != 1 || parsed.Additional[0].Type != Enums.DNS_RECORD_TYPE_OPT {
		t.Fatalf("response must preserve the OPT record")
	}
}

func TestBuildNoDataResponseFromLiteBuildsEmptyNoErrorResponse(t *testing.T) {
	request := buildDNSQuery(0x5151, "example.com", Enums.DNS_RECORD_TYPE_AAAA, true)

	parsed, err := ParsePacketLite(request)
	if err != nil {
		t.Fatalf("ParsePacketLite returned error: %v", err)
	}

	response, err := BuildNoDataResponseFromLite(request, parsed)
	if err != nil {
		t.Fatalf("BuildNoDataResponseFromLite returned error: %v", err)
	}

	flags := binary.BigEndian.Uint16(response[2:4])
	if got := flags & 0x000F; got != Enums.DNSR_CODE_NO_ERROR {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, Enums.DNSR_CODE_NO_ERROR)
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 0 {
		t.Fatalf("unexpected ancount: got=%d want=0", got)
	}
	if got := binary.BigEndian.Uint16(response[8:10]); got != 0 {
		t.Fatalf("unexpected nscount: got=%d want=0", got)
	}

	full, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("ParsePacket(response) returned error: %v", err)
	}
	if len(full.Authorities) != 0 {
		t.Fatalf("unexpected authority count: got=%d want=0", len(full.Authorities))
	}
	if len(full.Additional) != 1 || full.Additional[0].Type != Enums.DNS_RECORD_TYPE_OPT {
		t.Fatalf("response must preserve the OPT record")
	}
}

func TestBuildNameErrorResponseFromLiteBuildsAuthoritativeNXDOMAIN(t *testing.T) {
	request := buildDNSQuery(0x6161, "outside.example", Enums.DNS_RECORD_TYPE_A, true)
	request[3] |= 0x10 // CD

	parsed, err := ParsePacketLite(request)
	if err != nil {
		t.Fatalf("ParsePacketLite returned error: %v", err)
	}

	response, err := BuildNameErrorResponseFromLite(request, parsed)
	if err != nil {
		t.Fatalf("BuildNameErrorResponseFromLite returned error: %v", err)
	}

	flags := binary.BigEndian.Uint16(response[2:4])
	if got := flags & 0x000F; got != Enums.DNSR_CODE_NAME_ERROR {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, Enums.DNSR_CODE_NAME_ERROR)
	}
	if flags&(1<<15) == 0 {
		t.Fatal("response must set QR")
	}
	if flags&(1<<10) == 0 {
		t.Fatal("authoritative name error response must set AA")
	}
	if flags&(1<<7) != 0 {
		t.Fatal("authoritative name error response must clear RA")
	}
	if flags&(1<<8) == 0 {
		t.Fatal("response must preserve RD")
	}
	if flags&(1<<4) == 0 {
		t.Fatal("response must preserve CD")
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 0 {
		t.Fatalf("unexpected ancount: got=%d want=0", got)
	}

	full, err := ParsePacket(response)
	if err != nil {
		t.Fatalf("ParsePacket(response) returned error: %v", err)
	}
	if len(full.Questions) != 1 || full.Questions[0].Name != "outside.example" {
		t.Fatalf("unexpected question section: got=%+v", full.Questions)
	}
	if len(full.Additional) != 1 || full.Additional[0].Type != Enums.DNS_RECORD_TYPE_OPT {
		t.Fatalf("response must preserve the OPT record")
	}
}

func buildDNSQuery(id uint16, name string, qtype uint16, withOPT bool) []byte {
	qname := encodeDNSName(name)
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

	packet := make([]byte, dnsHeaderSize+len(qname)+4+len(opt))
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[10:12], arCount)

	offset := dnsHeaderSize
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qtype)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	offset += 4
	copy(packet[offset:], opt)

	return packet
}

func encodeDNSName(name string) []byte {
	if name == "." || name == "" {
		return []byte{0}
	}

	encoded := make([]byte, 0, len(name)+2)
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i != len(name) && name[i] != '.' {
			continue
		}

		labelLen := i - labelStart
		encoded = append(encoded, byte(labelLen))
		encoded = append(encoded, name[labelStart:i]...)
		labelStart = i + 1
	}

	return append(encoded, 0)
}
