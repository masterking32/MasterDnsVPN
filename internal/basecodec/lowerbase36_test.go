// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package basecodec

import "testing"

func TestEncodeLowerBase36UsesOnlyLowerAlphaNumeric(t *testing.T) {
	encoded := EncodeLowerBase36([]byte("MasterDnsVPN-123"))
	if encoded == "" {
		t.Fatal("encoded string must not be empty")
	}

	for i := 0; i < len(encoded); i++ {
		ch := encoded[i]
		if ch >= 'a' && ch <= 'z' {
			continue
		}
		if ch >= '0' && ch <= '9' {
			continue
		}
		t.Fatalf("unexpected character at index %d: %q", i, ch)
	}
}

func TestDecodeLowerBase36RoundTrip(t *testing.T) {
	original := []byte{0x00, 0x01, 0x02, 0x10, 0x20, 0x30, 0x40, 0xFE, 0xFF}
	encoded := EncodeLowerBase36(original)

	decoded, err := DecodeLowerBase36([]byte(encoded))
	if err != nil {
		t.Fatalf("DecodeLowerBase36 returned error: %v", err)
	}
	if len(decoded) != len(original) {
		t.Fatalf("unexpected decoded length: got=%d want=%d", len(decoded), len(original))
	}
	for i := range original {
		if decoded[i] != original[i] {
			t.Fatalf("unexpected decoded byte at %d: got=%d want=%d", i, decoded[i], original[i])
		}
	}
}

func TestDecodeLowerBase36RejectsInvalidCharacters(t *testing.T) {
	invalidSamples := [][]byte{
		[]byte("abc-123"),
		[]byte("abc="),
	}

	for _, sample := range invalidSamples {
		if _, err := DecodeLowerBase36(sample); err == nil {
			t.Fatalf("DecodeLowerBase36 should reject %q", sample)
		}
	}
}

func TestDecodeLowerBase36AcceptsUppercaseASCII(t *testing.T) {
	original := []byte{0x00, 0x01, 0xAB, 0xCD, 0xEF}
	encoded := EncodeLowerBase36(original)
	upper := []byte(encoded)
	for i := 0; i < len(upper); i++ {
		if upper[i] >= 'a' && upper[i] <= 'z' {
			upper[i] -= 'a' - 'A'
		}
	}

	decoded, err := DecodeLowerBase36(upper)
	if err != nil {
		t.Fatalf("DecodeLowerBase36 returned error for uppercase input: %v", err)
	}
	if len(decoded) != len(original) {
		t.Fatalf("unexpected decoded length: got=%d want=%d", len(decoded), len(original))
	}
	for i := range original {
		if decoded[i] != original[i] {
			t.Fatalf("unexpected decoded byte at %d: got=%d want=%d", i, decoded[i], original[i])
		}
	}

	decodedString, err := DecodeLowerBase36String(string(upper))
	if err != nil {
		t.Fatalf("DecodeLowerBase36String returned error for uppercase input: %v", err)
	}
	if len(decodedString) != len(original) {
		t.Fatalf("unexpected decoded string length: got=%d want=%d", len(decodedString), len(original))
	}
	for i := range original {
		if decodedString[i] != original[i] {
			t.Fatalf("unexpected decoded string byte at %d: got=%d want=%d", i, decodedString[i], original[i])
		}
	}
}

func TestEncodeLowerBase36PreservesLeadingZeroBytes(t *testing.T) {
	encoded := EncodeLowerBase36([]byte{0x00, 0x00, 0x01})
	if encoded[:2] != "00" {
		t.Fatalf("leading zero bytes should encode to leading zeros, got=%q", encoded)
	}

	decoded, err := DecodeLowerBase36([]byte(encoded))
	if err != nil {
		t.Fatalf("DecodeLowerBase36 returned error: %v", err)
	}
	if len(decoded) != 3 || decoded[0] != 0 || decoded[1] != 0 || decoded[2] != 1 {
		t.Fatalf("unexpected decoded bytes: %#v", decoded)
	}
}
