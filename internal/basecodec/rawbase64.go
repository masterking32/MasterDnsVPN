// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package basecodec

import "encoding/base64"

var rawBase64Encoding = base64.RawStdEncoding

func EncodeRawBase64(data []byte) []byte {
	if len(data) == 0 {
		return []byte{}
	}

	out := make([]byte, rawBase64Encoding.EncodedLen(len(data)))
	rawBase64Encoding.Encode(out, data)
	return out
}

func EncodedRawBase64Len(n int) int {
	return rawBase64Encoding.EncodedLen(n)
}

func EncodeRawBase64To(dst []byte, data []byte) []byte {
	if len(data) == 0 {
		return dst
	}

	start := len(dst)
	dst = append(dst, make([]byte, rawBase64Encoding.EncodedLen(len(data)))...)
	rawBase64Encoding.Encode(dst[start:], data)
	return dst
}

func DecodeRawBase64(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	out := make([]byte, rawBase64Encoding.DecodedLen(len(data)))
	n, err := rawBase64Encoding.Decode(out, data)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}
