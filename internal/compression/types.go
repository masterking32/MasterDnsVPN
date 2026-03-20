package compression

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

const (
	TypeOff  = 0
	TypeZSTD = 1
	TypeLZ4  = 2
	TypeZLIB = 3

	DefaultMinSize = 100
)

const availableTypeMask uint8 = (1 << TypeOff) | (1 << TypeZSTD) | (1 << TypeLZ4) | (1 << TypeZLIB)

var normalizedPackedPairNibble = [16]uint8{
	TypeOff,
	TypeZSTD,
	TypeLZ4,
	TypeZLIB,
	TypeOff,
	TypeOff,
	TypeOff,
	TypeOff,
	TypeOff,
	TypeOff,
	TypeOff,
	TypeOff,
	TypeOff,
	TypeOff,
	TypeOff,
	TypeOff,
}

var (
	deflateBufferPool = sync.Pool{
		New: func() any {
			return bytes.NewBuffer(make([]byte, 0, 256))
		},
	}
	deflateReaderPool = sync.Pool{
		New: func() any {
			return flate.NewReader(bytes.NewReader(nil))
		},
	}
	deflateWriterPool = sync.Pool{
		New: func() any {
			writer, _ := flate.NewWriter(io.Discard, 1)
			return writer
		},
	}

	zstdEncoderPool = sync.Pool{
		New: func() any {
			encoder, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
			return encoder
		},
	}
	zstdDecoderPool = sync.Pool{
		New: func() any {
			decoder, _ := zstd.NewReader(nil)
			return decoder
		},
	}
)

func NormalizeType(value uint8) uint8 {
	if value <= TypeZLIB {
		return value
	}
	return TypeOff
}

func IsTypeAvailable(value uint8) bool {
	value = NormalizeType(value)
	return availableTypeMask&(1<<value) != 0
}

func NormalizeAvailableType(value uint8) uint8 {
	if value > TypeZLIB || availableTypeMask&(1<<value) == 0 {
		return TypeOff
	}
	return value
}

func PackPair(uploadType uint8, downloadType uint8) uint8 {
	if uploadType > TypeZLIB {
		uploadType = TypeOff
	}
	if downloadType > TypeZLIB {
		downloadType = TypeOff
	}
	return (uploadType << 4) | downloadType
}

func SplitPair(value uint8) (uint8, uint8) {
	return normalizedPackedPairNibble[(value>>4)&0x0F], normalizedPackedPairNibble[value&0x0F]
}

func TypeName(value uint8) string {
	switch NormalizeType(value) {
	case TypeZSTD:
		return "ZSTD"
	case TypeLZ4:
		return "LZ4"
	case TypeZLIB:
		return "ZLIB"
	default:
		return "OFF"
	}
}

func CompressPayload(data []byte, compType uint8, minSize int) ([]byte, uint8) {
	if len(data) == 0 {
		return data, TypeOff
	}

	compType = NormalizeAvailableType(compType)
	if compType == TypeOff {
		return data, TypeOff
	}
	if minSize <= 0 {
		minSize = DefaultMinSize
	}
	if len(data) <= minSize {
		return data, TypeOff
	}

	var compData []byte
	var err error

	switch compType {
	case TypeZLIB:
		compData, err = compressZLIB(data)
	case TypeZSTD:
		compData, err = compressZSTD(data)
	case TypeLZ4:
		compData, err = compressLZ4(data)
	}

	if err != nil || len(compData) >= len(data) {
		return data, TypeOff
	}

	return compData, compType
}

func TryDecompressPayload(data []byte, compType uint8) ([]byte, bool) {
	if len(data) == 0 {
		return data, true
	}

	compType = NormalizeAvailableType(compType)
	if compType == TypeOff {
		return data, true
	}

	var out []byte
	var err error

	switch compType {
	case TypeZLIB:
		out, err = decompressZLIB(data)
	case TypeZSTD:
		out, err = decompressZSTD(data)
	case TypeLZ4:
		out, err = decompressLZ4(data)
	}

	if err != nil {
		return nil, false
	}
	return out, true
}

func compressZLIB(data []byte) ([]byte, error) {
	buffer := deflateBufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer deflateBufferPool.Put(buffer)

	writer := deflateWriterPool.Get().(*flate.Writer)
	writer.Reset(buffer)
	_, err := writer.Write(data)
	if err == nil {
		err = writer.Close()
	}
	deflateWriterPool.Put(writer)

	if err != nil {
		return nil, err
	}

	out := make([]byte, buffer.Len())
	copy(out, buffer.Bytes())
	return out, nil
}

func decompressZLIB(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	stream := deflateReaderPool.Get().(io.ReadCloser)
	stream.(flate.Resetter).Reset(reader, nil)
	defer deflateReaderPool.Put(stream)

	buffer := deflateBufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer deflateBufferPool.Put(buffer)

	_, err := buffer.ReadFrom(stream)
	_ = stream.Close()

	if err != nil || reader.Len() != 0 {
		return nil, io.ErrUnexpectedEOF
	}

	out := make([]byte, buffer.Len())
	copy(out, buffer.Bytes())
	return out, nil
}

func compressZSTD(data []byte) ([]byte, error) {
	encoder := zstdEncoderPool.Get().(*zstd.Encoder)
	defer zstdEncoderPool.Put(encoder)

	// Single-pass compression into a fresh buffer (to avoid holding pooled buffer refs in result)
	out := encoder.EncodeAll(data, nil)
	return out, nil
}

func decompressZSTD(data []byte) ([]byte, error) {
	decoder := zstdDecoderPool.Get().(*zstd.Decoder)
	defer zstdDecoderPool.Put(decoder)

	out, err := decoder.DecodeAll(data, nil)
	return out, err
}

func compressLZ4(data []byte) ([]byte, error) {
	// Calculate max possible compressed size
	maxSize := lz4.CompressBlockBound(len(data))
	// We need 4 bytes for the original size header (Python's store_size=True)
	buf := make([]byte, maxSize+4)

	// Store 4-byte little-endian size first (matches Python lz4.block behavior)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(data)))

	n, err := lz4.CompressBlock(data, buf[4:], nil)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, io.ErrShortBuffer
	}

	return buf[:n+4], nil
}

func decompressLZ4(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}

	// Read 4-byte original size (matches Python lz4.block behavior)
	origSize := binary.LittleEndian.Uint32(data[0:4])
	if origSize > 10*1024*1024 { // 10MB safety cap
		return nil, io.ErrShortBuffer
	}

	out := make([]byte, origSize)
	n, err := lz4.UncompressBlock(data[4:], out)
	if err != nil {
		return nil, err
	}
	if uint32(n) != origSize {
		return nil, io.ErrUnexpectedEOF
	}

	return out, nil
}
