// Package types implements the Stratum V2 binary serialization primitives as
// defined in sv2-spec section 3.1. All multibyte integers are little-endian;
// variable-length types carry an unsigned little-endian length prefix (1, 2, or
// 3 bytes depending on the maximum size). These primitives are the wire layer
// that the framing and subprotocol message packages build on.
//
// SRI's binary-sv2 crate is the byte-for-byte oracle for these encodings.
package types

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Sentinel errors, comparable with errors.Is.
var (
	// ErrShortBuffer means a decode ran past the end of the buffer.
	ErrShortBuffer = errors.New("sv2/types: short buffer")
	// ErrTooLong means a value exceeds the maximum length its type can prefix.
	ErrTooLong = errors.New("sv2/types: value exceeds type maximum length")
	// ErrValueRange means an integer value is outside the type's representable range.
	ErrValueRange = errors.New("sv2/types: value out of range")
)

const (
	maxU24 = 1<<24 - 1
)

// Encoder accumulates SV2-encoded bytes. The zero value is not usable; call
// NewEncoder. Scalar writes cannot fail; length-prefixed writes return an error
// when the payload is too long for the type's prefix.
type Encoder struct {
	buf []byte
}

// NewEncoder returns an empty Encoder.
func NewEncoder() *Encoder { return &Encoder{} }

// Bytes returns the accumulated buffer. The slice aliases internal storage and
// must not be mutated by the caller.
func (e *Encoder) Bytes() []byte { return e.buf }

// Len returns the number of bytes written so far.
func (e *Encoder) Len() int { return len(e.buf) }

// PutU8 appends a single byte.
func (e *Encoder) PutU8(v uint8) { e.buf = append(e.buf, v) }

// PutU16 appends a 16-bit little-endian integer.
func (e *Encoder) PutU16(v uint16) {
	e.buf = binary.LittleEndian.AppendUint16(e.buf, v)
}

// PutU24 appends a 24-bit little-endian integer. Returns ErrValueRange if v
// does not fit in 24 bits.
func (e *Encoder) PutU24(v uint32) error {
	if v > maxU24 {
		return fmt.Errorf("PutU24 %d: %w", v, ErrValueRange)
	}
	e.buf = append(e.buf, byte(v), byte(v>>8), byte(v>>16))
	return nil
}

// PutU32 appends a 32-bit little-endian integer.
func (e *Encoder) PutU32(v uint32) {
	e.buf = binary.LittleEndian.AppendUint32(e.buf, v)
}

// PutU64 appends a 64-bit little-endian integer.
func (e *Encoder) PutU64(v uint64) {
	e.buf = binary.LittleEndian.AppendUint64(e.buf, v)
}

// PutBool appends a BOOL (1 = true, 0 = false).
func (e *Encoder) PutBool(v bool) {
	if v {
		e.buf = append(e.buf, 1)
	} else {
		e.buf = append(e.buf, 0)
	}
}

// PutU256 appends a 256-bit value as 32 raw bytes (already little-endian / raw
// SHA-256 order per the spec).
func (e *Encoder) PutU256(v [32]byte) { e.buf = append(e.buf, v[:]...) }

// PutStr0_255 appends a STR0_255: a 1-byte length prefix followed by the UTF-8
// bytes. Returns ErrTooLong if the string exceeds 255 bytes.
func (e *Encoder) PutStr0_255(s string) error {
	if len(s) > 255 {
		return fmt.Errorf("PutStr0_255 len %d: %w", len(s), ErrTooLong)
	}
	e.buf = append(e.buf, byte(len(s)))
	e.buf = append(e.buf, s...)
	return nil
}

// PutB0_255 appends a B0_255: a 1-byte length prefix followed by the bytes.
func (e *Encoder) PutB0_255(b []byte) error {
	if len(b) > 255 {
		return fmt.Errorf("PutB0_255 len %d: %w", len(b), ErrTooLong)
	}
	e.buf = append(e.buf, byte(len(b)))
	e.buf = append(e.buf, b...)
	return nil
}

// PutB0_64K appends a B0_64K: a 2-byte little-endian length prefix followed by
// the bytes.
func (e *Encoder) PutB0_64K(b []byte) error {
	if len(b) > 0xFFFF {
		return fmt.Errorf("PutB0_64K len %d: %w", len(b), ErrTooLong)
	}
	e.buf = binary.LittleEndian.AppendUint16(e.buf, uint16(len(b)))
	e.buf = append(e.buf, b...)
	return nil
}

// PutB0_16M appends a B0_16M: a 3-byte little-endian (U24) length prefix
// followed by the bytes.
func (e *Encoder) PutB0_16M(b []byte) error {
	if len(b) > maxU24 {
		return fmt.Errorf("PutB0_16M len %d: %w", len(b), ErrTooLong)
	}
	n := uint32(len(b))
	e.buf = append(e.buf, byte(n), byte(n>>8), byte(n>>16))
	e.buf = append(e.buf, b...)
	return nil
}

// PutRaw appends bytes verbatim with no length prefix. Used for fixed-width
// fields whose length is known from context (framing, Noise records).
func (e *Encoder) PutRaw(b []byte) { e.buf = append(e.buf, b...) }

// Decoder reads SV2-encoded values from a buffer, advancing an internal cursor.
// The zero value is not usable; call NewDecoder.
type Decoder struct {
	buf []byte
	off int
}

// NewDecoder returns a Decoder positioned at the start of buf.
func NewDecoder(buf []byte) *Decoder { return &Decoder{buf: buf} }

// Remaining reports how many undecoded bytes are left.
func (d *Decoder) Remaining() int { return len(d.buf) - d.off }

// take advances the cursor by n bytes and returns the slice, or ErrShortBuffer.
func (d *Decoder) take(n int) ([]byte, error) {
	if n < 0 || d.Remaining() < n {
		return nil, fmt.Errorf("need %d bytes, have %d: %w", n, d.Remaining(), ErrShortBuffer)
	}
	s := d.buf[d.off : d.off+n]
	d.off += n
	return s, nil
}

// U8 decodes a single byte.
func (d *Decoder) U8() (uint8, error) {
	s, err := d.take(1)
	if err != nil {
		return 0, err
	}
	return s[0], nil
}

// U16 decodes a 16-bit little-endian integer.
func (d *Decoder) U16() (uint16, error) {
	s, err := d.take(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(s), nil
}

// U24 decodes a 24-bit little-endian integer into a uint32.
func (d *Decoder) U24() (uint32, error) {
	s, err := d.take(3)
	if err != nil {
		return 0, err
	}
	return uint32(s[0]) | uint32(s[1])<<8 | uint32(s[2])<<16, nil
}

// U32 decodes a 32-bit little-endian integer.
func (d *Decoder) U32() (uint32, error) {
	s, err := d.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(s), nil
}

// U64 decodes a 64-bit little-endian integer.
func (d *Decoder) U64() (uint64, error) {
	s, err := d.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(s), nil
}

// Bool decodes a BOOL; any nonzero byte is true.
func (d *Decoder) Bool() (bool, error) {
	v, err := d.U8()
	if err != nil {
		return false, err
	}
	return v != 0, nil
}

// U256 decodes 32 raw bytes.
func (d *Decoder) U256() ([32]byte, error) {
	var out [32]byte
	s, err := d.take(32)
	if err != nil {
		return out, err
	}
	copy(out[:], s)
	return out, nil
}

// Str0_255 decodes a STR0_255.
func (d *Decoder) Str0_255() (string, error) {
	n, err := d.U8()
	if err != nil {
		return "", err
	}
	s, err := d.take(int(n))
	if err != nil {
		return "", err
	}
	return string(s), nil
}

// B0_255 decodes a B0_255. The returned slice is a copy.
func (d *Decoder) B0_255() ([]byte, error) {
	n, err := d.U8()
	if err != nil {
		return nil, err
	}
	return d.copyN(int(n))
}

// B0_64K decodes a B0_64K. The returned slice is a copy.
func (d *Decoder) B0_64K() ([]byte, error) {
	n, err := d.U16()
	if err != nil {
		return nil, err
	}
	return d.copyN(int(n))
}

// B0_16M decodes a B0_16M. The returned slice is a copy.
func (d *Decoder) B0_16M() ([]byte, error) {
	n, err := d.U24()
	if err != nil {
		return nil, err
	}
	return d.copyN(int(n))
}

// Raw decodes n bytes verbatim (no length prefix). The returned slice is a copy.
func (d *Decoder) Raw(n int) ([]byte, error) { return d.copyN(n) }

// copyN takes n bytes and returns a defensive copy so callers cannot mutate the
// underlying buffer. A zero-length read returns nil (the canonical empty form),
// since encoding nil and an empty slice produce identical bytes.
func (d *Decoder) copyN(n int) ([]byte, error) {
	s, err := d.take(n)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	out := make([]byte, n)
	copy(out, s)
	return out, nil
}
