package types

import (
	"fmt"
	"math"
)

// PutF32 appends an IEEE-754 32-bit float, little-endian. SV2 uses F32 for
// nominal_hash_rate.
func (e *Encoder) PutF32(v float32) {
	e.PutU32(math.Float32bits(v))
}

// F32 decodes an IEEE-754 32-bit little-endian float.
func (d *Decoder) F32() (float32, error) {
	bits, err := d.U32()
	if err != nil {
		return 0, err
	}
	return math.Float32frombits(bits), nil
}

// PutOption writes an OPTION[T] (SEQ0_1[T]): a 1-byte count of 0 or 1 followed
// by the element when present. A nil pointer encodes as absent.
func PutOption[T any](e *Encoder, v *T, put func(*Encoder, T) error) error {
	if v == nil {
		e.PutU8(0)
		return nil
	}
	e.PutU8(1)
	return put(e, *v)
}

// ReadOption reads an OPTION[T] written by PutOption. A count above 1 is
// rejected with ErrValueRange.
func ReadOption[T any](d *Decoder, read func(*Decoder) (T, error)) (*T, error) {
	n, err := d.U8()
	if err != nil {
		return nil, err
	}
	switch n {
	case 0:
		return nil, nil
	case 1:
		v, err := read(d)
		if err != nil {
			return nil, err
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("OPTION count %d: %w", n, ErrValueRange)
	}
}
