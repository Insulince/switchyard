package types

import (
	"bytes"
	"errors"
	"testing"
)

func TestF32(t *testing.T) {
	e := NewEncoder()
	e.PutF32(1.0)
	// IEEE754 1.0 = 0x3f800000, little-endian = 00 00 80 3f
	if got, want := e.Bytes(), []byte{0x00, 0x00, 0x80, 0x3f}; !bytes.Equal(got, want) {
		t.Fatalf("PutF32(1.0) = % x, want % x", got, want)
	}
	d := NewDecoder(e.Bytes())
	if got, err := d.F32(); err != nil || got != 1.0 {
		t.Fatalf("F32 round trip: got %v err %v", got, err)
	}
}

func TestOption(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		v := uint32(0x04030201)
		e := NewEncoder()
		if err := PutOption(e, &v, func(e *Encoder, x uint32) error { e.PutU32(x); return nil }); err != nil {
			t.Fatalf("PutOption: %v", err)
		}
		// count 1, then U32 LE
		if got, want := e.Bytes(), []byte{0x01, 0x01, 0x02, 0x03, 0x04}; !bytes.Equal(got, want) {
			t.Fatalf("PutOption present = % x, want % x", got, want)
		}
		d := NewDecoder(e.Bytes())
		out, err := ReadOption(d, func(d *Decoder) (uint32, error) { return d.U32() })
		if err != nil || out == nil || *out != v {
			t.Fatalf("ReadOption present: out %v err %v", out, err)
		}
	})
	t.Run("absent", func(t *testing.T) {
		e := NewEncoder()
		if err := PutOption[uint32](e, nil, func(e *Encoder, x uint32) error { e.PutU32(x); return nil }); err != nil {
			t.Fatalf("PutOption nil: %v", err)
		}
		if got, want := e.Bytes(), []byte{0x00}; !bytes.Equal(got, want) {
			t.Fatalf("PutOption absent = % x, want 00", got)
		}
		d := NewDecoder(e.Bytes())
		out, err := ReadOption(d, func(d *Decoder) (uint32, error) { return d.U32() })
		if err != nil || out != nil {
			t.Fatalf("ReadOption absent: out %v err %v", out, err)
		}
	})
	t.Run("count over 1 rejected", func(t *testing.T) {
		d := NewDecoder([]byte{0x02})
		if _, err := ReadOption(d, func(d *Decoder) (uint32, error) { return d.U32() }); !errors.Is(err, ErrValueRange) {
			t.Fatalf("want ErrValueRange, got %v", err)
		}
	})
}
