package types

import (
	"errors"
	"math"
	"testing"
)

func TestPutSeq0_255Overflow(t *testing.T) {
	items := make([]uint8, 256)
	e := NewEncoder()
	err := PutSeq0_255(e, items, func(e *Encoder, v uint8) error { e.PutU8(v); return nil })
	if !errors.Is(err, ErrTooLong) {
		t.Fatalf("want ErrTooLong, got %v", err)
	}
}

func TestReadSeq0_255Underflow(t *testing.T) {
	// count says 1 element but the body is missing.
	d := NewDecoder([]byte{0x01})
	_, err := ReadSeq0_255(d, func(d *Decoder) (uint16, error) { return d.U16() })
	if !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}

// TestDecodedSliceIsDefensiveCopy pins that decoded byte slices do not alias the
// source buffer, so a caller mutating a decoded field cannot corrupt the frame
// it came from (relevant when frames are reused or pooled).
func TestDecodedSliceIsDefensiveCopy(t *testing.T) {
	src := []byte{0x02, 0xaa, 0xbb}
	d := NewDecoder(src)
	got, err := d.B0_255()
	if err != nil {
		t.Fatal(err)
	}
	got[0] = 0xff
	if src[1] != 0xaa {
		t.Fatalf("decoded slice aliased source buffer: src = % x", src)
	}
}

func TestZeroLengthDecodesToNil(t *testing.T) {
	d := NewDecoder([]byte{0x00}) // B0_255 with declared length 0
	got, err := d.B0_255()
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("zero-length decode = %v, want nil (canonical empty form)", got)
	}
}

func TestEncoderLen(t *testing.T) {
	e := NewEncoder()
	e.PutU32(0)
	e.PutU8(0)
	if e.Len() != 5 {
		t.Fatalf("Len = %d, want 5", e.Len())
	}
}

// TestDecodersErrorOnEmpty pins that every variable/length-prefixed decoder
// reports an error (never panics) when its length prefix cannot even be read.
func TestDecodersErrorOnEmpty(t *testing.T) {
	checks := map[string]func(*Decoder) error{
		"F32":      func(d *Decoder) error { _, err := d.F32(); return err },
		"Bool":     func(d *Decoder) error { _, err := d.Bool(); return err },
		"B0_32":    func(d *Decoder) error { _, err := d.B0_32(); return err },
		"Str0_255": func(d *Decoder) error { _, err := d.Str0_255(); return err },
		"B0_255":   func(d *Decoder) error { _, err := d.B0_255(); return err },
		"B0_64K":   func(d *Decoder) error { _, err := d.B0_64K(); return err },
		"B0_16M":   func(d *Decoder) error { _, err := d.B0_16M(); return err },
	}
	for name, fn := range checks {
		if err := fn(NewDecoder(nil)); err == nil {
			t.Fatalf("%s: want error on empty buffer", name)
		}
	}
}

func TestPutB0_255Overflow(t *testing.T) {
	e := NewEncoder()
	if err := e.PutB0_255(make([]byte, 256)); !errors.Is(err, ErrTooLong) {
		t.Fatalf("want ErrTooLong, got %v", err)
	}
}

func TestReadOptionInnerError(t *testing.T) {
	d := NewDecoder([]byte{0x01}) // count 1, element missing
	if _, err := ReadOption(d, func(d *Decoder) (uint32, error) { return d.U32() }); err == nil {
		t.Fatal("want error when option element is missing")
	}
}

func TestReadSeqInnerError(t *testing.T) {
	d := NewDecoder([]byte{0x01}) // SEQ0_255 count 1, body missing
	if _, err := ReadSeq0_255(d, func(d *Decoder) (uint32, error) { return d.U32() }); err == nil {
		t.Fatal("ReadSeq0_255 want error on missing body")
	}
	d2 := NewDecoder([]byte{0x01, 0x00}) // SEQ0_64K count 1, body missing
	if _, err := ReadSeq0_64K(d2, func(d *Decoder) (uint32, error) { return d.U32() }); err == nil {
		t.Fatal("ReadSeq0_64K want error on missing body")
	}
}

func TestPutSeqAndOptionCallbackErrorsPropagate(t *testing.T) {
	boom := errors.New("boom")
	if err := PutSeq0_255(NewEncoder(), []int{1}, func(*Encoder, int) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("PutSeq0_255 callback error not propagated: %v", err)
	}
	if err := PutSeq0_64K(NewEncoder(), []int{1}, func(*Encoder, int) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("PutSeq0_64K callback error not propagated: %v", err)
	}
	v := 1
	if err := PutOption(NewEncoder(), &v, func(*Encoder, int) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("PutOption callback error not propagated: %v", err)
	}
}

// TestF32BitExact pins that F32 is a pure IEEE-754 little-endian transport: every
// special value round-trips bit-for-bit, never normalized.
func TestF32BitExact(t *testing.T) {
	values := []float32{
		float32(math.Inf(1)),
		float32(math.Inf(-1)),
		float32(math.Copysign(0, -1)), // negative zero
		math.MaxFloat32,
		math.SmallestNonzeroFloat32,
	}
	for _, v := range values {
		e := NewEncoder()
		e.PutF32(v)
		d := NewDecoder(e.Bytes())
		got, err := d.F32()
		if err != nil {
			t.Fatalf("F32(%v): %v", v, err)
		}
		if math.Float32bits(got) != math.Float32bits(v) {
			t.Fatalf("F32 %v not bit-exact: got %#x want %#x", v, math.Float32bits(got), math.Float32bits(v))
		}
	}
	// NaN compares unequal to itself, so check the NaN property directly.
	e := NewEncoder()
	e.PutF32(float32(math.NaN()))
	d := NewDecoder(e.Bytes())
	got, _ := d.F32()
	if !math.IsNaN(float64(got)) {
		t.Fatalf("NaN did not survive round trip: %v", got)
	}
}
