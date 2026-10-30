package types

import (
	"bytes"
	"errors"
	"testing"
)

func TestB0_32(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		e := NewEncoder()
		if err := e.PutB0_32([]byte{0xde, 0xad}); err != nil {
			t.Fatalf("PutB0_32: %v", err)
		}
		if got, want := e.Bytes(), []byte{0x02, 0xde, 0xad}; !bytes.Equal(got, want) {
			t.Fatalf("PutB0_32 = % x, want % x", got, want)
		}
		d := NewDecoder(e.Bytes())
		got, err := d.B0_32()
		if err != nil || !bytes.Equal(got, []byte{0xde, 0xad}) {
			t.Fatalf("B0_32 round trip: got % x err %v", got, err)
		}
	})
	t.Run("encode over 32 rejected", func(t *testing.T) {
		e := NewEncoder()
		if err := e.PutB0_32(make([]byte, 33)); !errors.Is(err, ErrTooLong) {
			t.Fatalf("want ErrTooLong, got %v", err)
		}
	})
	t.Run("decode over 32 rejected", func(t *testing.T) {
		d := NewDecoder(append([]byte{0x21}, make([]byte, 33)...)) // len prefix 33
		if _, err := d.B0_32(); !errors.Is(err, ErrTooLong) {
			t.Fatalf("want ErrTooLong, got %v", err)
		}
	})
}

func TestSeq0_64K_U256(t *testing.T) {
	var a, b [32]byte
	a[0], b[31] = 0x11, 0x22
	items := [][32]byte{a, b}

	e := NewEncoder()
	err := PutSeq0_64K(e, items, func(e *Encoder, v [32]byte) error { e.PutU256(v); return nil })
	if err != nil {
		t.Fatalf("PutSeq0_64K: %v", err)
	}
	// count 2 LE = 02 00, then 64 bytes
	if e.Bytes()[0] != 0x02 || e.Bytes()[1] != 0x00 {
		t.Fatalf("count prefix = % x, want 02 00", e.Bytes()[:2])
	}

	d := NewDecoder(e.Bytes())
	out, err := ReadSeq0_64K(d, func(d *Decoder) ([32]byte, error) { return d.U256() })
	if err != nil {
		t.Fatalf("ReadSeq0_64K: %v", err)
	}
	if len(out) != 2 || out[0] != a || out[1] != b {
		t.Fatalf("seq round trip mismatch: %+v", out)
	}
	if d.Remaining() != 0 {
		t.Fatalf("Remaining = %d", d.Remaining())
	}
}

func TestSeq0_255_U16(t *testing.T) {
	items := []uint16{1, 0x0302, 0xffff}
	e := NewEncoder()
	if err := PutSeq0_255(e, items, func(e *Encoder, v uint16) error { e.PutU16(v); return nil }); err != nil {
		t.Fatalf("PutSeq0_255: %v", err)
	}
	if e.Bytes()[0] != 0x03 {
		t.Fatalf("count prefix = %#x, want 03", e.Bytes()[0])
	}
	d := NewDecoder(e.Bytes())
	out, err := ReadSeq0_255(d, func(d *Decoder) (uint16, error) { return d.U16() })
	if err != nil {
		t.Fatalf("ReadSeq0_255: %v", err)
	}
	if len(out) != 3 || out[0] != 1 || out[1] != 0x0302 || out[2] != 0xffff {
		t.Fatalf("seq mismatch: %+v", out)
	}
}

func TestSeqDecodeUnderflow(t *testing.T) {
	// count says 2 elements but no element bytes follow.
	d := NewDecoder([]byte{0x02, 0x00})
	_, err := ReadSeq0_64K(d, func(d *Decoder) ([32]byte, error) { return d.U256() })
	if !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}
