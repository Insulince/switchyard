package types

import (
	"bytes"
	"errors"
	"testing"
)

// TestScalarRoundTrip verifies every fixed-width scalar encodes to the exact
// little-endian bytes the SV2 spec mandates and decodes back to the same value.
func TestScalarRoundTrip(t *testing.T) {
	t.Run("U8", func(t *testing.T) {
		for _, v := range []uint8{0, 1, 0x7f, 0xff} {
			e := NewEncoder()
			e.PutU8(v)
			if got := e.Bytes(); len(got) != 1 || got[0] != v {
				t.Fatalf("PutU8(%d) = % x", v, got)
			}
			d := NewDecoder(e.Bytes())
			if got, err := d.U8(); err != nil || got != v {
				t.Fatalf("U8 round trip %d: got %d err %v", v, got, err)
			}
		}
	})

	t.Run("U16 little-endian", func(t *testing.T) {
		e := NewEncoder()
		e.PutU16(0x0201)
		if got, want := e.Bytes(), []byte{0x01, 0x02}; !bytes.Equal(got, want) {
			t.Fatalf("PutU16 = % x, want % x", got, want)
		}
		d := NewDecoder(e.Bytes())
		if got, err := d.U16(); err != nil || got != 0x0201 {
			t.Fatalf("U16 round trip: got %#x err %v", got, err)
		}
	})

	t.Run("U24 little-endian", func(t *testing.T) {
		e := NewEncoder()
		if err := e.PutU24(0x030201); err != nil {
			t.Fatalf("PutU24: %v", err)
		}
		if got, want := e.Bytes(), []byte{0x01, 0x02, 0x03}; !bytes.Equal(got, want) {
			t.Fatalf("PutU24 = % x, want % x", got, want)
		}
		d := NewDecoder(e.Bytes())
		if got, err := d.U24(); err != nil || got != 0x030201 {
			t.Fatalf("U24 round trip: got %#x err %v", got, err)
		}
	})

	t.Run("U24 max boundary", func(t *testing.T) {
		e := NewEncoder()
		if err := e.PutU24(0xFFFFFF); err != nil {
			t.Fatalf("PutU24 max: %v", err)
		}
		d := NewDecoder(e.Bytes())
		if got, err := d.U24(); err != nil || got != 0xFFFFFF {
			t.Fatalf("U24 max round trip: got %#x err %v", got, err)
		}
	})

	t.Run("U24 overflow rejected", func(t *testing.T) {
		e := NewEncoder()
		if err := e.PutU24(0x1000000); !errors.Is(err, ErrValueRange) {
			t.Fatalf("PutU24 overflow: want ErrValueRange, got %v", err)
		}
	})

	t.Run("U32 little-endian", func(t *testing.T) {
		e := NewEncoder()
		e.PutU32(0x04030201)
		if got, want := e.Bytes(), []byte{0x01, 0x02, 0x03, 0x04}; !bytes.Equal(got, want) {
			t.Fatalf("PutU32 = % x, want % x", got, want)
		}
		d := NewDecoder(e.Bytes())
		if got, err := d.U32(); err != nil || got != 0x04030201 {
			t.Fatalf("U32 round trip: got %#x err %v", got, err)
		}
	})

	t.Run("U64 little-endian", func(t *testing.T) {
		e := NewEncoder()
		e.PutU64(0x0807060504030201)
		want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		if got := e.Bytes(); !bytes.Equal(got, want) {
			t.Fatalf("PutU64 = % x, want % x", got, want)
		}
		d := NewDecoder(e.Bytes())
		if got, err := d.U64(); err != nil || got != 0x0807060504030201 {
			t.Fatalf("U64 round trip: got %#x err %v", got, err)
		}
	})
}

func TestBool(t *testing.T) {
	for _, v := range []bool{true, false} {
		e := NewEncoder()
		e.PutBool(v)
		b := e.Bytes()
		if len(b) != 1 {
			t.Fatalf("PutBool len = %d", len(b))
		}
		if v && b[0] != 1 {
			t.Fatalf("PutBool(true) = %d, want 1", b[0])
		}
		if !v && b[0] != 0 {
			t.Fatalf("PutBool(false) = %d, want 0", b[0])
		}
		d := NewDecoder(b)
		if got, err := d.Bool(); err != nil || got != v {
			t.Fatalf("Bool round trip %v: got %v err %v", v, got, err)
		}
	}
	// Any nonzero decodes as true.
	d := NewDecoder([]byte{0x42})
	if got, err := d.Bool(); err != nil || !got {
		t.Fatalf("Bool(0x42): got %v err %v, want true", got, err)
	}
}

func TestU256(t *testing.T) {
	var v [32]byte
	for i := range v {
		v[i] = byte(i)
	}
	e := NewEncoder()
	e.PutU256(v)
	if got := e.Bytes(); !bytes.Equal(got, v[:]) {
		t.Fatalf("PutU256 = % x", got)
	}
	d := NewDecoder(e.Bytes())
	got, err := d.U256()
	if err != nil || got != v {
		t.Fatalf("U256 round trip: err %v", err)
	}
}

func TestStr0_255(t *testing.T) {
	t.Run("round trip with length prefix", func(t *testing.T) {
		e := NewEncoder()
		if err := e.PutStr0_255("sv2"); err != nil {
			t.Fatalf("PutStr0_255: %v", err)
		}
		want := []byte{0x03, 's', 'v', '2'}
		if got := e.Bytes(); !bytes.Equal(got, want) {
			t.Fatalf("PutStr0_255 = % x, want % x", got, want)
		}
		d := NewDecoder(e.Bytes())
		if got, err := d.Str0_255(); err != nil || got != "sv2" {
			t.Fatalf("Str0_255 round trip: got %q err %v", got, err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		e := NewEncoder()
		if err := e.PutStr0_255(""); err != nil {
			t.Fatalf("PutStr0_255 empty: %v", err)
		}
		if got, want := e.Bytes(), []byte{0x00}; !bytes.Equal(got, want) {
			t.Fatalf("empty = % x", got)
		}
	})
	t.Run("over 255 rejected", func(t *testing.T) {
		e := NewEncoder()
		s := string(make([]byte, 256))
		if err := e.PutStr0_255(s); !errors.Is(err, ErrTooLong) {
			t.Fatalf("want ErrTooLong, got %v", err)
		}
	})
}

func TestByteArrays(t *testing.T) {
	t.Run("B0_255 prefix is one byte", func(t *testing.T) {
		e := NewEncoder()
		if err := e.PutB0_255([]byte{0xaa, 0xbb}); err != nil {
			t.Fatalf("PutB0_255: %v", err)
		}
		want := []byte{0x02, 0xaa, 0xbb}
		if got := e.Bytes(); !bytes.Equal(got, want) {
			t.Fatalf("PutB0_255 = % x, want % x", got, want)
		}
		d := NewDecoder(e.Bytes())
		if got, err := d.B0_255(); err != nil || !bytes.Equal(got, []byte{0xaa, 0xbb}) {
			t.Fatalf("B0_255 round trip: got % x err %v", got, err)
		}
	})

	t.Run("B0_64K prefix is two little-endian bytes", func(t *testing.T) {
		e := NewEncoder()
		payload := bytes.Repeat([]byte{0xcd}, 300)
		if err := e.PutB0_64K(payload); err != nil {
			t.Fatalf("PutB0_64K: %v", err)
		}
		got := e.Bytes()
		// 300 = 0x012c -> little-endian 0x2c 0x01
		if got[0] != 0x2c || got[1] != 0x01 {
			t.Fatalf("B0_64K prefix = % x, want 2c 01", got[:2])
		}
		d := NewDecoder(got)
		dec, err := d.B0_64K()
		if err != nil || !bytes.Equal(dec, payload) {
			t.Fatalf("B0_64K round trip: err %v len %d", err, len(dec))
		}
	})

	t.Run("B0_64K over 65535 rejected", func(t *testing.T) {
		e := NewEncoder()
		if err := e.PutB0_64K(make([]byte, 65536)); !errors.Is(err, ErrTooLong) {
			t.Fatalf("want ErrTooLong, got %v", err)
		}
	})

	t.Run("B0_16M prefix is three little-endian bytes", func(t *testing.T) {
		e := NewEncoder()
		payload := bytes.Repeat([]byte{0xef}, 70000) // 0x011170
		if err := e.PutB0_16M(payload); err != nil {
			t.Fatalf("PutB0_16M: %v", err)
		}
		got := e.Bytes()
		if got[0] != 0x70 || got[1] != 0x11 || got[2] != 0x01 {
			t.Fatalf("B0_16M prefix = % x, want 70 11 01", got[:3])
		}
		d := NewDecoder(got)
		dec, err := d.B0_16M()
		if err != nil || !bytes.Equal(dec, payload) {
			t.Fatalf("B0_16M round trip: err %v len %d", err, len(dec))
		}
	})
}

// TestDecoderUnderflow verifies every decode rejects a truncated buffer with
// ErrShortBuffer rather than panicking.
func TestDecoderUnderflow(t *testing.T) {
	checks := []struct {
		name string
		buf  []byte
		fn   func(*Decoder) error
	}{
		{"U8", nil, func(d *Decoder) error { _, err := d.U8(); return err }},
		{"U16", []byte{0x00}, func(d *Decoder) error { _, err := d.U16(); return err }},
		{"U24", []byte{0x00, 0x00}, func(d *Decoder) error { _, err := d.U24(); return err }},
		{"U32", []byte{0x00, 0x00, 0x00}, func(d *Decoder) error { _, err := d.U32(); return err }},
		{"U64", []byte{0x00}, func(d *Decoder) error { _, err := d.U64(); return err }},
		{"U256", []byte{0x00}, func(d *Decoder) error { _, err := d.U256(); return err }},
		{"Str0_255 missing body", []byte{0x05, 'a'}, func(d *Decoder) error { _, err := d.Str0_255(); return err }},
		{"B0_255 missing body", []byte{0x05}, func(d *Decoder) error { _, err := d.B0_255(); return err }},
		{"B0_64K missing prefix", []byte{0x00}, func(d *Decoder) error { _, err := d.B0_64K(); return err }},
		{"B0_16M missing body", []byte{0x02, 0x00, 0x00, 0xaa}, func(d *Decoder) error { _, err := d.B0_16M(); return err }},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			d := NewDecoder(c.buf)
			if err := c.fn(d); !errors.Is(err, ErrShortBuffer) {
				t.Fatalf("want ErrShortBuffer, got %v", err)
			}
		})
	}
}

// TestRaw verifies fixed-length raw byte reads/writes (used by framing/Noise).
func TestRaw(t *testing.T) {
	e := NewEncoder()
	e.PutRaw([]byte{1, 2, 3})
	e.PutU8(0xff)
	d := NewDecoder(e.Bytes())
	raw, err := d.Raw(3)
	if err != nil || !bytes.Equal(raw, []byte{1, 2, 3}) {
		t.Fatalf("Raw: got % x err %v", raw, err)
	}
	if got, err := d.U8(); err != nil || got != 0xff {
		t.Fatalf("trailing U8 after Raw: got %#x err %v", got, err)
	}
	if d.Remaining() != 0 {
		t.Fatalf("Remaining = %d, want 0", d.Remaining())
	}
}
