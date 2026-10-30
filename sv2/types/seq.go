package types

import "fmt"

// PutB0_32 appends a B0_32: a 1-byte length prefix followed by up to 32 bytes.
func (e *Encoder) PutB0_32(b []byte) error {
	if len(b) > 32 {
		return fmt.Errorf("PutB0_32 len %d: %w", len(b), ErrTooLong)
	}
	e.buf = append(e.buf, byte(len(b)))
	e.buf = append(e.buf, b...)
	return nil
}

// B0_32 decodes a B0_32, rejecting a declared length above 32. The returned
// slice is a copy.
func (d *Decoder) B0_32() ([]byte, error) {
	n, err := d.U8()
	if err != nil {
		return nil, err
	}
	if n > 32 {
		return nil, fmt.Errorf("B0_32 len %d: %w", n, ErrTooLong)
	}
	return d.copyN(int(n))
}

// PutSeq0_255 writes a SEQ0_255[T]: a 1-byte element count followed by each
// element encoded via put. Returns ErrTooLong if there are more than 255 items.
func PutSeq0_255[T any](e *Encoder, items []T, put func(*Encoder, T) error) error {
	if len(items) > 255 {
		return fmt.Errorf("PutSeq0_255 len %d: %w", len(items), ErrTooLong)
	}
	e.PutU8(uint8(len(items)))
	for i, it := range items {
		if err := put(e, it); err != nil {
			return fmt.Errorf("seq[%d]: %w", i, err)
		}
	}
	return nil
}

// ReadSeq0_255 reads a SEQ0_255[T] written by PutSeq0_255.
func ReadSeq0_255[T any](d *Decoder, read func(*Decoder) (T, error)) ([]T, error) {
	n, err := d.U8()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	out := make([]T, 0, n)
	for i := 0; i < int(n); i++ {
		v, err := read(d)
		if err != nil {
			return nil, fmt.Errorf("seq[%d]: %w", i, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// PutSeq0_64K writes a SEQ0_64K[T]: a 2-byte little-endian element count
// followed by each element encoded via put. Returns ErrTooLong above 65535 items.
func PutSeq0_64K[T any](e *Encoder, items []T, put func(*Encoder, T) error) error {
	if len(items) > 0xFFFF {
		return fmt.Errorf("PutSeq0_64K len %d: %w", len(items), ErrTooLong)
	}
	e.PutU16(uint16(len(items)))
	for i, it := range items {
		if err := put(e, it); err != nil {
			return fmt.Errorf("seq[%d]: %w", i, err)
		}
	}
	return nil
}

// ReadSeq0_64K reads a SEQ0_64K[T] written by PutSeq0_64K.
func ReadSeq0_64K[T any](d *Decoder, read func(*Decoder) (T, error)) ([]T, error) {
	n, err := d.U16()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	out := make([]T, 0, n)
	for i := 0; i < int(n); i++ {
		v, err := read(d)
		if err != nil {
			return nil, fmt.Errorf("seq[%d]: %w", i, err)
		}
		out = append(out, v)
	}
	return out, nil
}
