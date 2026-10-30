// Package framing implements the Stratum V2 standard message frame (sv2-spec
// 3.2): a 6-byte header (extension_type U16 LE with bit 15 as the channel_msg
// flag, msg_type U8, msg_length U24 LE) followed by msg_length payload bytes.
//
// This is the cleartext frame. The Noise transport (internal/sv2/noise) wraps
// these frames in AEAD records; it consumes and produces the same Frame values.
package framing

import (
	"errors"
	"fmt"
	"io"

	"github.com/Insulince/switchyard/sv2/types"
)

// HeaderSize is the fixed length of a standard frame header.
const HeaderSize = 6

// MaxPayload is the largest payload a U24 length prefix can describe.
const MaxPayload = 1<<24 - 1

// channelMsgBit is bit 15 of extension_type.
const channelMsgBit = 0x8000

// ErrExtensionRange means ExtensionType used a reserved high bit (only bits
// 0..14 are the extension value; bit 15 is the channel_msg flag).
var ErrExtensionRange = errors.New("sv2/framing: extension_type exceeds 15 bits")

// Frame is one decoded SV2 message frame.
type Frame struct {
	// ChannelMsg is the channel_msg flag (bit 15 of extension_type). When set,
	// the first four payload bytes are a U32 channel_id (the message packages
	// interpret that; framing treats it as opaque payload).
	ChannelMsg bool
	// ExtensionType is the 15-bit extension type (0 = the core protocols).
	ExtensionType uint16
	// MsgType identifies the message within its subprotocol.
	MsgType uint8
	// Payload is the message body (msg_length bytes).
	Payload []byte
}

// MarshalBinary encodes the frame to its on-wire bytes.
func (f Frame) MarshalBinary() ([]byte, error) {
	if f.ExtensionType&channelMsgBit != 0 {
		return nil, fmt.Errorf("%#x: %w", f.ExtensionType, ErrExtensionRange)
	}
	if len(f.Payload) > MaxPayload {
		return nil, fmt.Errorf("payload len %d: %w", len(f.Payload), types.ErrTooLong)
	}
	ext := f.ExtensionType
	if f.ChannelMsg {
		ext |= channelMsgBit
	}
	e := types.NewEncoder()
	e.PutU16(ext)
	e.PutU8(f.MsgType)
	if err := e.PutU24(uint32(len(f.Payload))); err != nil {
		return nil, err
	}
	e.PutRaw(f.Payload)
	return e.Bytes(), nil
}

// parseHeader decodes the 6-byte header from b, returning the frame metadata
// and the declared payload length.
func parseHeader(b []byte) (Frame, int, error) {
	d := types.NewDecoder(b)
	ext, err := d.U16()
	if err != nil {
		return Frame{}, 0, err
	}
	msgType, err := d.U8()
	if err != nil {
		return Frame{}, 0, err
	}
	length, err := d.U24()
	if err != nil {
		return Frame{}, 0, err
	}
	f := Frame{
		ChannelMsg:    ext&channelMsgBit != 0,
		ExtensionType: ext &^ channelMsgBit,
		MsgType:       msgType,
	}
	return f, int(length), nil
}

// ParseHeader decodes a 6-byte frame header, returning the frame metadata
// (without payload) and the declared payload length. The Noise transport needs
// the length from a decrypted header before it can read the payload records.
func ParseHeader(b []byte) (Frame, int, error) {
	if len(b) < HeaderSize {
		return Frame{}, 0, fmt.Errorf("frame header: %w", types.ErrShortBuffer)
	}
	return parseHeader(b[:HeaderSize])
}

// ParseFrame decodes a single frame from a complete in-memory buffer. Trailing
// bytes beyond the frame are ignored.
func ParseFrame(b []byte) (Frame, error) {
	if len(b) < HeaderSize {
		return Frame{}, fmt.Errorf("frame header: %w", types.ErrShortBuffer)
	}
	f, length, err := parseHeader(b)
	if err != nil {
		return Frame{}, err
	}
	d := types.NewDecoder(b[HeaderSize:])
	payload, err := d.Raw(length)
	if err != nil {
		return Frame{}, fmt.Errorf("frame payload: %w", err)
	}
	f.Payload = payload
	return f, nil
}

// WriteFrame encodes f and writes it to w.
func WriteFrame(w io.Writer, f Frame) error {
	b, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ReadFrame reads exactly one frame from r, blocking until the header and full
// payload are available. A truncated stream yields io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	f, length, err := parseHeader(hdr[:])
	if err != nil {
		return Frame{}, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	f.Payload = payload
	return f, nil
}
