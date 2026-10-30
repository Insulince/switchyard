package framing

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/Insulince/switchyard/sv2/types"
)

func TestParseHeaderRecoversMetadata(t *testing.T) {
	orig := Frame{ChannelMsg: true, ExtensionType: 0x1234, MsgType: 0x1f, Payload: bytes.Repeat([]byte{0xaa}, 300)}
	b, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	meta, length, err := ParseHeader(b)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if length != 300 {
		t.Fatalf("length = %d, want 300", length)
	}
	if !meta.ChannelMsg {
		t.Fatal("ChannelMsg flag not recovered")
	}
	if meta.ExtensionType != 0x1234 {
		t.Fatalf("ExtensionType = %#x, want 0x1234", meta.ExtensionType)
	}
	if meta.MsgType != 0x1f {
		t.Fatalf("MsgType = %#x, want 0x1f", meta.MsgType)
	}
	if meta.Payload != nil {
		t.Fatal("ParseHeader must not populate Payload")
	}
}

func TestParseHeaderShortBuffer(t *testing.T) {
	if _, _, err := ParseHeader([]byte{0x00, 0x00, 0x00}); !errors.Is(err, types.ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}

func TestMarshalBinaryPayloadTooLong(t *testing.T) {
	f := Frame{Payload: make([]byte, MaxPayload+1)}
	if _, err := f.MarshalBinary(); !errors.Is(err, types.ErrTooLong) {
		t.Fatalf("want ErrTooLong, got %v", err)
	}
}

func TestParseFrameTrailingBytesIgnored(t *testing.T) {
	f := Frame{MsgType: 0x01, Payload: []byte{1, 2, 3}}
	b, _ := f.MarshalBinary()
	b = append(b, 0xde, 0xad) // extra bytes after the frame
	got, err := ParseFrame(b)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if !bytes.Equal(got.Payload, []byte{1, 2, 3}) {
		t.Fatalf("payload = % x, want 01 02 03", got.Payload)
	}
}

func TestReadFrameEmptyStreamEOF(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF on empty stream, got %v", err)
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteFrameMarshalError(t *testing.T) {
	// ExtensionType with the channel_msg bit set is invalid for marshaling.
	f := Frame{ExtensionType: 0x8000, MsgType: 0x01, Payload: []byte{1}}
	if err := WriteFrame(io.Discard, f); !errors.Is(err, ErrExtensionRange) {
		t.Fatalf("want ErrExtensionRange, got %v", err)
	}
}

func TestWriteFrameWriterError(t *testing.T) {
	f := Frame{MsgType: 0x01, Payload: []byte{1, 2, 3}}
	if err := WriteFrame(errWriter{}, f); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("want io.ErrClosedPipe, got %v", err)
	}
}

func TestReadFrameTruncatedPayload(t *testing.T) {
	f := Frame{MsgType: 0x01, Payload: bytes.Repeat([]byte{0xaa}, 20)}
	b, _ := f.MarshalBinary()
	// Keep the full header but drop most of the payload.
	if _, err := ReadFrame(bytes.NewReader(b[:HeaderSize+5])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestMaxPayloadBoundaryRoundTrip(t *testing.T) {
	// Exercises the full 3-byte U24 length at its maximum. Allocates ~16MB.
	p := make([]byte, MaxPayload)
	p[0], p[len(p)-1] = 0x01, 0x02
	f := Frame{MsgType: 0x57, Payload: p}
	b, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	got, err := ParseFrame(b)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if len(got.Payload) != MaxPayload || got.Payload[0] != 0x01 || got.Payload[MaxPayload-1] != 0x02 {
		t.Fatalf("max-payload round trip failed (len %d)", len(got.Payload))
	}
}
