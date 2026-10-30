package framing

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Insulince/switchyard/sv2/types"
)

// TestHeaderByteLayout pins the exact 6-byte header encoding from sv2-spec 3.2:
// extension_type U16 LE (bit 15 = channel_msg), msg_type U8, msg_length U24 LE.
func TestHeaderByteLayout(t *testing.T) {
	f := Frame{ExtensionType: 0x0001, MsgType: 0x10, Payload: []byte{0x61, 0x62}}
	got, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	// ext 0x0001 LE = 01 00 ; msg_type 10 ; len 2 U24 LE = 02 00 00 ; payload 61 62
	want := []byte{0x01, 0x00, 0x10, 0x02, 0x00, 0x00, 0x61, 0x62}
	if !bytes.Equal(got, want) {
		t.Fatalf("frame = % x, want % x", got, want)
	}
}

// TestChannelMsgBit verifies channel_msg sets bit 15 of extension_type.
func TestChannelMsgBit(t *testing.T) {
	f := Frame{ChannelMsg: true, ExtensionType: 0x0001, MsgType: 0x00}
	got, err := f.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	// 0x0001 | 0x8000 = 0x8001 -> LE bytes 01 80
	if got[0] != 0x01 || got[1] != 0x80 {
		t.Fatalf("extension bytes = % x, want 01 80", got[:2])
	}
	parsed, err := ParseFrame(got)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if !parsed.ChannelMsg || parsed.ExtensionType != 0x0001 {
		t.Fatalf("parsed channelMsg=%v ext=%#x", parsed.ChannelMsg, parsed.ExtensionType)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	cases := []Frame{
		{ExtensionType: 0, MsgType: 0, Payload: nil},
		{ExtensionType: 0x7FFF, MsgType: 0xFF, Payload: []byte{1, 2, 3, 4}},
		{ChannelMsg: true, ExtensionType: 0x1234, MsgType: 0x4D, Payload: bytes.Repeat([]byte{0xab}, 1000)},
	}
	for _, in := range cases {
		raw, err := in.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		out, err := ParseFrame(raw)
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if out.ChannelMsg != in.ChannelMsg || out.ExtensionType != in.ExtensionType || out.MsgType != in.MsgType {
			t.Fatalf("header mismatch: in %+v out %+v", in, out)
		}
		if !bytes.Equal(out.Payload, in.Payload) && !(len(out.Payload) == 0 && len(in.Payload) == 0) {
			t.Fatalf("payload mismatch len in %d out %d", len(in.Payload), len(out.Payload))
		}
	}
}

func TestExtensionTypeRange(t *testing.T) {
	f := Frame{ExtensionType: 0x8000} // bit 15 must not be set via ExtensionType
	if _, err := f.MarshalBinary(); !errors.Is(err, ErrExtensionRange) {
		t.Fatalf("want ErrExtensionRange, got %v", err)
	}
}

func TestWriteReadFrame(t *testing.T) {
	in := Frame{ChannelMsg: true, ExtensionType: 0x0042, MsgType: 0x1B, Payload: []byte("hello sv2")}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// A second frame back-to-back to prove ReadFrame consumes exactly one.
	second := Frame{MsgType: 0x02, Payload: []byte{0xff}}
	if err := WriteFrame(&buf, second); err != nil {
		t.Fatalf("WriteFrame second: %v", err)
	}

	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.MsgType != in.MsgType || !bytes.Equal(got.Payload, in.Payload) || !got.ChannelMsg {
		t.Fatalf("first frame mismatch: %+v", got)
	}
	got2, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame second: %v", err)
	}
	if got2.MsgType != second.MsgType || !bytes.Equal(got2.Payload, second.Payload) {
		t.Fatalf("second frame mismatch: %+v", got2)
	}
}

func TestParseFrameTruncatedPayload(t *testing.T) {
	// Header claims 5 payload bytes but only 1 is present.
	raw := []byte{0x00, 0x00, 0x10, 0x05, 0x00, 0x00, 0xaa}
	if _, err := ParseFrame(raw); !errors.Is(err, types.ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}

func TestReadFrameTruncatedHeader(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader([]byte{0x00, 0x00})); err == nil {
		t.Fatalf("ReadFrame on short header: want error, got nil")
	}
}
