package common

import (
	"errors"
	"testing"

	"github.com/Insulince/switchyard/sv2/types"
)

func TestSetupConnectionRoundTrip(t *testing.T) {
	in := SetupConnection{
		Protocol:        ProtocolJobDeclaration,
		MinVersion:      2,
		MaxVersion:      2,
		Flags:           0x0000_0001,
		EndpointHost:    "pool.example",
		EndpointPort:    3336,
		Vendor:          "switchyard",
		HardwareVersion: "n/a",
		Firmware:        "sri-jdc",
		DeviceID:        "dev-42",
	}
	f, err := in.ToFrame()
	if err != nil {
		t.Fatalf("ToFrame: %v", err)
	}
	if f.MsgType != TypeSetupConnection || f.ChannelMsg {
		t.Fatalf("frame meta: type=%#x channelMsg=%v", f.MsgType, f.ChannelMsg)
	}
	out, err := ParseSetupConnection(f)
	if err != nil {
		t.Fatalf("ParseSetupConnection: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch:\n in  %+v\n out %+v", in, out)
	}
}

func TestSetupConnectionWireOrder(t *testing.T) {
	// Pin field order: protocol U8, min U16, max U16, flags U32, then strings/port.
	in := SetupConnection{Protocol: 0x01, MinVersion: 0x0002, MaxVersion: 0x0002, Flags: 0x04030201}
	f, err := in.ToFrame()
	if err != nil {
		t.Fatalf("ToFrame: %v", err)
	}
	p := f.Payload
	// protocol=01 ; min=02 00 ; max=02 00 ; flags LE=01 02 03 04
	want := []byte{0x01, 0x02, 0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04}
	for i := range want {
		if p[i] != want[i] {
			t.Fatalf("payload prefix = % x, want % x", p[:len(want)], want)
		}
	}
}

func TestSetupConnectionSuccessRoundTrip(t *testing.T) {
	in := SetupConnectionSuccess{UsedVersion: 2, Flags: 0xDEADBEEF}
	f, err := in.ToFrame()
	if err != nil {
		t.Fatalf("ToFrame: %v", err)
	}
	if f.MsgType != TypeSetupConnectionSuccess {
		t.Fatalf("type = %#x", f.MsgType)
	}
	out, err := ParseSetupConnectionSuccess(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if out != in {
		t.Fatalf("mismatch %+v vs %+v", out, in)
	}
}

func TestSetupConnectionErrorRoundTrip(t *testing.T) {
	in := SetupConnectionError{Flags: 0x1, ErrorCode: "unsupported-protocol"}
	f, err := in.ToFrame()
	if err != nil {
		t.Fatalf("ToFrame: %v", err)
	}
	if f.MsgType != TypeSetupConnectionError {
		t.Fatalf("type = %#x", f.MsgType)
	}
	out, err := ParseSetupConnectionError(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if out != in {
		t.Fatalf("mismatch %+v vs %+v", out, in)
	}
}

func TestChannelEndpointChangedRoundTrip(t *testing.T) {
	in := ChannelEndpointChanged{ChannelID: 0x01020304}
	f, err := in.ToFrame()
	if err != nil {
		t.Fatalf("ToFrame: %v", err)
	}
	if f.MsgType != TypeChannelEndpointChanged {
		t.Fatalf("type = %#x", f.MsgType)
	}
	if !f.ChannelMsg {
		t.Fatalf("ChannelEndpointChanged must set channel_msg bit")
	}
	out, err := ParseChannelEndpointChanged(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if out != in {
		t.Fatalf("mismatch %+v vs %+v", out, in)
	}
}

func TestParseWrongType(t *testing.T) {
	f, _ := SetupConnectionSuccess{UsedVersion: 2}.ToFrame()
	if _, err := ParseSetupConnection(f); !errors.Is(err, ErrWrongMessageType) {
		t.Fatalf("want ErrWrongMessageType, got %v", err)
	}
}

func TestParseTruncated(t *testing.T) {
	// SetupConnection.Success needs 6 bytes; give it a frame with only 2.
	f, _ := SetupConnectionSuccess{UsedVersion: 2}.ToFrame()
	f.Payload = f.Payload[:2]
	if _, err := ParseSetupConnectionSuccess(f); !errors.Is(err, types.ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}
