package common

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Insulince/switchyard/sv2/framing"
)

// framer is satisfied by every message struct via its value-receiver ToFrame.
type framer interface{ ToFrame() (framing.Frame, error) }

// pinMessage pins a message's wire behavior three ways:
//
//  1. canonical encoding: decode then re-encode reproduces the exact payload
//     bytes (no field is dropped, reordered, or re-widened);
//  2. wrong message type is rejected before any payload decoding;
//  3. truncation sweep: every prefix shorter than the full payload yields an
//     error rather than a panic or a silent partial parse.
//
// The instance passed in should set every variable-length field non-empty so the
// sweep exercises each field's length-prefix and body decode path.
func pinMessage[T framer](t *testing.T, m T, wantType uint8, wantChannel bool, parse func(framing.Frame) (T, error)) {
	t.Helper()
	f, err := m.ToFrame()
	if err != nil {
		t.Fatalf("ToFrame: %v", err)
	}
	if f.MsgType != wantType {
		t.Fatalf("MsgType = %#x, want %#x", f.MsgType, wantType)
	}
	if f.ChannelMsg != wantChannel {
		t.Fatalf("ChannelMsg = %v, want %v", f.ChannelMsg, wantChannel)
	}

	got, err := parse(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	f2, err := got.ToFrame()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(f.Payload, f2.Payload) {
		t.Fatalf("non-canonical re-encode:\n in  %x\n out %x", f.Payload, f2.Payload)
	}

	wrong := framing.Frame{MsgType: wantType ^ 0xFF, ChannelMsg: wantChannel, Payload: f.Payload}
	if _, err := parse(wrong); !errors.Is(err, ErrWrongMessageType) {
		t.Fatalf("wrong type: want ErrWrongMessageType, got %v", err)
	}

	for i := 0; i < len(f.Payload); i++ {
		short := framing.Frame{MsgType: wantType, ChannelMsg: wantChannel, Payload: append([]byte(nil), f.Payload[:i]...)}
		if _, err := parse(short); err == nil {
			t.Fatalf("payload truncated to %d/%d bytes parsed without error", i, len(f.Payload))
		}
	}
}

func TestPinCommonMessages(t *testing.T) {
	pinMessage(t, SetupConnection{
		Protocol: ProtocolMining, MinVersion: 2, MaxVersion: 2, Flags: 0xdeadbeef,
		EndpointHost: "host.example", EndpointPort: 3335,
		Vendor: "vendor", HardwareVersion: "hw1", Firmware: "fw2", DeviceID: "dev-3",
	}, TypeSetupConnection, false, ParseSetupConnection)

	pinMessage(t, SetupConnectionSuccess{UsedVersion: 2, Flags: 0x5},
		TypeSetupConnectionSuccess, false, ParseSetupConnectionSuccess)

	pinMessage(t, SetupConnectionError{Flags: 0x2, ErrorCode: ErrorCodeUnsupportedProtocol},
		TypeSetupConnectionError, false, ParseSetupConnectionError)

	pinMessage(t, ChannelEndpointChanged{ChannelID: 7},
		TypeChannelEndpointChanged, true, ParseChannelEndpointChanged)
}
