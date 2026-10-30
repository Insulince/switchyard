package common

import (
	"testing"

	"github.com/Insulince/switchyard/sv2/framing"
)

// FuzzCommonParsers asserts every Common parser tolerates arbitrary payloads
// without panicking. Run longer with:
//
//	go test ./internal/sv2/common -run x -fuzz FuzzCommonParsers
func FuzzCommonParsers(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add(make([]byte, 64))

	parsers := []struct {
		mt    uint8
		parse func(framing.Frame) error
	}{
		{TypeSetupConnection, func(fr framing.Frame) error { _, e := ParseSetupConnection(fr); return e }},
		{TypeSetupConnectionSuccess, func(fr framing.Frame) error { _, e := ParseSetupConnectionSuccess(fr); return e }},
		{TypeSetupConnectionError, func(fr framing.Frame) error { _, e := ParseSetupConnectionError(fr); return e }},
		{TypeChannelEndpointChanged, func(fr framing.Frame) error { _, e := ParseChannelEndpointChanged(fr); return e }},
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, p := range parsers {
			_ = p.parse(framing.Frame{MsgType: p.mt, Payload: payload})
		}
	})
}

// FuzzNegotiate asserts SetupConnection negotiation never panics and always
// returns exactly one of (success, error) for any decoded request.
func FuzzNegotiate(f *testing.F) {
	f.Add(uint8(0), uint16(2), uint16(2), uint32(0))
	f.Add(uint8(2), uint16(0), uint16(9), uint32(0xffffffff))

	cfg := ServerConfig{MinVersion: 2, MaxVersion: 2, AcceptedFlags: map[uint8]uint32{ProtocolMining: 0b101}}
	f.Fuzz(func(t *testing.T, protocol uint8, minV, maxV uint16, flags uint32) {
		ok, errMsg := cfg.Negotiate(SetupConnection{Protocol: protocol, MinVersion: minV, MaxVersion: maxV, Flags: flags})
		if (ok == nil) == (errMsg == nil) {
			t.Fatalf("Negotiate must return exactly one of success/error (ok=%v err=%v)", ok, errMsg)
		}
	})
}
