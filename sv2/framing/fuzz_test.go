package framing

import (
	"bytes"
	"testing"
)

// FuzzParseFrame asserts the frame parser never panics on arbitrary input and
// that any frame it does accept re-encodes and re-parses to an identical frame
// (round-trip stability). Run longer with:
//
//	go test ./internal/sv2/framing -run x -fuzz FuzzParseFrame
func FuzzParseFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	seed, _ := Frame{MsgType: 0x1f, ChannelMsg: true, Payload: []byte{1, 2, 3}}.MarshalBinary()
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		fr, err := ParseFrame(data)
		if err != nil {
			return
		}
		b, err := fr.MarshalBinary()
		if err != nil {
			t.Fatalf("re-marshal of an accepted frame failed: %v", err)
		}
		fr2, err := ParseFrame(b)
		if err != nil {
			t.Fatalf("re-parse of a re-marshaled frame failed: %v", err)
		}
		if fr2.MsgType != fr.MsgType || fr2.ChannelMsg != fr.ChannelMsg || !bytes.Equal(fr2.Payload, fr.Payload) {
			t.Fatalf("round trip not stable:\n in  %+v\n out %+v", fr, fr2)
		}
	})
}
