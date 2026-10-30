package noise

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/Insulince/switchyard/sv2/framing"
	"github.com/btcsuite/btcd/btcec/v2"
)

// establishedPair runs a full handshake and returns the responder and initiator
// transports, ready for encrypted frame exchange.
func establishedPair(t *testing.T) (resp, init *Transport) {
	t.Helper()
	authority, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	static, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	r := NewResponder(authority, static, time.Minute)
	i, act1, err := NewInitiator(authority.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	const now = uint32(1_000_000)
	act2, rt, err := r.Respond(act1, now)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	it, err := i.ProcessAct2(act2, now)
	if err != nil {
		t.Fatalf("ProcessAct2: %v", err)
	}
	return rt, it
}

func roundTripFrame(t *testing.T, from, to *Transport, f framing.Frame) framing.Frame {
	t.Helper()
	var buf bytes.Buffer
	if err := from.WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := to.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	return got
}

func TestTransportFrameRoundTrip(t *testing.T) {
	rt, it := establishedPair(t)

	down := framing.Frame{MsgType: 0x1f, ChannelMsg: true, Payload: []byte("a mining job")}
	got := roundTripFrame(t, rt, it, down)
	if got.MsgType != down.MsgType || got.ChannelMsg != down.ChannelMsg || !bytes.Equal(got.Payload, down.Payload) {
		t.Fatalf("downstream mismatch: %+v vs %+v", got, down)
	}

	up := framing.Frame{MsgType: 0x1b, ChannelMsg: true, Payload: []byte("a submitted share")}
	got2 := roundTripFrame(t, it, rt, up)
	if got2.MsgType != up.MsgType || !bytes.Equal(got2.Payload, up.Payload) {
		t.Fatalf("upstream mismatch: %+v vs %+v", got2, up)
	}
}

func TestTransportEmptyPayload(t *testing.T) {
	rt, it := establishedPair(t)
	f := framing.Frame{MsgType: 0x00, Payload: nil}

	var buf bytes.Buffer
	if err := rt.WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// An empty-payload frame is exactly one encrypted header record on the wire.
	if buf.Len() != encryptedHeaderSize {
		t.Fatalf("wire size %d, want %d", buf.Len(), encryptedHeaderSize)
	}
	got, err := it.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(got.Payload) != 0 || got.MsgType != 0x00 {
		t.Fatalf("empty frame mismatch: %+v", got)
	}
}

func TestTransportMultiChunk(t *testing.T) {
	rt, it := establishedPair(t)

	// Payload spanning several chunks (each chunk carries maxChunkPlaintext).
	payload := make([]byte, 2*maxChunkPlaintext+1234)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	f := framing.Frame{MsgType: 0x57, ChannelMsg: true, Payload: payload}

	var buf bytes.Buffer
	if err := rt.WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// Wire size: encrypted header + 3 payload records (two full + one partial),
	// each record adding a MAC.
	wantChunks := 3
	wantWire := encryptedHeaderSize + len(payload) + wantChunks*tagLen
	if buf.Len() != wantWire {
		t.Fatalf("wire size %d, want %d", buf.Len(), wantWire)
	}

	got, err := it.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatalf("multi-chunk payload mismatch (len got %d want %d)", len(got.Payload), len(payload))
	}
}

func TestTransportTamperDetected(t *testing.T) {
	rt, it := establishedPair(t)
	f := framing.Frame{MsgType: 0x21, ChannelMsg: true, Payload: bytes.Repeat([]byte{0xab}, 100)}

	var buf bytes.Buffer
	if err := rt.WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	b := buf.Bytes()
	b[encryptedHeaderSize+3] ^= 0xff // corrupt a payload-record byte

	if _, err := it.ReadFrame(bytes.NewReader(b)); err == nil {
		t.Fatal("expected AEAD failure on tampered transport record")
	}
}

func TestTransportSequentialFrames(t *testing.T) {
	rt, it := establishedPair(t)
	var buf bytes.Buffer
	frames := []framing.Frame{
		{MsgType: 0x01, Payload: []byte("one")},
		{MsgType: 0x02, Payload: []byte("two")},
		{MsgType: 0x03, Payload: []byte("three")},
	}
	for _, f := range frames {
		if err := rt.WriteFrame(&buf, f); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}
	for i, want := range frames {
		got, err := it.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		if got.MsgType != want.MsgType || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame %d mismatch: %+v vs %+v", i, got, want)
		}
	}
}

func TestTransportTruncatedStream(t *testing.T) {
	rt, it := establishedPair(t)
	f := framing.Frame{MsgType: 0x05, Payload: bytes.Repeat([]byte{1}, 50)}
	var buf bytes.Buffer
	if err := rt.WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// Chop the stream mid-payload-record.
	truncated := buf.Bytes()[:encryptedHeaderSize+5]
	if _, err := it.ReadFrame(bytes.NewReader(truncated)); err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want io.ErrUnexpectedEOF, got %v", err)
	}
}
