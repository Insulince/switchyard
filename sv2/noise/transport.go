package noise

import (
	"fmt"
	"io"

	"github.com/Insulince/switchyard/sv2/framing"
)

// This file is the post-handshake transport: it carries cleartext SV2
// framing.Frame values over the AEAD channel established by the handshake. The
// record layout follows SRI codec-sv2 (encoder.rs / decoder.rs):
//
//   - The 6-byte SV2 frame header is encrypted as its own AEAD record
//     (6 + 16 MAC = 22 bytes on the wire).
//   - The payload is encrypted in records of up to SV2_FRAME_CHUNK_SIZE bytes
//     each (ciphertext + MAC); i.e. at most maxChunkPlaintext plaintext bytes
//     per record.
//
// There is no separate length prefix: the decrypted header's msg_length tells
// the reader how many payload bytes (and therefore how many records) follow.
// Transport records use empty associated data and the per-direction monotonic
// nonce (verified against SRI's GenericCipher::encrypt and nonce_to_bytes).

const (
	// frameChunkSize is SRI's SV2_FRAME_CHUNK_SIZE: the maximum size of a single
	// encrypted record (ciphertext including the 16-byte MAC).
	frameChunkSize = 65535
	// maxChunkPlaintext is the most plaintext one record can carry.
	maxChunkPlaintext = frameChunkSize - tagLen
	// encryptedHeaderSize is the wire size of the encrypted 6-byte frame header.
	encryptedHeaderSize = framing.HeaderSize + tagLen
)

// WriteFrame encrypts f and writes it to w as a sequence of AEAD records: one
// for the header, then one per payload chunk. Records are written with the send
// cipher, advancing its nonce once per record.
func (t *Transport) WriteFrame(w io.Writer, f framing.Frame) error {
	raw, err := f.MarshalBinary()
	if err != nil {
		return err
	}

	encHeader, err := t.send.encrypt(nil, raw[:framing.HeaderSize])
	if err != nil {
		return fmt.Errorf("sv2/noise: encrypt header: %w", err)
	}
	if _, err := w.Write(encHeader); err != nil {
		return err
	}

	payload := raw[framing.HeaderSize:]
	for len(payload) > 0 {
		n := len(payload)
		if n > maxChunkPlaintext {
			n = maxChunkPlaintext
		}
		record, err := t.send.encrypt(nil, payload[:n])
		if err != nil {
			return fmt.Errorf("sv2/noise: encrypt payload chunk: %w", err)
		}
		if _, err := w.Write(record); err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

// EncryptMessage seals a single Noise transport record with empty associated
// data, the direct analog of SRI's NoiseCodec::encrypt. Unlike WriteFrame it
// performs no SV2 frame header/chunk structure; it is the raw record primitive,
// used by interop tests and by callers that manage their own message framing.
func (t *Transport) EncryptMessage(plaintext []byte) ([]byte, error) {
	return t.send.encrypt(nil, plaintext)
}

// DecryptMessage opens a single Noise transport record produced by
// EncryptMessage (or SRI's NoiseCodec::encrypt).
func (t *Transport) DecryptMessage(ciphertext []byte) ([]byte, error) {
	return t.recv.decrypt(nil, ciphertext)
}

// ReadFrame reads one encrypted frame from r and returns the decrypted Frame. It
// first reads and decrypts the header record to learn the payload length, then
// reads exactly the payload records that length implies. Records are decrypted
// with the recv cipher, advancing its nonce once per record. A truncated stream
// yields io.ErrUnexpectedEOF.
func (t *Transport) ReadFrame(r io.Reader) (framing.Frame, error) {
	encHeader := make([]byte, encryptedHeaderSize)
	if _, err := io.ReadFull(r, encHeader); err != nil {
		return framing.Frame{}, err
	}
	header, err := t.recv.decrypt(nil, encHeader)
	if err != nil {
		return framing.Frame{}, fmt.Errorf("sv2/noise: decrypt header: %w", err)
	}

	meta, payloadLen, err := framing.ParseHeader(header)
	if err != nil {
		return framing.Frame{}, err
	}

	payload := make([]byte, 0, payloadLen)
	remaining := payloadLen
	for remaining > 0 {
		n := remaining
		if n > maxChunkPlaintext {
			n = maxChunkPlaintext
		}
		record := make([]byte, n+tagLen)
		if _, err := io.ReadFull(r, record); err != nil {
			return framing.Frame{}, err
		}
		chunk, err := t.recv.decrypt(nil, record)
		if err != nil {
			return framing.Frame{}, fmt.Errorf("sv2/noise: decrypt payload chunk: %w", err)
		}
		payload = append(payload, chunk...)
		remaining -= n
	}

	meta.Payload = payload
	return meta, nil
}
