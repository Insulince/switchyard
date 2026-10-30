package common

// This file implements the server (responder) side of SetupConnection
// negotiation, per sv2-spec 09-Common-Messages. The structs live in common.go;
// this is the policy that turns a client SetupConnection into either
// SetupConnection.Success or SetupConnection.Error.

// Version is the current Stratum V2 protocol version. The spec mandates 2.
const Version uint16 = 2

// SetupConnection.Error error codes (sv2-spec 09, Error Codes section). These
// strings are part of the wire contract; do not alter them.
const (
	ErrorCodeUnsupportedFeatureFlags = "unsupported-feature-flags"
	ErrorCodeUnsupportedProtocol     = "unsupported-protocol"
	ErrorCodeProtocolVersionMismatch = "protocol-version-mismatch"
)

// Mining subprotocol SetupConnection.flags bits (client -> server, "REQUIRES_*";
// sv2-spec 04-Protocol-Overview / 07-Mining). These are the features a connecting
// miner demands of us. BYOT requires work selection (the miner brings its own job)
// and version rolling.
const (
	MiningFlagRequiresStandardJobs   uint32 = 1 << 0
	MiningFlagRequiresWorkSelection  uint32 = 1 << 1
	MiningFlagRequiresVersionRolling uint32 = 1 << 2
)

// Job Declaration subprotocol SetupConnection.flags bits (client -> server).
const (
	JobDeclarationFlagRequiresAsyncJobMining uint32 = 1 << 0
)

// ServerConfig describes what this responder will accept during connection setup:
// the protocol-version range it supports and, per served subprotocol, two distinct
// flag sets the SV2 spec keeps in SEPARATE bit vocabularies.
//
//   - AcceptedFlags: the client-required ("REQUIRES_*") bits this server can
//     satisfy. A client SetupConnection.flags is accepted iff it is a subset of
//     this set. AcceptedFlags also doubles as the set of served subprotocols: a
//     protocol is served iff it has an entry (a served protocol that tolerates no
//     required flags maps to 0).
//   - SuccessFlags: the server's OWN flags advertised in SetupConnection.Success.
//     For Mining these mean REQUIRES_FIXED_VERSION / REQUIRES_EXTENDED_CHANNEL_ONLY
//   - a different vocabulary than the request bits, so they must never be an echo
//     of AcceptedFlags. A protocol with no entry advertises 0 (the common case).
type ServerConfig struct {
	MinVersion    uint16
	MaxVersion    uint16
	AcceptedFlags map[uint8]uint32
	SuccessFlags  map[uint8]uint32
}

// Negotiate applies the SetupConnection negotiation and returns exactly one of a
// success or an error message (the other is nil). Checks run in spec order:
// protocol support, then version overlap, then feature flags.
func (c ServerConfig) Negotiate(req SetupConnection) (*SetupConnectionSuccess, *SetupConnectionError) {
	acceptedFlags, served := c.AcceptedFlags[req.Protocol]
	if !served {
		return nil, &SetupConnectionError{Flags: 0, ErrorCode: ErrorCodeUnsupportedProtocol}
	}

	// Highest version both sides support: intersect the ranges and take the top.
	lo := max(c.MinVersion, req.MinVersion)
	hi := min(c.MaxVersion, req.MaxVersion)
	if lo > hi {
		return nil, &SetupConnectionError{Flags: 0, ErrorCode: ErrorCodeProtocolVersionMismatch}
	}

	// Any required flag bit the server cannot satisfy fails the setup; the
	// offending bits are reported back in the error's flags field.
	if unsupported := req.Flags &^ acceptedFlags; unsupported != 0 {
		return nil, &SetupConnectionError{Flags: unsupported, ErrorCode: ErrorCodeUnsupportedFeatureFlags}
	}

	// Success carries the server's OWN flags (a different vocabulary than the
	// request bits), not an echo of what the client required. Absent => 0.
	return &SetupConnectionSuccess{UsedVersion: hi, Flags: c.SuccessFlags[req.Protocol]}, nil
}
