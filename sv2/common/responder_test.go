package common

import "testing"

func miningCfg() ServerConfig {
	return ServerConfig{
		MinVersion: 2,
		MaxVersion: 2,
		AcceptedFlags: map[uint8]uint32{
			ProtocolMining:         0b101, // tolerates client-required bits 0 and 2
			ProtocolJobDeclaration: 0,     // served, tolerates no required flags
		},
		SuccessFlags: map[uint8]uint32{
			// The server's own Success flags live in a DIFFERENT bit vocabulary
			// than the request flags, so this is deliberately unrelated to
			// AcceptedFlags - the tests assert the two never bleed together.
			ProtocolMining: 0b010,
		},
	}
}

func TestNegotiateSuccess(t *testing.T) {
	req := SetupConnection{Protocol: ProtocolMining, MinVersion: 2, MaxVersion: 2, Flags: 0b100}
	ok, errMsg := miningCfg().Negotiate(req)
	if errMsg != nil {
		t.Fatalf("unexpected error: %+v", errMsg)
	}
	if ok.UsedVersion != 2 {
		t.Fatalf("used_version = %d, want 2", ok.UsedVersion)
	}
	// Success.flags is the server's OWN advertisement (SuccessFlags), never an
	// echo of the client's required bits - those are a separate vocabulary.
	if ok.Flags != 0b010 {
		t.Fatalf("flags = %b, want 010 (server's own success flags, not the client's required flags)", ok.Flags)
	}
}

// TestNegotiateAcceptsRequiredFlagsWithoutEchoingThem is the BYOT case: a client
// requires bits the server tolerates (work-selection + version-rolling), and the
// server advertises NO success flags of its own. The handshake must succeed with
// Success.flags == 0 - the previous design wrongly echoed the required bits back
// into Success.flags (a different bit vocabulary), and earlier still rejected them
// outright. This is the exact handshake the SRI JDC drives.
func TestNegotiateAcceptsRequiredFlagsWithoutEchoingThem(t *testing.T) {
	cfg := ServerConfig{
		MinVersion:    2,
		MaxVersion:    2,
		AcceptedFlags: map[uint8]uint32{ProtocolMining: MiningFlagRequiresWorkSelection | MiningFlagRequiresVersionRolling},
		// No SuccessFlags entry: the gateway requires neither fixed-version nor
		// extended-channel-only, so it advertises nothing back.
	}
	req := SetupConnection{Protocol: ProtocolMining, MinVersion: 2, MaxVersion: 2, Flags: MiningFlagRequiresWorkSelection | MiningFlagRequiresVersionRolling}
	ok, errMsg := cfg.Negotiate(req)
	if errMsg != nil {
		t.Fatalf("unexpected error negotiating BYOT flags: %+v", errMsg)
	}
	if ok.Flags != 0 {
		t.Fatalf("flags = %b, want 0 (server advertises no success flags)", ok.Flags)
	}
}

func TestNegotiateServedProtocolWithNoFlags(t *testing.T) {
	req := SetupConnection{Protocol: ProtocolJobDeclaration, MinVersion: 2, MaxVersion: 2, Flags: 0}
	ok, errMsg := miningCfg().Negotiate(req)
	if errMsg != nil {
		t.Fatalf("unexpected error: %+v", errMsg)
	}
	if ok.Flags != 0 {
		t.Fatalf("flags = %b, want 0", ok.Flags)
	}
}

func TestNegotiateUnsupportedProtocol(t *testing.T) {
	req := SetupConnection{Protocol: ProtocolTemplateDistribution, MinVersion: 2, MaxVersion: 2}
	ok, errMsg := miningCfg().Negotiate(req)
	if ok != nil {
		t.Fatalf("expected error, got success %+v", ok)
	}
	if errMsg.ErrorCode != ErrorCodeUnsupportedProtocol {
		t.Fatalf("error_code = %q, want %q", errMsg.ErrorCode, ErrorCodeUnsupportedProtocol)
	}
}

func TestNegotiateVersionMismatch(t *testing.T) {
	req := SetupConnection{Protocol: ProtocolMining, MinVersion: 3, MaxVersion: 3}
	ok, errMsg := miningCfg().Negotiate(req)
	if ok != nil {
		t.Fatalf("expected error, got success %+v", ok)
	}
	if errMsg.ErrorCode != ErrorCodeProtocolVersionMismatch {
		t.Fatalf("error_code = %q, want %q", errMsg.ErrorCode, ErrorCodeProtocolVersionMismatch)
	}
}

func TestNegotiateVersionOverlapPicksHighest(t *testing.T) {
	c := ServerConfig{MinVersion: 2, MaxVersion: 5, AcceptedFlags: map[uint8]uint32{ProtocolMining: 0}}
	cases := []struct {
		min, max uint16
		want     uint16
		wantErr  bool
	}{
		{3, 9, 5, false}, // capped at server max
		{2, 2, 2, false}, // server min, exact
		{5, 5, 5, false}, // server max, exact
		{1, 3, 3, false}, // client below server min, capped up to overlap
		{6, 9, 0, true},  // disjoint above
		{0, 1, 0, true},  // disjoint below
	}
	for _, tc := range cases {
		ok, errMsg := c.Negotiate(SetupConnection{Protocol: ProtocolMining, MinVersion: tc.min, MaxVersion: tc.max})
		if tc.wantErr {
			if errMsg == nil || errMsg.ErrorCode != ErrorCodeProtocolVersionMismatch {
				t.Fatalf("[%d..%d] expected version-mismatch, got ok=%+v err=%+v", tc.min, tc.max, ok, errMsg)
			}
			continue
		}
		if errMsg != nil {
			t.Fatalf("[%d..%d] unexpected error %+v", tc.min, tc.max, errMsg)
		}
		if ok.UsedVersion != tc.want {
			t.Fatalf("[%d..%d] used_version = %d, want %d", tc.min, tc.max, ok.UsedVersion, tc.want)
		}
	}
}

func TestNegotiateUnsupportedFlags(t *testing.T) {
	// bit 1 (0b010) is not in the server's supported set 0b101.
	req := SetupConnection{Protocol: ProtocolMining, MinVersion: 2, MaxVersion: 2, Flags: 0b110}
	ok, errMsg := miningCfg().Negotiate(req)
	if ok != nil {
		t.Fatalf("expected error, got success %+v", ok)
	}
	if errMsg.ErrorCode != ErrorCodeUnsupportedFeatureFlags {
		t.Fatalf("error_code = %q, want %q", errMsg.ErrorCode, ErrorCodeUnsupportedFeatureFlags)
	}
	if errMsg.Flags != 0b010 {
		t.Fatalf("error flags = %b, want 010 (only the unsupported bit)", errMsg.Flags)
	}
}

func TestNegotiateResultsRoundTripAsFrames(t *testing.T) {
	ok, _ := miningCfg().Negotiate(SetupConnection{Protocol: ProtocolMining, MinVersion: 2, MaxVersion: 2, Flags: 0b001})
	f, err := ok.ToFrame()
	if err != nil {
		t.Fatalf("success ToFrame: %v", err)
	}
	gotOk, err := ParseSetupConnectionSuccess(f)
	if err != nil {
		t.Fatalf("parse success: %v", err)
	}
	if gotOk != *ok {
		t.Fatalf("success round trip: %+v vs %+v", gotOk, *ok)
	}

	_, errMsg := miningCfg().Negotiate(SetupConnection{Protocol: ProtocolTemplateDistribution, MinVersion: 2, MaxVersion: 2})
	ef, err := errMsg.ToFrame()
	if err != nil {
		t.Fatalf("error ToFrame: %v", err)
	}
	gotErr, err := ParseSetupConnectionError(ef)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if gotErr != *errMsg {
		t.Fatalf("error round trip: %+v vs %+v", gotErr, *errMsg)
	}
}
