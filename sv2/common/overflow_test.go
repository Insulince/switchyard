package common

import "testing"

// TestToFrameFieldOverflow pins that each STR0_255 field surfaces an encode error
// when it exceeds 255 bytes.
func TestToFrameFieldOverflow(t *testing.T) {
	bigStr := string(make([]byte, 256))
	cases := []struct {
		name string
		m    framer
	}{
		{"SetupConnection.EndpointHost", SetupConnection{EndpointHost: bigStr}},
		{"SetupConnection.Vendor", SetupConnection{Vendor: bigStr}},
		{"SetupConnection.HardwareVersion", SetupConnection{HardwareVersion: bigStr}},
		{"SetupConnection.Firmware", SetupConnection{Firmware: bigStr}},
		{"SetupConnection.DeviceID", SetupConnection{DeviceID: bigStr}},
		{"SetupConnectionError.ErrorCode", SetupConnectionError{ErrorCode: bigStr}},
	}
	for _, c := range cases {
		if _, err := c.m.ToFrame(); err == nil {
			t.Fatalf("%s: expected ToFrame overflow error, got nil", c.name)
		}
	}
}
