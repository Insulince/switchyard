// Package common implements the Stratum V2 Common subprotocol messages
// (sv2-spec 3.6, message types in 08-Message-Types): SetupConnection,
// SetupConnection.Success, SetupConnection.Error, and ChannelEndpointChanged.
// These are the connection-setup handshake every SV2 subprotocol shares.
package common

import (
	"errors"
	"fmt"

	"github.com/Insulince/switchyard/sv2/framing"
	"github.com/Insulince/switchyard/sv2/types"
)

// Subprotocol identifiers carried in SetupConnection.protocol.
const (
	ProtocolMining               uint8 = 0
	ProtocolJobDeclaration       uint8 = 1
	ProtocolTemplateDistribution uint8 = 2
)

// Common message type bytes.
const (
	TypeSetupConnection        uint8 = 0x00
	TypeSetupConnectionSuccess uint8 = 0x01
	TypeSetupConnectionError   uint8 = 0x02
	TypeChannelEndpointChanged uint8 = 0x03
)

// ErrWrongMessageType is returned when a Parse* function receives a frame whose
// MsgType does not match the expected message.
var ErrWrongMessageType = errors.New("sv2/common: wrong message type")

// expectType validates the frame's message type before decoding its payload.
func expectType(f framing.Frame, want uint8) error {
	if f.MsgType != want {
		return fmt.Errorf("got %#x want %#x: %w", f.MsgType, want, ErrWrongMessageType)
	}
	return nil
}

// SetupConnection initiates a connection; it is the first message a client
// sends. (Client -> Server)
type SetupConnection struct {
	Protocol        uint8
	MinVersion      uint16
	MaxVersion      uint16
	Flags           uint32
	EndpointHost    string
	EndpointPort    uint16
	Vendor          string
	HardwareVersion string
	Firmware        string
	DeviceID        string
}

// ToFrame encodes the message into a standard frame.
func (m SetupConnection) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU8(m.Protocol)
	e.PutU16(m.MinVersion)
	e.PutU16(m.MaxVersion)
	e.PutU32(m.Flags)
	if err := e.PutStr0_255(m.EndpointHost); err != nil {
		return framing.Frame{}, fmt.Errorf("endpoint_host: %w", err)
	}
	e.PutU16(m.EndpointPort)
	if err := e.PutStr0_255(m.Vendor); err != nil {
		return framing.Frame{}, fmt.Errorf("vendor: %w", err)
	}
	if err := e.PutStr0_255(m.HardwareVersion); err != nil {
		return framing.Frame{}, fmt.Errorf("hardware_version: %w", err)
	}
	if err := e.PutStr0_255(m.Firmware); err != nil {
		return framing.Frame{}, fmt.Errorf("firmware: %w", err)
	}
	if err := e.PutStr0_255(m.DeviceID); err != nil {
		return framing.Frame{}, fmt.Errorf("device_id: %w", err)
	}
	return framing.Frame{MsgType: TypeSetupConnection, Payload: e.Bytes()}, nil
}

// ParseSetupConnection decodes a SetupConnection from a frame.
func ParseSetupConnection(f framing.Frame) (SetupConnection, error) {
	var m SetupConnection
	if err := expectType(f, TypeSetupConnection); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.Protocol, err = d.U8(); err != nil {
		return m, err
	}
	if m.MinVersion, err = d.U16(); err != nil {
		return m, err
	}
	if m.MaxVersion, err = d.U16(); err != nil {
		return m, err
	}
	if m.Flags, err = d.U32(); err != nil {
		return m, err
	}
	if m.EndpointHost, err = d.Str0_255(); err != nil {
		return m, err
	}
	if m.EndpointPort, err = d.U16(); err != nil {
		return m, err
	}
	if m.Vendor, err = d.Str0_255(); err != nil {
		return m, err
	}
	if m.HardwareVersion, err = d.Str0_255(); err != nil {
		return m, err
	}
	if m.Firmware, err = d.Str0_255(); err != nil {
		return m, err
	}
	if m.DeviceID, err = d.Str0_255(); err != nil {
		return m, err
	}
	return m, nil
}

// SetupConnectionSuccess accepts a connection. (Server -> Client)
type SetupConnectionSuccess struct {
	UsedVersion uint16
	Flags       uint32
}

// ToFrame encodes the message into a standard frame.
func (m SetupConnectionSuccess) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU16(m.UsedVersion)
	e.PutU32(m.Flags)
	return framing.Frame{MsgType: TypeSetupConnectionSuccess, Payload: e.Bytes()}, nil
}

// ParseSetupConnectionSuccess decodes a SetupConnection.Success from a frame.
func ParseSetupConnectionSuccess(f framing.Frame) (SetupConnectionSuccess, error) {
	var m SetupConnectionSuccess
	if err := expectType(f, TypeSetupConnectionSuccess); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.UsedVersion, err = d.U16(); err != nil {
		return m, err
	}
	if m.Flags, err = d.U32(); err != nil {
		return m, err
	}
	return m, nil
}

// SetupConnectionError rejects a connection prior to closing it.
// (Server -> Client)
type SetupConnectionError struct {
	Flags     uint32
	ErrorCode string
}

// ToFrame encodes the message into a standard frame.
func (m SetupConnectionError) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.Flags)
	if err := e.PutStr0_255(m.ErrorCode); err != nil {
		return framing.Frame{}, fmt.Errorf("error_code: %w", err)
	}
	return framing.Frame{MsgType: TypeSetupConnectionError, Payload: e.Bytes()}, nil
}

// ParseSetupConnectionError decodes a SetupConnection.Error from a frame.
func ParseSetupConnectionError(f framing.Frame) (SetupConnectionError, error) {
	var m SetupConnectionError
	if err := expectType(f, TypeSetupConnectionError); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.Flags, err = d.U32(); err != nil {
		return m, err
	}
	if m.ErrorCode, err = d.Str0_255(); err != nil {
		return m, err
	}
	return m, nil
}

// ChannelEndpointChanged notifies that a channel's endpoint changed. It is a
// channel message: channel_id rides in the payload with the channel_msg bit set.
// (Server -> Client)
type ChannelEndpointChanged struct {
	ChannelID uint32
}

// ToFrame encodes the message into a channel frame.
func (m ChannelEndpointChanged) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.ChannelID)
	return framing.Frame{MsgType: TypeChannelEndpointChanged, ChannelMsg: true, Payload: e.Bytes()}, nil
}

// ParseChannelEndpointChanged decodes a ChannelEndpointChanged from a frame.
func ParseChannelEndpointChanged(f framing.Frame) (ChannelEndpointChanged, error) {
	var m ChannelEndpointChanged
	if err := expectType(f, TypeChannelEndpointChanged); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.ChannelID, err = d.U32(); err != nil {
		return m, err
	}
	return m, nil
}
