// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package socksproto

import (
	"encoding/binary"
	"errors"
)

var (
	ErrUDPDatagramTooShort = errors.New("socks udp datagram too short")
	ErrUDPFragmented       = errors.New("socks udp fragmentation unsupported")
)

type UDPDatagram struct {
	Target  Target
	Payload []byte
}

func ParseUDPDatagram(packet []byte) (UDPDatagram, error) {
	if len(packet) < 4 {
		return UDPDatagram{}, ErrUDPDatagramTooShort
	}
	if packet[2] != 0 {
		return UDPDatagram{}, ErrUDPFragmented
	}

	target, offset, err := parseTargetWithOffset(packet[3:])
	if err != nil {
		return UDPDatagram{}, err
	}
	offset += 3
	if len(packet) < offset {
		return UDPDatagram{}, ErrUDPDatagramTooShort
	}

	return UDPDatagram{
		Target:  target,
		Payload: append([]byte(nil), packet[offset:]...),
	}, nil
}

func BuildUDPDatagram(target Target, payload []byte) []byte {
	targetBytes := BuildTargetPayload(target)
	packet := make([]byte, 0, 3+len(targetBytes)+len(payload))
	packet = append(packet, 0x00, 0x00, 0x00)
	packet = append(packet, targetBytes...)
	packet = append(packet, payload...)
	return packet
}

func BuildTargetPayload(target Target) []byte {
	switch target.AddressType {
	case AddressTypeIPv4:
		packet := make([]byte, 1+4+2)
		packet[0] = AddressTypeIPv4
		copy(packet[1:5], ParseIPv4(target.Host))
		binary.BigEndian.PutUint16(packet[5:7], target.Port)
		return packet
	case AddressTypeIPv6:
		packet := make([]byte, 1+16+2)
		packet[0] = AddressTypeIPv6
		copy(packet[1:17], ParseIPv6(target.Host))
		binary.BigEndian.PutUint16(packet[17:19], target.Port)
		return packet
	default:
		hostBytes := []byte(target.Host)
		packet := make([]byte, 1+1+len(hostBytes)+2)
		packet[0] = AddressTypeDomain
		packet[1] = byte(len(hostBytes))
		copy(packet[2:2+len(hostBytes)], hostBytes)
		binary.BigEndian.PutUint16(packet[2+len(hostBytes):], target.Port)
		return packet
	}
}

func parseTargetWithOffset(payload []byte) (Target, int, error) {
	target, err := ParseTargetPayload(payload)
	if err != nil {
		return Target{}, 0, err
	}

	offset := 1
	switch target.AddressType {
	case AddressTypeIPv4:
		offset += 4 + 2
	case AddressTypeIPv6:
		offset += 16 + 2
	case AddressTypeDomain:
		if len(payload) < 2 {
			return Target{}, 0, ErrTargetTooShort
		}
		offset += 1 + int(payload[1]) + 2
	default:
		return Target{}, 0, ErrUnsupportedAddressType
	}
	return target, offset, nil
}
