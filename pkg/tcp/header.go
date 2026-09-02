// Package tcp implements the Transmission Control Protocol per RFC 793.
// This file implements the TCP header codec (RFC 793 §3.1 p.15-17).
package tcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// RFC 793 §3.1 — TCP Header Format
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |           |U|A|P|R|S|F|                               |
// | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
// |       |           |G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             data                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Flag bits — RFC 793 §3.1 (6 control bits).
const (
	FlagFIN uint8 = 1 << 0 // 0x01
	FlagSYN uint8 = 1 << 1 // 0x02
	FlagRST uint8 = 1 << 2 // 0x04
	FlagPSH uint8 = 1 << 3 // 0x08
	FlagACK uint8 = 1 << 4 // 0x10
	FlagURG uint8 = 1 << 5 // 0x20

	// FlagMask is the set of valid control bits (6 bits).
	FlagMask uint8 = 0x3F
)

const (
	MinHeaderLen  = 20
	MaxHeaderLen  = 60
	MaxOptionsLen = 40
)

// Sentinel errors for spec violations.
var (
	ErrHeaderTooShort    = errors.New("tcp: header too short")
	ErrHeaderTooLong     = errors.New("tcp: header too long")
	ErrInvalidDataOffset = errors.New("tcp: invalid data offset")
	ErrReservedNotZero   = errors.New("tcp: reserved bits must be zero")
	ErrInvalidFlagBits   = errors.New("tcp: invalid flag bits")
	ErrChecksumMismatch  = errors.New("tcp: checksum mismatch")
	ErrInvalidOptionsLen = errors.New("tcp: options length invalid")
)

// Header represents the TCP header per RFC 793 §3.1.
// All multi-byte fields are in network byte order on the wire.
type Header struct {
	SrcPort   uint16
	DstPort   uint16
	SeqNum    uint32
	AckNum    uint32
	// DataOffset is the header length in 32-bit words (5..15). It is
	// computed on Marshal from Options length and validated on Parse.
	DataOffset uint8
	Flags      uint8  // low 6 bits: URG|ACK|PSH|RST|SYN|FIN
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
	// Options holds raw option bytes (0..40) without padding. Padding is
	// handled automatically on Marshal/Parse. Callers may include Kind
	// 0 (EOL) and Kind 1 (NOP) as needed; MSS (Kind 2) etc. are carried
	// opaquely until option parsing is extended (RFC 793 §3.1, RFC 1122).
	Options []byte
}

// HasFlag reports whether the given flag bit is set.
func (h *Header) HasFlag(f uint8) bool { return h.Flags&f != 0 }

// String returns a short debug representation.
func (h *Header) String() string {
	return fmt.Sprintf("tcp.Header{%d→%d seq=%d ack=%d flags=%06b win=%d csum=0x%04x urg=%d opts=%d}",
		h.SrcPort, h.DstPort, h.SeqNum, h.AckNum, h.Flags, h.Window, h.Checksum, h.UrgentPtr, len(h.Options))
}

// Marshal encodes the header into network byte order per RFC 793 §3.1.
// It validates field ranges, computes DataOffset from Options (with padding
// to a 32-bit boundary), and writes the checksum field as stored in
// h.Checksum (no pseudo-header calculation). Use MarshalWithChecksum to
// compute the checksum over src/dst/payload.
//
// The returned slice is exactly DataOffset*4 bytes (20..60).
func (h *Header) Marshal() ([]byte, error) {
	if h.Flags&^FlagMask != 0 {
		return nil, fmt.Errorf("%w: flags 0x%02x exceed 6 bits", ErrInvalidFlagBits, h.Flags)
	}
	if len(h.Options) > MaxOptionsLen {
		return nil, fmt.Errorf("%w: %d > %d", ErrInvalidOptionsLen, len(h.Options), MaxOptionsLen)
	}
	// Pad options to multiple of 4 bytes as part of header.
	optLen := len(h.Options)
	paddedOptLen := (optLen + 3) &^ 3 // round up to multiple of 4
	headerLen := MinHeaderLen + paddedOptLen
	if headerLen > MaxHeaderLen {
		return nil, fmt.Errorf("%w: header length %d > %d", ErrHeaderTooLong, headerLen, MaxHeaderLen)
	}
	dataOffset := uint8(headerLen / 4)
	if dataOffset < 5 || dataOffset > 15 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidDataOffset, dataOffset)
	}

	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(b[2:4], h.DstPort)
	binary.BigEndian.PutUint32(b[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(b[8:12], h.AckNum)
	// RFC 793 §3.1: DataOffset (4 bits) in high nibble of byte 12,
	// Reserved (6 bits) must be zero, Flags (6 bits) in low bits of byte 13.
	// Encoding: byte12 = dataOffset<<4, byte13 = flags & 0x3F (reserved zero)
	b[12] = dataOffset << 4
	b[13] = h.Flags & FlagMask
	binary.BigEndian.PutUint16(b[14:16], h.Window)
	binary.BigEndian.PutUint16(b[16:18], h.Checksum)
	binary.BigEndian.PutUint16(b[18:20], h.UrgentPtr)
	if optLen > 0 {
		copy(b[20:20+optLen], h.Options)
		// remaining padded bytes are already zero (EOL / padding)
	}
	// Store computed DataOffset back for callers inspecting h after marshal.
	h.DataOffset = dataOffset
	return b, nil
}

// MarshalWithChecksum marshals the header plus payload length into a complete
// TCP segment and computes the checksum including the IPv4 pseudo-header
// (RFC 793 §3.1 p.16). The pseudo-header is:
//
//	0      7 8     15 16    23 24    31
//	+--------+--------+--------+--------+
//	|          source address           |
//	+--------+--------+--------+--------+
//	|        destination address        |
//	+--------+--------+--------+--------+
//	|  zero  |protocol|   TCP length    |
//	+--------+--------+--------+--------+
//
// Protocol is 6 (TCP). TCP length is header + payload length.
//
// src and dst must be IPv4 addresses (IPv6 out of scope for MVP).
// The computed checksum is written into the segment and into h.Checksum.
// Payload is not modified; it is included only for checksum calculation.
func (h *Header) MarshalWithChecksum(src, dst netip.Addr, payload []byte) ([]byte, error) {
	if !src.Is4() || !dst.Is4() {
		return nil, fmt.Errorf("tcp: MarshalWithChecksum requires IPv4 addresses, got src=%v dst=%v", src, dst)
	}
	// Marshal with checksum zero for calculation.
	saved := h.Checksum
	h.Checksum = 0
	hdr, err := h.Marshal()
	if err != nil {
		h.Checksum = saved
		return nil, err
	}
	// Build segment = hdr + payload for checksum.
	segLen := len(hdr) + len(payload)
	// Compute checksum over pseudo-header + segment.
	csum := tcpChecksum(src, dst, hdr, payload, segLen)
	// Write checksum into header bytes (network order).
	binary.BigEndian.PutUint16(hdr[16:18], csum)
	h.Checksum = csum
	return hdr, nil
}

// Parse parses a TCP segment's header from b per RFC 793 §3.1.
// It validates DataOffset, Reserved bits, and minimum length, then returns
// the decoded Header and the remaining payload slice (headerLen .. len(b)).
// The slice returned shares storage with b. Checksum is not verified here;
// use VerifyChecksum for that.
//
// b must contain at least the header (DataOffset*4 bytes); it may contain
// additional payload bytes which are returned separately.
func Parse(b []byte) (*Header, []byte, error) {
	if len(b) < MinHeaderLen {
		return nil, nil, fmt.Errorf("%w: %d < %d", ErrHeaderTooShort, len(b), MinHeaderLen)
	}
	dataOffset := b[12] >> 4
	if dataOffset < 5 {
		return nil, nil, fmt.Errorf("%w: %d < 5", ErrInvalidDataOffset, dataOffset)
	}
	headerLen := int(dataOffset) * 4
	if headerLen > MaxHeaderLen {
		return nil, nil, fmt.Errorf("%w: %d > %d", ErrHeaderTooLong, headerLen, MaxHeaderLen)
	}
	if len(b) < headerLen {
		return nil, nil, fmt.Errorf("%w: need %d have %d", ErrHeaderTooShort, headerLen, len(b))
	}
	// Reserved bits: 6 bits spanning low 4 bits of byte12 + top 2 bits of byte13.
	// RFC 793 requires zero; RFC 1122 clarifies must be zero on send, ignored
	// on receive is tolerant — we enforce strict (MVP) and can relax later.
	reserved := ((b[12] & 0x0F) << 2) | (b[13] >> 6)
	if reserved != 0 {
		return nil, nil, fmt.Errorf("%w: got 0x%02x", ErrReservedNotZero, reserved)
	}
	flags := b[13] & FlagMask
	h := &Header{
		SrcPort:    binary.BigEndian.Uint16(b[0:2]),
		DstPort:    binary.BigEndian.Uint16(b[2:4]),
		SeqNum:     binary.BigEndian.Uint32(b[4:8]),
		AckNum:     binary.BigEndian.Uint32(b[8:12]),
		DataOffset: dataOffset,
		Flags:      flags,
		Window:     binary.BigEndian.Uint16(b[14:16]),
		Checksum:   binary.BigEndian.Uint16(b[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(b[18:20]),
	}
	// Options: raw bytes between fixed header and padding.
	optTotal := headerLen - MinHeaderLen
	if optTotal > 0 {
		optBytes := b[20:headerLen]
		// Trim trailing zero padding (but keep NO-OP/EOL structure for
		// callers that care — we only trim zeros beyond meaningful options).
		// For simplicity we return the slice trimmed of trailing zeros;
		// a zero-length options field of pure padding returns nil.
		// Callers needing exact padding can reconstruct from DataOffset.
		trimmed := trimTrailingZeros(optBytes)
		if len(trimmed) > 0 {
			h.Options = make([]byte, len(trimmed))
			copy(h.Options, trimmed)
		}
	}
	payload := b[headerLen:]
	return h, payload, nil
}

// VerifyChecksum validates the checksum of a complete TCP segment (header +
// payload) against the IPv4 pseudo-header per RFC 793 §3.1. It returns
// ErrChecksumMismatch if the checksum is invalid. The segment must include
// the header as transmitted (checksum field non-zero).
func VerifyChecksum(src, dst netip.Addr, segment []byte) error {
	if !src.Is4() || !dst.Is4() {
		return fmt.Errorf("tcp: VerifyChecksum requires IPv4 addresses, got src=%v dst=%v", src, dst)
	}
	if len(segment) < MinHeaderLen {
		return fmt.Errorf("%w: segment too short for checksum", ErrHeaderTooShort)
	}
	// Compute one's complement sum over pseudo-header + segment.
	// Valid checksum => sum == 0xFFFF (i.e., ~sum == 0). Equivalent to
	// computing checksum with checksum field included should yield 0.
	sum := sumWithPseudoHeader(src, dst, segment, len(segment))
	if sum != 0xFFFF {
		return fmt.Errorf("%w: computed 0x%04x", ErrChecksumMismatch, sum)
	}
	return nil
}

// ComputeChecksum computes the TCP checksum for the given header and payload
// with the IPv4 pseudo-header. It is a lower-level helper used by
// MarshalWithChecksum and for testing. Header bytes are provided as already
// marshaled (checksum field should be zero).
func ComputeChecksum(src, dst netip.Addr, headerBytes, payload []byte) uint16 {
	if !src.Is4() || !dst.Is4() {
		return 0
	}
	segLen := len(headerBytes) + len(payload)
	return tcpChecksum(src, dst, headerBytes, payload, segLen)
}

// tcpChecksum computes the one's complement checksum over pseudo-header +
// headerBytes + payload. headerBytes checksum field is assumed zero on entry.
// segLen is total TCP length (header+payload) for the pseudo-header.
func tcpChecksum(src, dst netip.Addr, headerBytes, payload []byte, segLen int) uint16 {
	sum := sumWithPseudoHeaderForChecksum(src, dst, headerBytes, payload, segLen)
	return ^uint16(sum)
}

// sumWithPseudoHeader returns the raw one's complement sum (before final
// complement) over pseudo-header + segment. For verification the segment
// includes its checksum field; a valid segment yields 0xFFFF.
func sumWithPseudoHeader(src, dst netip.Addr, segment []byte, segLen int) uint16 {
	src4 := src.As4()
	dst4 := dst.As4()
	var sum uint32
	// Pseudo-header: src (4), dst (4), zero+protocol (2), length (2)
	sum += uint32(src4[0])<<8 | uint32(src4[1])
	sum += uint32(src4[2])<<8 | uint32(src4[3])
	sum += uint32(dst4[0])<<8 | uint32(dst4[1])
	sum += uint32(dst4[2])<<8 | uint32(dst4[3])
	sum += uint32(6) // protocol = 6 (TCP) in low byte, high byte zero
	sum += uint32(segLen)
	// TCP segment (header+payload) with checksum field as-is.
	sum = addBytes(sum, segment)
	// Fold carries.
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum)
}

func sumWithPseudoHeaderForChecksum(src, dst netip.Addr, headerBytes, payload []byte, segLen int) uint32 {
	src4 := src.As4()
	dst4 := dst.As4()
	var sum uint32
	sum += uint32(src4[0])<<8 | uint32(src4[1])
	sum += uint32(src4[2])<<8 | uint32(src4[3])
	sum += uint32(dst4[0])<<8 | uint32(dst4[1])
	sum += uint32(dst4[2])<<8 | uint32(dst4[3])
	sum += uint32(6)
	sum += uint32(segLen)
	sum = addBytes(sum, headerBytes)
	sum = addBytes(sum, payload)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return sum
}

func addBytes(sum uint32, b []byte) uint32 {
	// RFC 1071 — one's complement sum over 16-bit words, network order,
	// odd tail padded with zero byte.
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	return sum
}

func trimTrailingZeros(b []byte) []byte {
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	return b[:end]
}
