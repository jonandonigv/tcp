// Package tcp — stack demux per RFC 793 §3.9 and AGENTS.md §7.
// This file provides a minimal in-memory Stack for tests that does not
// require privileged sockets. It is the orchestration layer that will
// eventually integrate with netadapter.TUN/TAP; for phase 4 it serves
// as a loopback demux between two TCBs.
package tcp

import (
	"net/netip"

	"github.com/jonandonigv/tcp/pkg/retransmit"
)

// Stack is a minimal in-memory TCP stack for tests (RFC 793 §3.9 demux).
// It tracks TCBs by 4-tuple and dispatches segments without raw sockets.
type Stack struct {
	tcbs map[string]*TCB
}

// NewStack returns an empty stack.
func NewStack() *Stack { return &Stack{tcbs: make(map[string]*TCB)} }

// key returns a 4-tuple map key.
func key(localAddr netip.Addr, localPort uint16, remoteAddr netip.Addr, remotePort uint16) string {
	return localAddr.String() + ":" + itoa(localPort) + "->" + remoteAddr.String() + ":" + itoa(remotePort)
}

func itoa(v uint16) string {
	// fast path avoid fmt
	if v == 0 {
		return "0"
	}
	var b [6]byte
	pos := len(b)
	for v > 0 {
		pos--
		b[pos] = byte('0' + v%10)
		v /= 10
	}
	return string(b[pos:])
}

// Add inserts a TCB into the demux table.
func (s *Stack) Add(tcb *TCB) { s.tcbs[key(tcb.LocalAddr, tcb.LocalPort, tcb.RemoteAddr, tcb.RemotePort)] = tcb }

// Lookup finds a TCB by 4-tuple; if not found but a LISTEN exists on
// localAddr:localPort, that LISTEN is returned for HandleListenSegment.
func (s *Stack) Lookup(localAddr netip.Addr, localPort uint16, remoteAddr netip.Addr, remotePort uint16) (*TCB, bool) {
	if tcb, ok := s.tcbs[key(localAddr, localPort, remoteAddr, remotePort)]; ok {
		return tcb, true
	}
	// Fallback: search for LISTEN on same local
	for _, tcb := range s.tcbs {
		if tcb.State == StateListen && tcb.LocalAddr == localAddr && tcb.LocalPort == localPort {
			return tcb, true
		}
	}
	return nil, false
}

// Deliver is the test helper that delivers a segment (hdr+payload) to the
// appropriate TCB and returns any reply headers and delivered payload.
// It updates retransmit queues where applicable.
//
// For LISTEN it clones a child TCB and stores it; for others it routes
// through control HandleSegment or data Recv depending on state.
func (s *Stack) Deliver(localAddr, remoteAddr netip.Addr, hdr *Header, payload []byte, iss uint32, q *retransmit.Queue) (replyHdr *Header, delivered []byte, newChild *TCB, err error) {
	// Try exact 4-tuple first
	tcb, ok := s.Lookup(localAddr, hdr.DstPort, remoteAddr, hdr.SrcPort)
	if !ok {
		// No TCB — drop (RFC 793 p.65 CLOSED).
		return nil, nil, nil, ErrTCBClosed
	}
	if tcb.State == StateListen {
		child, reply, err := HandleListenSegmentWithAddrs(tcb, hdr, remoteAddr, iss)
		if err != nil {
			return nil, nil, nil, err
		}
		if child != nil {
			s.Add(child)
			newChild = child
			replyHdr = reply
		}
		return replyHdr, nil, newChild, nil
	}
	// Connected path: try handshake first; if synchronized and payload, try data.
	switch tcb.State {
	case StateSynSent, StateSynReceived:
		reply, err := HandleSegment(tcb, hdr)
		return reply, nil, nil, err
	default:
		// Attempt data path; fallback to handshake for non-data states
		delivered, ack, err := Recv(tcb, q, hdr, payload)
		if err != nil && err != ErrSegmentOutOfWindow && err != ErrAckNotAcceptable {
			// For data-path errors other than window/ack, also try control
			if reply, cerr := HandleSegment(tcb, hdr); cerr == nil && reply != nil {
				return reply, delivered, nil, err
			}
		}
		return ack, delivered, nil, err
	}
}
