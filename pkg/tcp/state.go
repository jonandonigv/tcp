// Package tcp — state machine per RFC 793 §3.2 p.22 / Figure 6 p.23.
// TCB is owned by a single goroutine; all state transitions are driven
// via channels, not shared mutable state.
package tcp

import (
	"errors"
	"fmt"
)

// State represents the TCP connection state (RFC 793 Figure 6, p.23).
type State uint8

const (
	StateClosed       State = iota // CLOSED
	StateListen                    // LISTEN
	StateSynSent                   // SYN-SENT
	StateSynReceived               // SYN-RECEIVED
	StateEstablished               // ESTABLISHED
	StateFinWait1                  // FIN-WAIT-1
	StateFinWait2                  // FIN-WAIT-2
	StateCloseWait                 // CLOSE-WAIT
	StateClosing                   // CLOSING
	StateLastAck                   // LAST-ACK
	StateTimeWait                  // TIME-WAIT
)

// stateNames mirrors RFC 793 naming.
var stateNames = map[State]string{
	StateClosed:       "CLOSED",
	StateListen:       "LISTEN",
	StateSynSent:      "SYN-SENT",
	StateSynReceived:  "SYN-RECEIVED",
	StateEstablished:  "ESTABLISHED",
	StateFinWait1:     "FIN-WAIT-1",
	StateFinWait2:     "FIN-WAIT-2",
	StateCloseWait:    "CLOSE-WAIT",
	StateClosing:      "CLOSING",
	StateLastAck:      "LAST-ACK",
	StateTimeWait:     "TIME-WAIT",
}

func (s State) String() string {
	if n, ok := stateNames[s]; ok {
		return n
	}
	return fmt.Sprintf("State(%d)", uint8(s))
}

// Sentinel errors.
var (
	ErrInvalidState      = errors.New("tcp: invalid state")
	ErrInvalidTransition = errors.New("tcp: invalid state transition")
	ErrInvalidEvent      = errors.New("tcp: invalid event")
)

// Event represents a stimulus that may cause a state transition.
// RFC 793 §3.2 / p.22 distinguishes user calls (OPEN, SEND, RECEIVE,
// CLOSE, ABORT, STATUS), segment arrivals, and timeouts. This skeleton
// models them as discrete events; phase 3 will drive the full
// event→(state, action) table.
type Event uint8

const (
	// User calls — RFC 793 p.22.
	EventPassiveOpen Event = iota // LISTEN (passive OPEN)
	EventActiveOpen               // SYN-SENT (active OPEN)
	EventSend                     // SEND (user data)
	EventReceive                  // RECEIVE
	EventClose                    // CLOSE (graceful)
	EventAbort                    // ABORT (RST)
	EventStatus                   // STATUS (query)

	// Segment arrivals — control bits observed on the wire.
	EventRcvSyn    // RCV SYN
	EventRcvSynAck // RCV SYN+ACK
	EventRcvAck    // RCV ACK
	EventRcvFin    // RCV FIN
	EventRcvFinAck // RCV FIN+ACK
	EventRcvRst    // RCV RST

	// Timeouts.
	EventRetransmitTimeout // RTO expiry
	EventTimeWaitTimeout   // 2MSL expiry in TIME-WAIT
)

var eventNames = map[Event]string{
	EventPassiveOpen:       "PASSIVE_OPEN",
	EventActiveOpen:        "ACTIVE_OPEN",
	EventSend:              "SEND",
	EventReceive:           "RECEIVE",
	EventClose:             "CLOSE",
	EventAbort:             "ABORT",
	EventStatus:            "STATUS",
	EventRcvSyn:            "RCV_SYN",
	EventRcvSynAck:         "RCV_SYNACK",
	EventRcvAck:            "RCV_ACK",
	EventRcvFin:            "RCV_FIN",
	EventRcvFinAck:         "RCV_FINACK",
	EventRcvRst:            "RCV_RST",
	EventRetransmitTimeout: "TIMEOUT_RETRANSMIT",
	EventTimeWaitTimeout:   "TIMEOUT_TIMEWAIT",
}

func (e Event) String() string {
	if n, ok := eventNames[e]; ok {
		return n
	}
	return fmt.Sprintf("Event(%d)", uint8(e))
}

// transitionTable encodes the RFC 793 Figure 6 edges plus the classic
// BSD extensions. Each entry is the set of states reachable from a
// given state via *any* event; the precise event→next-state mapping is
// validated by NextState. This two-level design keeps the skeleton
// deterministic and extensible: add finer event guards in phase 3 without
// changing CanTransitionTo callers.
//
// For determinism the table is exhaustive and declarative — no sleeps,
// no I/O, purely table-driven (see AGENTS.md Testing).
var transitionTable = map[State]map[State]struct{}{
	StateClosed: {
		StateListen:  {},
		StateSynSent: {},
	},
	StateListen: {
		StateSynReceived: {},
		StateSynSent:     {}, // simultaneous active open from LISTEN (RFC 793 p.32)
		StateClosed:      {},
	},
	StateSynSent: {
		StateClosed:      {},
		StateSynReceived: {},
		StateEstablished: {},
	},
	StateSynReceived: {
		StateEstablished: {},
		StateFinWait1:    {},
		StateClosed:      {}, // RST
	},
	StateEstablished: {
		StateFinWait1:  {},
		StateCloseWait: {},
		StateClosed:    {}, // ABORT/RST
	},
	StateFinWait1: {
		StateFinWait2: {},
		StateClosing:  {},
		StateTimeWait: {}, // simultaneous FIN/ACK edge
		StateClosed:   {},
	},
	StateFinWait2: {
		StateTimeWait: {},
		StateClosed:   {},
	},
	StateCloseWait: {
		StateLastAck: {},
		StateClosed:  {},
	},
	StateClosing: {
		StateTimeWait: {},
		StateClosed:   {},
	},
	StateLastAck: {
		StateClosed: {},
	},
	StateTimeWait: {
		StateClosed: {},
	},
}

// eventTable maps (state, event) → next state for the skeleton. Only the
// transitions required for deterministic unit tests are encoded; phase 3
// will complete the full RFC 793 §3.9 event processing (segment
// acceptability, SEQ/ACK validation, window updates). Illegal
// (state,event) pairs return ErrInvalidTransition and leave state unchanged.
var eventTable = map[State]map[Event]State{
	StateClosed: {
		EventPassiveOpen: StateListen,
		EventActiveOpen:  StateSynSent,
	},
	StateListen: {
		EventRcvSyn:    StateSynReceived,
		EventActiveOpen: StateSynSent,
		EventClose:     StateClosed,
		EventAbort:     StateClosed,
	},
	StateSynSent: {
		EventClose:     StateClosed,
		EventAbort:     StateClosed,
		EventRcvSyn:    StateSynReceived,
		EventRcvSynAck: StateEstablished,
		EventRcvRst:    StateClosed,
	},
	StateSynReceived: {
		EventRcvAck: StateEstablished,
		EventClose:  StateFinWait1,
		EventAbort:  StateClosed,
		EventRcvRst: StateClosed,
		EventRcvFin: StateFinWait1, // peer CLOSE after SYN-RECEIVED before ESTABLISHED (rare)
	},
	StateEstablished: {
		EventClose:  StateFinWait1,
		EventAbort:  StateClosed,
		EventRcvFin: StateCloseWait,
		EventRcvRst: StateClosed,
	},
	StateFinWait1: {
		EventRcvAck:    StateFinWait2, // ACK of our FIN
		EventRcvFin:    StateClosing,  // simultaneous close: FIN without ACK
		EventRcvFinAck: StateTimeWait, // FIN+ACK together
		EventRcvRst:    StateClosed,
		EventAbort:     StateClosed,
	},
	StateFinWait2: {
		EventRcvFin: StateTimeWait,
		EventClose:  StateTimeWait, // already sent FIN; passive half-close
		EventAbort:  StateClosed,
		EventRcvRst: StateClosed,
	},
	StateCloseWait: {
		EventClose:  StateLastAck,
		EventAbort:  StateClosed,
		EventRcvRst: StateClosed,
	},
	StateClosing: {
		EventRcvAck: StateTimeWait,
		EventAbort:  StateClosed,
		EventRcvRst: StateClosed,
	},
	StateLastAck: {
		EventRcvAck: StateClosed,
		EventAbort:  StateClosed,
		EventRcvRst: StateClosed,
	},
	StateTimeWait: {
		EventTimeWaitTimeout: StateClosed,
		EventAbort:           StateClosed,
	},
}

// CanTransitionTo reports whether a direct transition from s to next is
// allowed by the RFC 793 state diagram, regardless of the triggering event.
func (s State) CanTransitionTo(next State) bool {
	m, ok := transitionTable[s]
	if !ok {
		return false
	}
	_, ok = m[next]
	return ok
}

// NextState returns the next state for (s, ev) per the skeleton event table.
// If the pair is illegal it returns ErrInvalidTransition. STATUS and SEND/
// RECEIVE in most states are no-ops (remain in same state) and are encoded
// explicitly where legal.
func NextState(s State, ev Event) (State, error) {
	if _, ok := stateNames[s]; !ok {
		return s, fmt.Errorf("%w: %v", ErrInvalidState, s)
	}
	if ev == EventStatus || ev == EventSend || ev == EventReceive {
		// RFC 793 §3.9 — STATUS/SEND/RECEIVE do not change state in most
		// states (data-transfer states). For the skeleton allow them as
		// no-ops in synced states; reject in CLOSED/LISTEN/SYN-* where they
		// are illegal. Phase 3 will add buffering semantics.
		switch s {
		case StateEstablished, StateFinWait1, StateFinWait2, StateCloseWait, StateClosing, StateLastAck:
			return s, nil
		case StateSynReceived:
			if ev == EventSend {
				return s, nil
			}
		}
		// otherwise fall through to table lookup for rejection
	}
	m, ok := eventTable[s]
	if !ok {
		return s, fmt.Errorf("%w: %v --%v--> ?", ErrInvalidTransition, s, ev)
	}
	nxt, ok := m[ev]
	if !ok {
		return s, fmt.Errorf("%w: %v --%v--> ?", ErrInvalidTransition, s, ev)
	}
	return nxt, nil
}

// IsSynchronized reports whether the state has completed the three-way
// handshake (RFC 793 p.23: ESTABLISHED, FIN-WAIT-*, CLOSE-WAIT, CLOSING,
// LAST-ACK, TIME-WAIT).
func (s State) IsSynchronized() bool {
	switch s {
	case StateEstablished, StateFinWait1, StateFinWait2, StateCloseWait, StateClosing, StateLastAck, StateTimeWait:
		return true
	default:
		return false
	}
}

// IsClosed reports whether no TCB exists (CLOSED).
func (s State) IsClosed() bool { return s == StateClosed }
