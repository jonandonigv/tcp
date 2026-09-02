// Package main implements a tiny CLI to exercise the RFC 793 stack
// without privileged sockets (AGENTS.md §3 cmd/example). It runs a
// deterministic loopback handshake + data transfer + graceful close via
// the in-memory Stack demux (pkg/tcp/stack.go) and retransmit queues.
//
// Usage:
//
//	go run ./cmd/example
package main

import (
	"fmt"
	"log"
	"net/netip"
	"time"

	"github.com/jonandonigv/tcp/pkg/retransmit"
	"github.com/jonandonigv/tcp/pkg/tcp"
)

func main() {
	local := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("10.0.0.2")
	const (
		clientPort = 12345
		serverPort = 80
		clientISS  = 1000
		serverISS  = 2000
	)

	// Deterministic clock for 2MSL timer (no sleeps in tests, example uses real time).
	now := time.Now()

	stack := tcp.NewStack()

	// Passive open: server LISTEN
	listen, err := tcp.PassiveOpen(remote, serverPort, 8192)
	if err != nil {
		log.Fatalf("PassiveOpen: %v", err)
	}
	stack.Add(listen)
	fmt.Printf("LISTEN %v:%d\n", remote, serverPort)

	// Active open: client SYN-SENT
	clientTCB, syn, err := tcp.ActiveOpen(local, clientPort, remote, serverPort, clientISS, 4096)
	if err != nil {
		log.Fatalf("ActiveOpen: %v", err)
	}
	stack.Add(clientTCB)
	fmt.Printf("SYN  %d→%d seq=%d (client SYN-SENT)\n", clientPort, serverPort, syn.SeqNum)

	// Server receives SYN -> SYN-RECEIVED + SYN-ACK
	qClient := retransmit.NewQueue(nil)
	qServer := retransmit.NewQueue(nil)
	reply, _, newChild, err := stack.Deliver(remote, local, syn, nil, serverISS, qServer)
	if err != nil {
		log.Fatalf("deliver SYN: %v", err)
	}
	serverTCB := newChild
	fmt.Printf("SYN-ACK %d→%d seq=%d ack=%d (server SYN-RECEIVED)\n", reply.SrcPort, reply.DstPort, reply.SeqNum, reply.AckNum)

	// Client receives SYN-ACK -> ESTABLISHED + ACK
	ack, err := tcp.HandleSegment(clientTCB, reply)
	if err != nil {
		log.Fatalf("client SYN-ACK: %v", err)
	}
	fmt.Printf("ACK  %d→%d seq=%d ack=%d (client ESTABLISHED)\n", ack.SrcPort, ack.DstPort, ack.SeqNum, ack.AckNum)

	// Server receives ACK -> ESTABLISHED
	if _, err := tcp.HandleSegment(serverTCB, ack); err != nil {
		log.Fatalf("server ACK: %v", err)
	}
	fmt.Printf("ESTABLISHED client=%v server=%v\n", clientTCB.State, serverTCB.State)

	// Data: client -> server (MSS 10 for demo, split)
	payload := []byte("hello loopback via RFC 793 stack")
	hdrs, err := tcp.Send(clientTCB, qClient, payload, 10)
	if err != nil {
		log.Fatalf("Send: %v", err)
	}
	fmt.Printf("Send %d bytes in %d segments (SND.NXT=%d)\n", len(payload), len(hdrs), clientTCB.SndNxt)

	var reassembled []byte
	for i, h := range hdrs {
		chunk := payload[i*10:]
		if len(chunk) > 10 {
			chunk = chunk[:10]
		}
		if i == len(hdrs)-1 {
			// last chunk may be shorter
			remaining := len(payload) - i*10
			chunk = payload[i*10 : i*10+remaining]
		}
		// Deliver to server via Recv (stack Deliver would also work)
		delivered, ackSeg, err := tcp.Recv(serverTCB, qServer, h, chunk)
		if err != nil {
			log.Fatalf("Recv %d: %v", i, err)
		}
		reassembled = append(reassembled, delivered...)
		if ackSeg != nil {
			// Server ACKs, client processes ACK + window update
			if _, _, err := tcp.Recv(clientTCB, qClient, ackSeg, nil); err != nil && err != tcp.ErrSegmentOutOfWindow {
				// pure ACK may be handled via control; also try HandleSegment for window
				tcp.HandleSegment(clientTCB, ackSeg)
			}
		}
		fmt.Printf("  seg %d seq=%d len=%d → server RCV.NXT=%d delivered=%q\n", i, h.SeqNum, len(chunk), serverTCB.RcvNxt, delivered)
	}
	fmt.Printf("Reassembled %q (expected %q) match=%v\n", reassembled, payload, string(reassembled) == string(payload))

	// Graceful close: client active close
	fin, err := tcp.Close(clientTCB, qClient)
	if err != nil {
		log.Fatalf("Close: %v", err)
	}
	fmt.Printf("FIN  %d→%d seq=%d (client %v)\n", fin.SrcPort, fin.DstPort, fin.SeqNum, clientTCB.State)

	// Server receives FIN -> CLOSE-WAIT
	if _, err := tcp.HandleSegment(serverTCB, fin); err != nil {
		// Recv path also handles FIN for data; try Recv
		tcp.Recv(serverTCB, qServer, fin, nil)
	}
	// Also via data path to ensure RCV.NXT+state
	tcp.Recv(serverTCB, qServer, fin, nil)
	fmt.Printf("Server after FIN: %v RCV.NXT=%d\n", serverTCB.State, serverTCB.RcvNxt)

	// Server needs to ACK FIN (HandleSegment already sent ACK, but simulate)
	ackFIN := tcp.BuildAck(serverTCB)
	// Client processes ACK of its FIN -> FIN-WAIT-2 (via HandleSegment)
	tcp.HandleSegment(clientTCB, ackFIN)
	fmt.Printf("Client after FIN-ACK: %v SND.UNA=%d\n", clientTCB.State, clientTCB.SndUna)

	// Server passive close -> LAST-ACK
	fin2, err := tcp.Close(serverTCB, qServer)
	if err != nil {
		log.Fatalf("server Close: %v", err)
	}
	fmt.Printf("FIN  %d→%d seq=%d (server %v)\n", fin2.SrcPort, fin2.DstPort, fin2.SeqNum, serverTCB.State)

	// Client receives FIN -> TIME-WAIT
	tcp.Recv(clientTCB, qClient, fin2, nil)
	ack2 := tcp.BuildAck(clientTCB)
	fmt.Printf("Client after peer FIN: %v RCV.NXT=%d\n", clientTCB.State, clientTCB.RcvNxt)

	// Server receives ACK -> CLOSED
	tcp.HandleSegment(serverTCB, ack2)
	fmt.Printf("Server after final ACK: %v\n", serverTCB.State)

	// TIME-WAIT 2MSL expiry
	if clientTCB.State == tcp.StateTimeWait {
		clientTCB.EnterTimeWait(now, tcp.Default2MSL)
		fmt.Printf("Client TIME-WAIT until %v (2MSL=%v)\n", clientTCB.TimeWaitUntil, tcp.Default2MSL)
		// Fast-forward
		clientTCB.CloseTimeWait(now.Add(tcp.Default2MSL + time.Nanosecond))
		fmt.Printf("Client after 2MSL: %v\n", clientTCB.State)
	}

	fmt.Println("Loopback exercise complete (no privileged sockets, deterministic).")
}
