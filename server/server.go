package server

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type Server struct {
	Address           string
	Listener          net.Listener
	QuitChannel       chan struct{}
	RecieveBuffer     chan Message
	SendBuffer        chan string
	Wg                sync.WaitGroup
	ActiveConnections map[net.Conn]struct{}
	ActiveConnMux     sync.Mutex
}

func CreateTCPServer(addr string) *Server {
	return &Server{
		Address:           addr,
		QuitChannel:       make(chan struct{}),
		RecieveBuffer:     make(chan Message, 10),
		SendBuffer:        make(chan string, 10),
		ActiveConnections: make(map[net.Conn]struct{}),
	}
}

func (s *Server) Listen() error {
	listener, err := net.Listen("tcp", s.Address)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer listener.Close()
	s.Listener = listener

	// Setup signal handling for graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-signalCh
		fmt.Printf("Recieved signal %s, shutting down...\n", sig)
		// Close the QuitChannel to signal graceful shutdown
		close(s.QuitChannel)
		// Close all active connections before shutting down
		s.CloseAllConnections()
	}()

	// Accept connections on a diff go routine
	s.Wg.Add(1)
	go s.AcceptConnections()

	fmt.Println("Server listening on", s.Address)

	// Wait for QuitChannel to be closed
	<-s.QuitChannel

	close(s.RecieveBuffer)
	close(s.SendBuffer)

	return nil
}

func (s *Server) AcceptConnections() {
	defer s.Wg.Done()

	for {
		select {
		case <-s.QuitChannel:
			return
		default:
		}

		conn, err := s.Listener.Accept()
		if err != nil {
			log.Fatal("error accepting connection:", err)
			continue
		}

		// TODO: Add the connection tot he active connection map

		log.Println("new connection:", conn.RemoteAddr())

		// Handle the connection on a separate goroutine
		s.Wg.Add(1)
		go s.ReadConnection(conn)
	}
}

func (s *Server) ReadConnection(conn net.Conn) {
	defer conn.Close()
	defer s.Wg.Done()

	buff := make([]byte, 2050)

	for {
		bytesRead, err := conn.Read(buff)
		if err != nil {
			log.Printf("Connection closed: %s", conn.RemoteAddr().Network())
			// TODO: Remove the connection for the active connection map
			return
		}

		header := HeaderMessage{
			FromAddress: conn.RemoteAddr().String(),
		}

		s.RecieveBuffer <- Message{
			Header:  header,
			Payload: buff[:bytesRead],
		}

		respond := <-s.SendBuffer

		_, err = conn.Write([]byte(respond))
		if err != nil {
			log.Fatal(err)
		}

	}
}

func (s *Server) CloseAllConnections() {}
