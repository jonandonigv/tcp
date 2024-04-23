package server

import (
	"log"
	"net"
	"os"
	"sync"
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

	return nil
}

func (s *Server) AcceptConnections() {}

func (s *Server) ReadConnection(conn net.Conn) {}

func (s *Server) CloseAllConnections() {}
