package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

const (
	HOST = "localhost"
	TYPE = "tcp"
	PORT = "8080"
)

func handleRequest(conn net.Conn) {
	// Inconming request
	buffer := make([]byte, 1024)
	_, err := conn.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}

	// Write data ti response
	time := time.Now().Format(time.ANSIC)
	responseStr := fmt.Sprintf("Your message is: %v. Recieved time: %v", string(buffer[:]), time)
	conn.Write([]byte(responseStr))

	conn.Close()

}

func main() {
	listen, err := net.Listen(TYPE, HOST+":"+PORT)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	} else {
		fmt.Printf("Listening in %v:%v", HOST, PORT)
	}

	// Close the listener
	defer listen.Close()

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}

		go handleRequest(conn)

	}
}
