package main

import (
	"fmt"

	"github.com/jonandonigv/tcp/server"
)

/*
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

} */

func main() {

	server := server.CreateTCPServer("localhost:3000")

	go func() {
		for msg := range server.RecieveBuffer {
			fmt.Printf("<Message \n < Headers: address %s > \n Payload: %s >", msg.Header.FromAddress, msg.Payload)
			response := "< Message from " + msg.Header.FromAddress + " Recieved>"

			select {
			case server.SendBuffer <- response:
			case <-server.QuitChannel:
				return
			}
		}
	}()

	server.Listen()
	/*
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
	*/
}
