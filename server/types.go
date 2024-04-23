package server

type HeaderMessage struct {
	FromAddress string
	// TODO: Add all the TCP header
}

type Message struct {
	Header  HeaderMessage
	Payload []byte
}
