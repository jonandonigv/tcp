package server

type TCPHeader struct {
	SourceAddress      string
	DestinationAddress string
	SequenceNumber     int32
	AcknolegedNumber   int16
	DataOffset         int32
	//TODO: Add the rest of the header bits
}

type HeaderMessage struct {
	FromAddress string
	// TODO: Add all the TCP header
}

type Message struct {
	Header  HeaderMessage
	Payload []byte
}
