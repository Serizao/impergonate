package communication


import(
	"github.com/Microsoft/go-winio"
	"log"
	"io"
	"time"
	"net"
	"os"
)


func Listen() {
	c := winio.PipeConfig{
	  SecurityDescriptor: "S:(ML;;NW;;;LW)D:(A;;0x12019f;;;WD)",
	  MessageMode:      false,  // Use message mode so that CloseWrite() is supported
	  InputBufferSize:  65536, // Use 64KB buffers to improve performance
	  OutputBufferSize: 65536,
	}
  	ln, err := winio.ListenPipe(`\\.\pipe\impersonate_communicate`,&c)
	if err != nil {
		return
	}
	for {
		conn, err := ln.Accept()
		if nil != err {
			log.Fatalf("Could not accept connection: %v", err)
		}
		log.Println("Accepted connection from", conn)

		go io.Copy(conn, os.Stdin)
		go io.Copy(os.Stdout, conn)
	}
}



func Connect()(net.Conn,error){
	var d = time.Duration(10 * time.Millisecond)
	conn, err := winio.DialPipe(`\\.\pipe\impersonate_communicate`, &d)
	if err != nil {
		return nil,err
	}
	return conn,nil
}