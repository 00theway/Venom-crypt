package myConn

import (
	"bytes"
	"encoding/binary"
	"net"
)

const (
	MsgLenFieldSize = 4
)

type secureConn struct {
	net.Conn
	crypt    AesCrypt
	overhead int
	input    bytes.Reader
}


func (p * secureConn) ReciveMsgbuf() (int,error){
	var msgSize uint32
	var decrypted []byte
	var msgSizeBuf []byte
	var msgBuf []byte

	msgSizeBuf = make([]byte, p.overhead)
	_, err := p.Conn.Read(msgSizeBuf)
	if err != nil {
		return 0, err
	}
	msgSize = binary.LittleEndian.Uint32(msgSizeBuf)

	msgBuf = make([]byte, msgSize)
	_, err = p.Conn.Read(msgBuf)
	if err != nil {
		return 0, err
	}

	if msgSize != 0 {
		decrypted, err = p.crypt.Decrypt(decrypted, msgBuf)
		if err != nil {
			return 0, err
		}
	}
	p.input.Reset(decrypted)
	return 0, nil
}

func (p *secureConn) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	for p.input.Len() == 0 {
		_,err := p.ReciveMsgbuf()
		if err != nil {
			return 0, err
		}
	}

	n, _ := p.input.Read(buf)
	return n, nil
}

func (p *secureConn) Write(rawBuf []byte) (int, error) {
	var buf []byte

	buf, err := p.crypt.Encrypt(buf, rawBuf)
	if err != nil {
		return 0, err
	}
	msg := make([]byte, len(buf)+p.overhead)

	copy(msg[4:], buf)
	msgSize := uint32(len(msg) - p.overhead)
	binary.LittleEndian.PutUint32(msg, msgSize)
	_, err = p.Conn.Write(msg)
	if err != nil {
		return 0, err
	}
	return len(rawBuf), nil
}

func NewSecureConn(c net.Conn) (net.Conn, error) {
	crypt := &AesCrypt{}
	overhead := MsgLenFieldSize
	helloConn := &secureConn{
		Conn:     c,
		crypt:    *crypt,
		overhead: overhead,
	}

	return helloConn, nil
}
//
//func main() {
//	if os.Args[1] == "client"{
//		Client()
//	}else{
//		Server()
//	}
//
//}
//
//func Read(input io.Reader, buffer []byte) (int, error) {
//	n, err := io.ReadFull(input, buffer)
//	if err != nil {
//		fmt.Println("[-]Read Error: ", err)
//	}
//	return n, err
//}
//
//func Client(){
//	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:1234")
//	checkError(err)
//	conn_nocrypt, err := net.DialTCP("tcp", nil, tcpAddr)
//	conn, err := NewSecureConn(conn_nocrypt)
//	checkError(err)
//
//
//	var one [1]byte
//	i := 1
//	for{
//		_, err = Read(conn, one[0:])
//		if err != nil {
//			fmt.Println(err)
//		}
//
//		fmt.Println("read 1 byte")
//		fmt.Println(string(one[0]))
//		i += 1
//		if i >= 10{
//			break
//		}
//	}
//
//
//
//	_, err = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
//	checkError(err)
//	conn.Close()
//
//	os.Exit(0)
//}
//
//func Server(){
//	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:1234")
//	checkError(err)
//	listener, err := net.ListenTCP("tcp", tcpAddr)
//	checkError(err)
//	for {
//		conn_nocrypt, err := listener.Accept()
//		conn,err := NewSecureConn(conn_nocrypt)
//		if err != nil {
//			continue
//		}
//		daytime := "qwertyuioplkjhgfdsazxcvb"
//
//		conn.Write([]byte(daytime)) // don't care about return value
//		//result, err := ioutil.ReadAll(conn)
//		//checkError(err)
//		//fmt.Println(string(result))
//		conn.Close()                // we're finished with this client
//	}
//}
//
//func checkError(err error) {
//	if err != nil {
//		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
//		os.Exit(1)
//	}
//}
