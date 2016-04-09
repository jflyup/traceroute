package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/internal/iana"
	"golang.org/x/net/ipv4"
	"net"
	"os"
	"time"
)

var pid uint16 = uint16(os.Getpid())

func sendEcho(host string, ttl int) error {
	conn, err := net.Dial("ip4:icmp", host)

	if err != nil {
		return errors.New("dial error")
	}

	p := ipv4.NewConn(conn)

	if err := p.SetTTL(ttl); err != nil {
		return errors.New("SetTTL error")
	}
	echo := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: int(pid), Seq: 1,
		}}

	if buf, err := echo.Marshal(nil); err == nil {
		if _, err := conn.Write(buf); err != nil {
			return errors.New("write error")
		}
	} else {
		return errors.New("Marshal error")
	}

	return nil
}

func main() {
	argc := len(os.Args)
	if argc < 2 {
		fmt.Println("usage: program + host")
		return
	}

	var ttl int = 1

	if err := sendEcho(os.Args[1], ttl); err != nil {
		fmt.Println("sendEcho error", err)
		return
	}

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Println("listen error", err)
	}
	rb := make([]byte, 1500)
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		fmt.Println("set dead line err:", err)
		return
	}

	for {
		if ttl > 20 {
			break
		}
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			fmt.Printf("%d **read err: %s\n", ttl, err)
			ttl++
			sendEcho(os.Args[1], ttl)
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			continue
		}
		reply, err := icmp.ParseMessage(iana.ProtocolICMP, rb[:n])
		if err != nil {
			fmt.Println("parse icmp err:", err)
			return
		}

		switch reply.Type {
		case ipv4.ICMPTypeEchoReply:
			if echoReply, ok := reply.Body.(*icmp.Echo); ok {
				if echoReply.ID == int(pid) { // don't understand why ID is declared as int
					fmt.Println("recv reply from ", peer)
					fmt.Println("traceroute completed")
					return
				}
			}
		case ipv4.ICMPTypeTimeExceeded:
			if timeExceed, ok := reply.Body.(*icmp.TimeExceeded); ok {
				// internet header(20 bytes) plus the first 64 bits of the original datagram's data
				//fmt.Println("recv id and pid", binary.BigEndian.Uint16(timeExceed.Data[22:24]), pid)
				if binary.BigEndian.Uint16(timeExceed.Data[24:26]) == pid {
					fmt.Printf("%d hop: %s\n", ttl, peer)
					ttl++
					sendEcho(os.Args[1], ttl)
				}
			}
		default:
			//fmt.Println("recv type from peer", reply.Type, peer)
		}
	}

}
