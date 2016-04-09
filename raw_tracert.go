package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"syscall"
)

const icmpID uint16 = 43565 // use a magic number for now

type ICMP struct {
	Type       uint8
	Code       uint8
	Checksum   uint16
	Identifier uint16
	SeqNo      uint16
}

func Checksum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)

	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}

	if length > 0 {
		sum += uint32(data[index])
	}

	sum += (sum >> 16)

	return uint16(^sum)
}

func main() {
	h := Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + 8,
		TTL:      1,
		Protocol: 1,
	}

	argc := len(os.Args)
	if argc < 2 {
		log.Println("usage: program + host")
		return
	}

	ipAddr, _ := net.ResolveIPAddr("ip", os.Args[1])
	h.Dst = ipAddr.IP

	icmpReq := ICMP{
		Type:       8,
		Code:       0,
		Identifier: icmpID,
		SeqNo:      1,
	}

	out, err := h.Marshal()
	if err != nil {
		log.Println("ip header error", err)
		return
	}

	var icmpBuf bytes.Buffer
	binary.Write(&icmpBuf, binary.BigEndian, icmpReq)
	icmpReq.Checksum = Checksum(icmpBuf.Bytes())

	icmpBuf.Reset()
	binary.Write(&icmpBuf, binary.BigEndian, icmpReq)

	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	addr := syscall.SockaddrInet4{
		Port: 0,
	}

	copy(addr.Addr[:], ipAddr.IP[12:16])
	pkg := append(out, icmpBuf.Bytes()...)

	if err := syscall.Sendto(fd, pkg, 0, &addr); err != nil {
		log.Println("Sendto err:", err)
	}

	laddr, err := net.ResolveIPAddr("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)

	}

	c, err := net.ListenIP("ip4:icmp", laddr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		buf := make([]byte, 2048)
		n, raddr, err := c.ReadFrom(buf)
		if err != nil {
			log.Println(err)
			continue
		}
		icmpType := buf[0]
		if icmpType == 11 {
			if n == 36 { // Time exceeded messages
				// A time exceeded message contain IP header(20 bytes) and first 64 bits of the original payload
				id := binary.BigEndian.Uint16(buf[32:34])
				log.Println("recv id", id)
				if id == icmpID {
					log.Println("recv Time Exceeded from", raddr)
				}
			}
		}
	}

}
