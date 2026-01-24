package tendrils

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"regexp"
	"time"
)

var acnUACNRegex = regexp.MustCompile(`\(acn-uacn=([^)]+)\)`)

const (
	shureMulticastAddr = "239.255.254.253:8427"
)

func (t *Tendrils) listenShure(ctx context.Context, iface net.Interface) {
	addr, err := net.ResolveUDPAddr("udp4", shureMulticastAddr)
	if err != nil {
		log.Printf("[ERROR] failed to resolve shure address: %v", err)
		return
	}

	conn, err := net.ListenMulticastUDP("udp4", &iface, addr)
	if err != nil {
		if t.DebugShure {
			log.Printf("[shure] %s: failed to listen: %v", iface.Name, err)
		}
		return
	}
	defer conn.Close()

	go t.sendShureDiscovery(ctx, iface.Name, conn)

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		t.handleShurePacket(iface.Name, src.IP, buf[:n])
	}
}

func (t *Tendrils) sendShureDiscovery(ctx context.Context, ifaceName string, conn *net.UDPConn) {
	dest := &net.UDPAddr{IP: net.IPv4(239, 255, 254, 253), Port: 8427}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	t.sendShureQuery(ifaceName, conn, dest)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sendShureQuery(ifaceName, conn, dest)
		}
	}
}

func (t *Tendrils) sendShureQuery(ifaceName string, conn *net.UDPConn, dest *net.UDPAddr) {
	// SLP Service Type Request (SrvTypeRqst)
	// This asks "what service types are available?"
	langTag := []byte("en")

	// Build SLP v2 header + SrvTypeRqst body
	// Header: version(1) + function(1) + length(3) + flags(2) + next-ext(3) + xid(2) + lang-len(2) + lang
	// SrvTypeRqst body: PR list len(2) + PR list + naming auth len(2) + naming auth + scope list len(2) + scope list

	headerLen := 14 + len(langTag)
	bodyLen := 2 + 0 + 2 + 0 + 2 + 7 // empty PR list, empty naming auth, "default" scope
	totalLen := headerLen + bodyLen

	pkt := make([]byte, totalLen)
	pkt[0] = 0x02                 // SLP version 2
	pkt[1] = 0x09                 // Function: SrvTypeRqst (9)
	pkt[2] = byte(totalLen >> 16) // Length (3 bytes)
	pkt[3] = byte(totalLen >> 8)
	pkt[4] = byte(totalLen)
	pkt[5] = 0x00 // Flags (2 bytes) - multicast
	pkt[6] = 0x20
	pkt[7] = 0x00 // Next ext offset (3 bytes)
	pkt[8] = 0x00
	pkt[9] = 0x00
	binary.BigEndian.PutUint16(pkt[10:12], 0x0001) // XID
	binary.BigEndian.PutUint16(pkt[12:14], uint16(len(langTag)))
	copy(pkt[14:], langTag)

	offset := 14 + len(langTag)
	binary.BigEndian.PutUint16(pkt[offset:], 0) // PR list length (0)
	offset += 2
	binary.BigEndian.PutUint16(pkt[offset:], 0) // Naming authority length (0 = IANA)
	offset += 2
	binary.BigEndian.PutUint16(pkt[offset:], 7) // Scope list length
	offset += 2
	copy(pkt[offset:], "default")

	conn.WriteToUDP(pkt, dest)

	if t.DebugShure {
		log.Printf("[shure] %s: sent slp discovery query", ifaceName)
	}
}

func (t *Tendrils) handleShurePacket(ifaceName string, srcIP net.IP, data []byte) {
	if t.DebugShure {
		log.Printf("[shure] %s: packet from %s (%d bytes): %q", ifaceName, srcIP, len(data), data)
	}

	match := acnUACNRegex.FindSubmatch(data)
	if match == nil {
		return
	}

	name := string(match[1])
	if t.DebugShure {
		log.Printf("[shure] %s: found device %s at %s", ifaceName, name, srcIP)
	}

	t.nodes.Update(nil, nil, []net.IP{srcIP}, "", name, "shure")
}
