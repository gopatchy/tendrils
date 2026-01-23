package tendrils

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"strings"
	"time"
)

func (t *Tendrils) listenBMD(ctx context.Context, iface net.Interface) {
	addrs, err := iface.Addrs()
	if err != nil {
		return
	}

	var srcIP net.IP
	var broadcast net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			srcIP = ipnet.IP.To4()
			mask := ipnet.Mask
			broadcast = make(net.IP, 4)
			for i := 0; i < 4; i++ {
				broadcast[i] = srcIP[i] | ^mask[i]
			}
			break
		}
	}
	if srcIP == nil {
		return
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: srcIP, Port: 0})
	if err != nil {
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	go t.atemDiscoveryLoop(ctx, conn, broadcast, iface.Name)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			go t.atemDiscoveryLoop(ctx, conn, broadcast, iface.Name)
		}
	}
}

func (t *Tendrils) atemDiscoveryLoop(ctx context.Context, conn *net.UDPConn, broadcast net.IP, ifaceName string) {
	// Send hello to broadcast
	hello := []byte{
		0x10, 0x14,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	conn.WriteToUDP(hello, &net.UDPAddr{IP: broadcast, Port: 9910})

	if t.DebugBMD {
		log.Printf("[bmd] %s: sent atem discovery to %s", ifaceName, broadcast)
	}

	// Collect responses and initiate sessions
	sessions := map[string]*atemSession{}
	buf := make([]byte, 2048)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		if n < 12 {
			continue
		}

		ipKey := src.IP.String()
		sess := sessions[ipKey]
		if sess == nil {
			sess = &atemSession{ip: src.IP}
			sessions[ipKey] = sess
		}

		t.handleATEMPacket(conn, src, buf[:n], sess, ifaceName)

		if sess.productName != "" && !sess.updated {
			sess.updated = true
			if t.DebugBMD {
				log.Printf("[bmd] %s: atem %s at %s", ifaceName, sess.productName, src.IP)
			}
			t.nodes.Update(nil, nil, []net.IP{src.IP}, "", sess.productName, "bmd")
		}
	}

	// Update any ATEMs we found but couldn't get name for
	for _, sess := range sessions {
		if !sess.updated {
			if t.DebugBMD {
				log.Printf("[bmd] %s: atem (unknown) at %s", ifaceName, sess.ip)
			}
			t.nodes.Update(nil, nil, []net.IP{sess.ip}, "", "atem", "bmd")
		}
	}
}

type atemSession struct {
	ip          net.IP
	sessionID   uint16
	remoteSeq   uint16
	productName string
	updated     bool
}

func (t *Tendrils) handleATEMPacket(conn *net.UDPConn, src *net.UDPAddr, data []byte, sess *atemSession, ifaceName string) {
	flags := data[0] >> 3
	length := int(binary.BigEndian.Uint16(data[0:2]) & 0x07FF)

	if length > len(data) {
		return
	}

	sessionID := binary.BigEndian.Uint16(data[2:4])
	remoteSeq := binary.BigEndian.Uint16(data[10:12])

	// Hello response - extract session ID
	if flags&0x02 != 0 {
		sess.sessionID = sessionID
		// Send ACK
		ack := make([]byte, 12)
		ack[0] = 0x80
		ack[1] = 0x0c
		binary.BigEndian.PutUint16(ack[2:4], sessionID)
		binary.BigEndian.PutUint16(ack[4:6], remoteSeq)
		conn.WriteToUDP(ack, src)
	}

	// ACK request - send ACK
	if flags&0x01 != 0 {
		sess.remoteSeq = remoteSeq
		ack := make([]byte, 12)
		ack[0] = 0x80
		ack[1] = 0x0c
		binary.BigEndian.PutUint16(ack[2:4], sessionID)
		binary.BigEndian.PutUint16(ack[4:6], remoteSeq)
		conn.WriteToUDP(ack, src)
	}

	// Parse commands in payload
	if length > 12 {
		t.parseATEMCommands(data[12:length], sess)
	}
}

func (t *Tendrils) parseATEMCommands(data []byte, sess *atemSession) {
	offset := 0
	for offset+8 <= len(data) {
		cmdLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		if cmdLen < 8 || offset+cmdLen > len(data) {
			break
		}

		cmdName := string(data[offset+4 : offset+8])

		if cmdName == "_pin" && cmdLen > 8 {
			// Product Information Name
			nameData := data[offset+8 : offset+cmdLen]
			nullIdx := 0
			for i, b := range nameData {
				if b == 0 {
					nullIdx = i
					break
				}
			}
			if nullIdx > 0 {
				sess.productName = strings.TrimSpace(string(nameData[:nullIdx]))
			}
		}

		offset += cmdLen
	}
}
