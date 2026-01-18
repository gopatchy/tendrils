package tendrils

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

var portNameRewrites = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`.*Slot: (\d+) Port: (\d+).*`), "$1/$2"},
}

func rewritePortName(name string) string {
	for _, rw := range portNameRewrites {
		if rw.re.MatchString(name) {
			return rw.re.ReplaceAllString(name, rw.repl)
		}
	}
	return name
}

type snmpConfig struct {
	username  string
	authKey   string
	privKey   string
	authProto gosnmp.SnmpV3AuthProtocol
	privProto gosnmp.SnmpV3PrivProtocol
	secLevel  gosnmp.SnmpV3MsgFlags
	timeout   time.Duration
	retries   int
}

func defaultSNMPConfig() *snmpConfig {
	return &snmpConfig{
		username:  "tendrils",
		authKey:   "tendrils",
		privKey:   "tendrils",
		authProto: gosnmp.SHA512,
		privProto: gosnmp.AES,
		secLevel:  gosnmp.AuthPriv,
		timeout:   5 * time.Second,
		retries:   1,
	}
}

func (t *Tendrils) connectSNMP(ip net.IP) (*gosnmp.GoSNMP, error) {
	cfg := defaultSNMPConfig()

	snmp := &gosnmp.GoSNMP{
		Target:        ip.String(),
		Port:          161,
		Version:       gosnmp.Version3,
		Timeout:       cfg.timeout,
		Retries:       cfg.retries,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      cfg.secLevel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 cfg.username,
			AuthenticationProtocol:   cfg.authProto,
			AuthenticationPassphrase: cfg.authKey,
			PrivacyProtocol:          cfg.privProto,
			PrivacyPassphrase:        cfg.privKey,
		},
	}

	err := snmp.Connect()
	if err != nil {
		return nil, err
	}

	return snmp, nil
}

func (t *Tendrils) pollSNMP(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	t.querySwitches()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.querySwitches()
		}
	}
}

func (t *Tendrils) querySwitches() {
	nodes := t.nodes.All()

	for _, node := range nodes {
		for _, iface := range node.Interfaces {
			for _, ip := range iface.IPs {
				if ip.To4() == nil {
					continue
				}

				go t.querySNMPDevice(ip)
			}
		}
	}
}

func (t *Tendrils) querySNMPDevice(ip net.IP) {
	snmp, err := t.connectSNMP(ip)
	if err != nil {
		if t.DebugSNMP {
			log.Printf("[snmp] %s: connect failed: %v", ip, err)
		}
		return
	}
	defer snmp.Conn.Close()

	t.querySysName(snmp, ip)
	t.queryInterfaceMACs(snmp, ip)
	t.queryBridgeMIB(snmp, ip)
}

func (t *Tendrils) querySysName(snmp *gosnmp.GoSNMP, deviceIP net.IP) {
	oid := "1.3.6.1.2.1.1.5.0"

	result, err := snmp.Get([]string{oid})
	if err != nil {
		return
	}

	if len(result.Variables) > 0 {
		variable := result.Variables[0]
		if variable.Type == gosnmp.OctetString {
			sysName := string(variable.Value.([]byte))
			if sysName != "" {
				t.nodes.mu.RLock()
				if id, exists := t.nodes.ipIndex[deviceIP.String()]; exists {
					t.nodes.mu.RUnlock()
					t.nodes.mu.Lock()
					node := t.nodes.nodes[id]
					if node.Name == "" {
						node.Name = sysName
					}
					t.nodes.mu.Unlock()
					return
				}
				t.nodes.mu.RUnlock()
			}
		}
	}
}

func (t *Tendrils) queryInterfaceMACs(snmp *gosnmp.GoSNMP, deviceIP net.IP) {
	oid := "1.3.6.1.2.1.2.2.1.6"

	results, err := snmp.BulkWalkAll(oid)
	if err != nil {
		return
	}

	ifNames := t.getInterfaceNames(snmp)

	type ifaceEntry struct {
		mac  net.HardwareAddr
		name string
	}
	var ifaces []ifaceEntry

	for _, result := range results {
		if result.Type != gosnmp.OctetString {
			continue
		}

		macBytes := result.Value.([]byte)
		if len(macBytes) != 6 {
			continue
		}

		mac := net.HardwareAddr(macBytes)
		if isBroadcastOrZero(mac) {
			continue
		}

		oidSuffix := strings.TrimPrefix(strings.TrimPrefix(result.Name, "."+oid), ".")
		var ifIndex int
		if _, err := fmt.Sscanf(oidSuffix, "%d", &ifIndex); err != nil {
			continue
		}

		name := rewritePortName(ifNames[ifIndex])
		if t.DebugSNMP {
			log.Printf("[snmp] %s: interface %d mac=%s name=%s", deviceIP, ifIndex, mac, name)
		}

		ifaces = append(ifaces, ifaceEntry{mac: mac, name: name})
	}

	var macs []net.HardwareAddr
	for _, iface := range ifaces {
		t.nodes.Update(iface.mac, nil, iface.name, "", "snmp-ifmac")
		macs = append(macs, iface.mac)
	}
	if len(macs) > 1 {
		t.nodes.Merge(macs, "snmp-ifmac")
	}
}

func (t *Tendrils) queryBridgeMIB(snmp *gosnmp.GoSNMP, deviceIP net.IP) {
	portOID := "1.3.6.1.2.1.17.7.1.2.2.1.2"

	portResults, err := snmp.BulkWalkAll(portOID)
	if err != nil {
		return
	}

	type macPortEntry struct {
		mac        net.HardwareAddr
		bridgePort int
	}
	var macPorts []macPortEntry

	for _, result := range portResults {
		if result.Type == gosnmp.Integer {
			oidSuffix := strings.TrimPrefix(result.Name[len(portOID):], ".")
			parts := strings.Split(oidSuffix, ".")

			if len(parts) >= 8 {
				var macBytes []byte
				for j := 2; j <= 7; j++ {
					var b int
					fmt.Sscanf(parts[j], "%d", &b)
					macBytes = append(macBytes, byte(b))
				}

				if len(macBytes) == 6 {
					mac := net.HardwareAddr(macBytes)
					bridgePort := result.Value.(int)
					macPorts = append(macPorts, macPortEntry{mac: mac, bridgePort: bridgePort})
				}
			}
		}
	}

	bridgePortToIfIndex := t.getBridgePortMapping(snmp)
	ifNames := t.getInterfaceNames(snmp)

	for _, entry := range macPorts {
		mac := entry.mac

		if isBroadcastOrZero(mac) {
			continue
		}

		if t.DebugSNMP {
			ifIndex, exists := bridgePortToIfIndex[entry.bridgePort]
			if !exists {
				ifIndex = entry.bridgePort
			}
			ifName := ifNames[ifIndex]
			if ifName == "" {
				ifName = "??"
			}
			log.Printf("[snmp] %s: mac=%s port=%s", deviceIP, mac, ifName)
		}

		t.nodes.Update(mac, nil, "", "", "snmp")
	}
}

func (t *Tendrils) getBridgePortMapping(snmp *gosnmp.GoSNMP) map[int]int {
	oid := "1.3.6.1.2.1.17.1.4.1.2"

	results, err := snmp.BulkWalkAll(oid)
	if err != nil {
		return nil
	}

	mapping := make(map[int]int)
	for _, result := range results {
		if result.Type == gosnmp.Integer {
			oidParts := strings.TrimPrefix(strings.TrimPrefix(result.Name, "."+oid), ".")
			var bridgePort int
			_, err := fmt.Sscanf(oidParts, "%d", &bridgePort)
			if err != nil {
				continue
			}
			ifIndex := result.Value.(int)
			mapping[bridgePort] = ifIndex
		}
	}

	return mapping
}

func (t *Tendrils) getInterfaceNames(snmp *gosnmp.GoSNMP) map[int]string {
	oid := "1.3.6.1.2.1.2.2.1.2"

	results, err := snmp.BulkWalkAll(oid)
	if err != nil {
		return nil
	}

	names := make(map[int]string)
	for _, result := range results {
		if result.Type == gosnmp.OctetString {
			oidParts := strings.TrimPrefix(strings.TrimPrefix(result.Name, "."+oid), ".")
			var ifIndex int
			_, err := fmt.Sscanf(oidParts, "%d", &ifIndex)
			if err != nil {
				continue
			}
			name := string(result.Value.([]byte))
			names[ifIndex] = name
		}
	}

	return names
}
