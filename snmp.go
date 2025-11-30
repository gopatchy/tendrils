package tendrils

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

var (
	addToParentRules = []*regexp.Regexp{
		regexp.MustCompile(`CPU Interface`),
	}

	portNameRewrites = []struct {
		regex       *regexp.Regexp
		replacement string
	}{
		{regexp.MustCompile(`Slot: (\d+) Port: (\d+) .+`), "$1/$2"},
	}
)

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
		for _, ip := range node.IPs {
			if ip.To4() == nil {
				continue
			}

			go t.querySNMPDevice(ip)
		}
	}
}

func (t *Tendrils) querySNMPDevice(ip net.IP) {
	snmp, err := t.connectSNMP(ip)
	if err != nil {
		return
	}
	defer snmp.Conn.Close()

	t.queryBridgeMIB(snmp, ip)
	t.queryARPTable(snmp, ip)
}

func (t *Tendrils) queryBridgeMIB(snmp *gosnmp.GoSNMP, deviceIP net.IP) {
	macOID := "1.3.6.1.2.1.17.4.3.1.1"
	portOID := "1.3.6.1.2.1.17.4.3.1.2"

	macResults, err := snmp.BulkWalkAll(macOID)
	if err != nil {
		return
	}

	if len(macResults) == 0 {
		macOID = "1.3.6.1.2.1.17.7.1.2.2.1.1"
		portOID = "1.3.6.1.2.1.17.7.1.2.2.1.2"
		macResults, err = snmp.BulkWalkAll(macOID)
		if err != nil {
			return
		}
	}

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
		bridgePort := entry.bridgePort

		if isBroadcastOrZero(mac) {
			continue
		}

		ifIndex, exists := bridgePortToIfIndex[bridgePort]
		if !exists {
			ifIndex = bridgePort
		}

		ifName := ifNames[ifIndex]
		if ifName == "" {
			ifName = "??"
		}

		addToParent := false
		for _, rule := range addToParentRules {
			if rule.MatchString(ifName) {
				addToParent = true
				break
			}
		}

		for _, rewrite := range portNameRewrites {
			if rewrite.regex.MatchString(ifName) {
				ifName = rewrite.regex.ReplaceAllString(ifName, rewrite.replacement)
				break
			}
		}

		if addToParent {
			t.nodes.Update([]net.IP{deviceIP}, []net.HardwareAddr{mac}, "", "", "snmp")
		} else {
			t.nodes.UpdateWithParent(deviceIP, nil, []net.HardwareAddr{mac}, ifName, "", "snmp")
		}
	}
}

func (t *Tendrils) queryARPTable(snmp *gosnmp.GoSNMP, deviceIP net.IP) {
	macOID := "1.3.6.1.2.1.4.22.1.2"
	ipOID := "1.3.6.1.2.1.4.22.1.3"
	ifIndexOID := "1.3.6.1.2.1.4.22.1.1"

	macResults, err := snmp.BulkWalkAll(macOID)
	if err != nil {
		return
	}

	ipResults, err := snmp.BulkWalkAll(ipOID)
	if err != nil {
		return
	}

	ifIndexResults, err := snmp.BulkWalkAll(ifIndexOID)
	if err != nil {
		return
	}

	ipMap := make(map[string]net.IP)
	for _, result := range ipResults {
		if result.Type == gosnmp.IPAddress {
			oidSuffix := result.Name[len(ipOID)+1:]
			ipBytes := result.Value.([]byte)
			ipMap[oidSuffix] = net.IP(ipBytes)
		}
	}

	ifIndexMap := make(map[string]int)
	for _, result := range ifIndexResults {
		if result.Type == gosnmp.Integer {
			oidSuffix := result.Name[len(ifIndexOID)+1:]
			ifIndexMap[oidSuffix] = result.Value.(int)
		}
	}

	ifNames := t.getInterfaceNames(snmp)

	for _, result := range macResults {
		if result.Type == gosnmp.OctetString {
			macBytes := result.Value.([]byte)
			if len(macBytes) != 6 {
				continue
			}

			mac := net.HardwareAddr(macBytes)
			if isBroadcastOrZero(mac) {
				continue
			}

			oidSuffix := result.Name[len(macOID)+1:]
			ip, hasIP := ipMap[oidSuffix]
			ifIndex, hasIfIndex := ifIndexMap[oidSuffix]

			var ips []net.IP
			if hasIP {
				ips = []net.IP{ip}
			}

			ifName := ""
			if hasIfIndex {
				ifName = ifNames[ifIndex]
			}
			if ifName == "" {
				ifName = "??"
			}

			t.nodes.UpdateWithParent(deviceIP, ips, []net.HardwareAddr{mac}, ifName, "", "snmp")
		}
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
