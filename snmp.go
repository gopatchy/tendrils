package tendrils

import (
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

func (t *Tendrils) pollNode(node *Node) {
	t.nodes.mu.RLock()
	var ips []net.IP
	for _, iface := range node.Interfaces {
		for _, ip := range iface.IPs {
			if ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
	}
	nodeName := node.Name
	t.nodes.mu.RUnlock()

	if !t.DisableSNMP {
		for _, ip := range ips {
			t.querySNMPDevice(node, ip)
		}
	}

	if !t.DisableBMD && nodeName == "" {
		for _, ip := range ips {
			t.probeBMDDevice(ip)
		}
	}
}

func (t *Tendrils) querySNMPDevice(node *Node, ip net.IP) {
	snmp, err := t.connectSNMP(ip)
	if err != nil {
		if t.DebugSNMP {
			log.Printf("[snmp] %s: connect failed: %v", ip, err)
		}
		return
	}
	defer snmp.Conn.Close()

	t.querySysName(snmp, node)
	t.queryInterfaceMACs(snmp, node)
	t.queryInterfaceStats(snmp, node)
	t.queryPoEBudget(snmp, node)
	t.queryBridgeMIB(snmp, node)
}

func (t *Tendrils) querySysName(snmp *gosnmp.GoSNMP, node *Node) {
	oid := "1.3.6.1.2.1.1.5.0"

	result, err := snmp.Get([]string{oid})
	if err != nil {
		return
	}

	if len(result.Variables) == 0 {
		return
	}

	variable := result.Variables[0]
	if variable.Type != gosnmp.OctetString {
		return
	}

	sysName := string(variable.Value.([]byte))
	if sysName == "" {
		return
	}

	t.nodes.Update(node, nil, nil, "", sysName, "snmp-sysname")
}

func (t *Tendrils) queryInterfaceMACs(snmp *gosnmp.GoSNMP, node *Node) {
	oid := "1.3.6.1.2.1.2.2.1.6"

	results, err := snmp.BulkWalkAll(oid)
	if err != nil {
		return
	}

	ifNames := t.getInterfaceNames(snmp)

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
			log.Printf("[snmp] %s: interface %d mac=%s name=%s", snmp.Target, ifIndex, mac, name)
		}

		t.nodes.Update(node, mac, nil, name, "", "snmp-ifmac")
	}
}

func (t *Tendrils) queryInterfaceStats(snmp *gosnmp.GoSNMP, node *Node) {
	ifNames := t.getInterfaceNames(snmp)

	ifOperStatus := t.getInterfaceTable(snmp, "1.3.6.1.2.1.2.2.1.8")
	ifHighSpeed := t.getInterfaceTable(snmp, "1.3.6.1.2.1.31.1.1.1.15")
	ifInErrors := t.getInterfaceTable(snmp, "1.3.6.1.2.1.2.2.1.14")
	ifOutErrors := t.getInterfaceTable(snmp, "1.3.6.1.2.1.2.2.1.20")

	poeStats := t.getPoEStats(snmp, ifNames)

	t.nodes.mu.Lock()
	defer t.nodes.mu.Unlock()

	for ifIndex, name := range ifNames {
		name = rewritePortName(name)
		iface, exists := node.Interfaces[name]
		if !exists {
			continue
		}

		status, hasStatus := ifOperStatus[ifIndex]
		isUp := hasStatus && status == 1
		if !isUp {
			iface.Stats = nil
			continue
		}

		stats := &InterfaceStats{}

		if speed, ok := ifHighSpeed[ifIndex]; ok {
			stats.Speed = uint64(speed) * 1000000
		}

		if inErr, ok := ifInErrors[ifIndex]; ok {
			stats.InErrors = uint64(inErr)
		}

		if outErr, ok := ifOutErrors[ifIndex]; ok {
			stats.OutErrors = uint64(outErr)
		}

		if poe, ok := poeStats[name]; ok {
			stats.PoE = poe
		}

		iface.Stats = stats
	}
}

func (t *Tendrils) queryPoEBudget(snmp *gosnmp.GoSNMP, node *Node) {
	maxPowerOID := "1.3.6.1.2.1.105.1.3.1.1.2.1"
	powerOID := "1.3.6.1.2.1.105.1.3.1.1.4.1"

	result, err := snmp.Get([]string{maxPowerOID, powerOID})
	if err != nil {
		return
	}

	var power, maxPower float64
	for _, v := range result.Variables {
		var val int
		switch x := v.Value.(type) {
		case int:
			val = x
		case uint:
			val = int(x)
		case int64:
			val = int(x)
		case uint64:
			val = int(x)
		default:
			continue
		}

		if v.Name == "."+powerOID {
			power = float64(val)
		} else if v.Name == "."+maxPowerOID {
			maxPower = float64(val)
		}
	}

	if maxPower > 0 {
		t.nodes.mu.Lock()
		node.PoEBudget = &PoEBudget{Power: power, MaxPower: maxPower}
		t.nodes.mu.Unlock()
	}
}

func (t *Tendrils) getInterfaceTable(snmp *gosnmp.GoSNMP, oid string) map[int]int {
	results, err := snmp.BulkWalkAll(oid)
	if err != nil {
		return nil
	}

	table := map[int]int{}
	for _, result := range results {
		oidSuffix := strings.TrimPrefix(strings.TrimPrefix(result.Name, "."+oid), ".")
		var ifIndex int
		if _, err := fmt.Sscanf(oidSuffix, "%d", &ifIndex); err != nil {
			continue
		}

		var value int
		switch v := result.Value.(type) {
		case int:
			value = v
		case uint:
			value = int(v)
		case int64:
			value = int(v)
		case uint64:
			value = int(v)
		default:
			continue
		}

		table[ifIndex] = value
	}
	return table
}

func (t *Tendrils) getPoEStats(snmp *gosnmp.GoSNMP, ifNames map[int]string) map[string]*PoEStats {
	statusOID := "1.3.6.1.2.1.105.1.1.1.6"

	statusResults, err := snmp.BulkWalkAll(statusOID)
	if err != nil {
		return nil
	}

	powerTable := t.getPoETable(snmp, "1.3.6.1.4.1.4526.10.15.1.1.1.2")
	maxPowerTable := t.getPoETable(snmp, "1.3.6.1.4.1.4526.10.15.1.1.1.1")

	stats := map[string]*PoEStats{}
	for _, result := range statusResults {
		oidSuffix := strings.TrimPrefix(strings.TrimPrefix(result.Name, "."+statusOID), ".")
		parts := strings.Split(oidSuffix, ".")
		if len(parts) < 2 {
			continue
		}

		var portIndex int
		if _, err := fmt.Sscanf(parts[1], "%d", &portIndex); err != nil {
			continue
		}

		var status int
		switch v := result.Value.(type) {
		case int:
			status = v
		case uint:
			status = int(v)
		case int64:
			status = int(v)
		case uint64:
			status = int(v)
		default:
			continue
		}

		ifName := rewritePortName(ifNames[portIndex])
		if ifName == "" {
			continue
		}

		if status != 3 {
			continue
		}

		poe := &PoEStats{}
		if power, ok := powerTable[portIndex]; ok {
			poe.Power = float64(power) / 1000.0
		}
		if maxPower, ok := maxPowerTable[portIndex]; ok {
			poe.MaxPower = float64(maxPower) / 1000.0
		}

		if t.DebugSNMP {
			log.Printf("[snmp] %s: poe port %d (%s) power=%v maxpower=%v", snmp.Target, portIndex, ifName, powerTable[portIndex], maxPowerTable[portIndex])
		}

		if poe.Power > 0 || poe.MaxPower > 0 {
			stats[ifName] = poe
		}
	}
	return stats
}

func (t *Tendrils) getPoETable(snmp *gosnmp.GoSNMP, oid string) map[int]int {
	results, err := snmp.BulkWalkAll(oid)
	if err != nil {
		return nil
	}

	table := map[int]int{}
	for _, result := range results {
		oidSuffix := strings.TrimPrefix(strings.TrimPrefix(result.Name, "."+oid), ".")
		parts := strings.Split(oidSuffix, ".")
		if len(parts) < 2 {
			continue
		}

		var portIndex int
		if _, err := fmt.Sscanf(parts[1], "%d", &portIndex); err != nil {
			continue
		}

		var value int
		switch v := result.Value.(type) {
		case int:
			value = v
		case uint:
			value = int(v)
		case int64:
			value = int(v)
		case uint64:
			value = int(v)
		default:
			continue
		}

		table[portIndex] = value
	}
	return table
}

func (t *Tendrils) queryBridgeMIB(snmp *gosnmp.GoSNMP, node *Node) {
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

		ifIndex, exists := bridgePortToIfIndex[entry.bridgePort]
		if !exists {
			ifIndex = entry.bridgePort
		}
		ifName := rewritePortName(ifNames[ifIndex])

		if t.DebugSNMP {
			log.Printf("[snmp] %s: mac=%s port=%s", snmp.Target, mac, ifName)
		}

		t.nodes.Update(nil, mac, nil, "", "", "snmp")
		t.nodes.UpdateMACTable(node, mac, ifName)
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

