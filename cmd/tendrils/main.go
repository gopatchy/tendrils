package main

import (
	"flag"

	"github.com/gopatchy/tendrils"
)

func main() {
	iface := flag.String("i", "", "interface to use")
	noARP := flag.Bool("no-arp", false, "disable ARP discovery")
	noLLDP := flag.Bool("no-lldp", false, "disable LLDP discovery")
	noSNMP := flag.Bool("no-snmp", false, "disable SNMP discovery")
	logTree := flag.Bool("log-tree", false, "log full tree on changes")
	logReasons := flag.Bool("log-reasons", false, "log addition reasons")
	debugARP := flag.Bool("debug-arp", false, "debug ARP discovery")
	debugLLDP := flag.Bool("debug-lldp", false, "debug LLDP discovery")
	debugSNMP := flag.Bool("debug-snmp", false, "debug SNMP discovery")
	flag.Parse()

	t := tendrils.New()
	t.Interface = *iface
	t.DisableARP = *noARP
	t.DisableLLDP = *noLLDP
	t.DisableSNMP = *noSNMP
	t.LogTree = *logTree
	t.LogReasons = *logReasons
	t.DebugARP = *debugARP
	t.DebugLLDP = *debugLLDP
	t.DebugSNMP = *debugSNMP
	t.Run()
}
