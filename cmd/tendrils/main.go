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
	noIGMP := flag.Bool("no-igmp", false, "disable IGMP querier")
	noMDNS := flag.Bool("no-mdns", false, "disable mDNS discovery")
	noArtNet := flag.Bool("no-artnet", false, "disable Art-Net discovery")
	noDante := flag.Bool("no-dante", false, "disable Dante discovery")
	noBMD := flag.Bool("no-bmd", false, "disable Blackmagic discovery")
	logEvents := flag.Bool("log-events", false, "log node events")
	logNodes := flag.Bool("log-nodes", false, "log full node details on changes")
	debugARP := flag.Bool("debug-arp", false, "debug ARP discovery")
	debugLLDP := flag.Bool("debug-lldp", false, "debug LLDP discovery")
	debugSNMP := flag.Bool("debug-snmp", false, "debug SNMP discovery")
	debugIGMP := flag.Bool("debug-igmp", false, "debug IGMP querier")
	debugMDNS := flag.Bool("debug-mdns", false, "debug mDNS discovery")
	debugArtNet := flag.Bool("debug-artnet", false, "debug Art-Net discovery")
	debugDante := flag.Bool("debug-dante", false, "debug Dante discovery")
	debugBMD := flag.Bool("debug-bmd", false, "debug Blackmagic discovery")
	flag.Parse()

	t := tendrils.New()
	t.Interface = *iface
	t.DisableARP = *noARP
	t.DisableLLDP = *noLLDP
	t.DisableSNMP = *noSNMP
	t.DisableIGMP = *noIGMP
	t.DisableMDNS = *noMDNS
	t.DisableArtNet = *noArtNet
	t.DisableDante = *noDante
	t.DisableBMD = *noBMD
	t.LogEvents = *logEvents
	t.LogNodes = *logNodes
	t.DebugARP = *debugARP
	t.DebugLLDP = *debugLLDP
	t.DebugSNMP = *debugSNMP
	t.DebugIGMP = *debugIGMP
	t.DebugMDNS = *debugMDNS
	t.DebugArtNet = *debugArtNet
	t.DebugDante = *debugDante
	t.DebugBMD = *debugBMD
	t.Run()
}
