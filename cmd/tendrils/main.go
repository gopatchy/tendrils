package main

import (
	"flag"

	"github.com/gopatchy/tendrils"
)

func main() {
	iface := flag.String("i", "", "interface to use (default: all interfaces)")
	flag.Parse()

	t := tendrils.New(*iface)
	t.Run()
}
