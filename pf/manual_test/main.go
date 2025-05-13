package main

import (
	"flag"
	"time"

	"github.com/charleshuang3/firewall/pf"
)

var (
	host = flag.String("host", "", "")
	user = flag.String("user", "", "")
	pass = flag.String("pass", "", "")
)

func main() {
	flag.Parse()
	a := pf.New(*host, *user, *pass)
	a.BanIP("10.9.9.9", 3)

	time.Sleep(time.Second * 10)
}
