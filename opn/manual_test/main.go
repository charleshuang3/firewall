package main

import (
	"flag"

	"github.com/charleshuang3/firewall/opn"
)

var (
	host = flag.String("host", "10.0.0.1", "")
	user = flag.String("user", "", "")
	pass = flag.String("pass", "", "")
	list = flag.String("list", "", "")
)

func main() {
	flag.Parse()
	a := opn.New(*host, *user, *pass, *list)
	a.BanIP("10.9.9.9", 3)
}
