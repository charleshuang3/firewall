package ros

import (
	"fmt"
	"log"

	"github.com/go-routeros/routeros/v3"

	"github.com/charleshuang3/firewall"
)

var _ firewall.IFirewall = (*API)(nil)

type API struct {
	address string
	user    string
	pass    string
}

func New(address, user, pass string) *API {
	return &API{
		address: address,
		user:    user,
		pass:    pass,
	}
}

func (s *API) client() (*routeros.Client, error) {
	return routeros.Dial(s.address, s.user, s.pass)
}

func (s *API) BanIP(ip string, timeoutInMinute int) {
	c, err := s.client()
	if err != nil {
		log.Printf("routeros.Dial failed: %v", err)
		return
	}
	defer c.Close()

	reply, err := c.Run("/ip/firewall/address-list/add", "=list=black-list", "=address="+ip, fmt.Sprintf("=timeout=%dm", timeoutInMinute))
	if err != nil {
		log.Println(reply)
	}
}
