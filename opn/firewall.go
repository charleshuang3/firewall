package opn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/charleshuang3/firewall"
)

var _ firewall.IFirewall = (*API)(nil)

type API struct {
	address  string
	user     string
	pass     string
	listUUID string
}

type ban struct {
	ip              string
	timeoutInMinute int
}

func New(address, user, pass, listUUID string) *API {
	api := &API{
		address:  address,
		user:     user,
		pass:     pass,
		listUUID: listUUID,
	}

	return api
}

type Value struct {
	Value    string `json:"value"`
	Selected int    `json:"selected"`
}

type Alias struct {
	Enabled string `json:"enabled"`
	Name    string `json:"name"`
	Type    struct {
		Host         *Value `json:"host"`
		Network      *Value `json:"network"`
		Port         *Value `json:"port"`
		URL          *Value `json:"url"`
		Urltable     *Value `json:"urltable"`
		Geoip        *Value `json:"geoip"`
		Networkgroup *Value `json:"networkgroup"`
		Mac          *Value `json:"mac"`
		External     *Value `json:"external"`
	} `json:"type"`
	Proto struct {
		IPv4 *Value `json:"IPv4"`
		IPv6 *Value `json:"IPv6"`
	} `json:"proto"`
	Counters    string            `json:"counters"`
	Updatefreq  string            `json:"updatefreq"`
	Content     map[string]*Value `json:"content"`
	Description string            `json:"description"`
}

type IPsAndExpiries struct {
	Expiries map[string]int64 `json:"expiries"`
}

type GetAliasResponse struct {
	Alias *Alias `json:"alias"`
}

type UpdateAliasRequest struct {
	Alias struct {
		Enabled     string `json:"enabled"`
		Name        string `json:"name"`
		Type        string `json:"type"`
		Proto       string `json:"proto"`
		Updatefreq  string `json:"updatefreq"`
		Content     string `json:"content"`
		Counters    string `json:"counters"`
		Description string `json:"description"`
	} `json:"alias"`
	NetworkContent string `json:"network_content"`
}

func (s *API) request(b *ban) {
	// read current block list first
	bl, err := s.readBlockList()
	if err != nil {
		log.Println(err)
		return
	}

	// remove expired and add new block
	r, err := newUpdateRequest(bl, b)
	if err != nil {
		log.Println(err)
		return
	}

	if err = s.updateAlias(r); err != nil {
		log.Println(err)
	}
}

func (s *API) readBlockList() (*Alias, error) {
	r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/api/firewall/alias/getItem/%s", s.address, s.listUUID), nil)
	if err != nil {
		// it should not happen unless config invalid.
		return nil, fmt.Errorf("new request failed: %w", err)
	}
	r.SetBasicAuth(s.user, s.pass)

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("get alias failed: %w", err)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read get alias response failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get alias failed: code = %d, resp = %q", resp.StatusCode, string(b))
	}

	o := &GetAliasResponse{}
	err = json.Unmarshal(b, o)
	if err != nil {
		return nil, fmt.Errorf("unmarshal get alias response failed: %w", err)
	}

	return o.Alias, nil
}

func newUpdateRequest(a *Alias, b *ban) (*UpdateAliasRequest, error) {
	banned := &IPsAndExpiries{
		Expiries: map[string]int64{},
	}
	if len(a.Description) != 0 {
		if err := json.Unmarshal([]byte(a.Description), banned); err != nil {
			return nil, fmt.Errorf("unmarshal Description failed: %d", err)
		}
	}

	ips := []string{}

	// remove expiried ban
	now := time.Now()
	nowTs := now.Unix()
	for k, v := range banned.Expiries {
		if v > nowTs {
			ips = append(ips, k)
			continue
		}

		delete(banned.Expiries, k)
	}

	// add new ban
	exp := now.Add(time.Minute * time.Duration(b.timeoutInMinute))
	banned.Expiries[b.ip] = exp.Unix()
	ips = append(ips, b.ip)

	// write description
	d, err := json.Marshal(banned)
	if err != nil {
		return nil, err
	}

	res := &UpdateAliasRequest{}
	res.Alias.Enabled = "1"
	res.Alias.Name = a.Name
	res.Alias.Counters = a.Counters
	res.Alias.Proto = ""
	res.Alias.Updatefreq = a.Updatefreq
	res.Alias.Type = "host"

	res.Alias.Content = strings.Join(ips, "\n")
	res.Alias.Description = string(d)

	return res, nil
}

func (s *API) updateAlias(o *UpdateAliasRequest) error {
	b, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("json.Marshal failed: %w", err)
	}

	r, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/api/firewall/alias/setItem/%s", s.address, s.listUUID), bytes.NewReader(b))
	if err != nil {
		// it should not happen unless config invalid.
		return fmt.Errorf("new request failed: %w", err)
	}

	r.SetBasicAuth(s.user, s.pass)
	r.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("update alias failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("update alias response failed: %w", err)
		}
		return fmt.Errorf("update alias failed: code = %d, resp = %q", resp.StatusCode, string(b))
	}

	return nil
}

func (s *API) BanIP(ip string, timeoutInMinute int) {
	s.request(&ban{ip: ip, timeoutInMinute: timeoutInMinute})
}
