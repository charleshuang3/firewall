package pf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/charleshuang3/firewall"
)

var _ firewall.IFirewall = (*API)(nil)

const (
	blockListName = "block_list"
	defaultTTL    = 3 * time.Hour
)

type API struct {
	address string
	user    string
	pass    string
}

type ban struct {
	ip              string
	timeoutInMinute int
}

func New(address, user, pass string) *API {
	api := &API{
		address: address,
		user:    user,
		pass:    pass,
	}

	return api
}

type GetAliasResponse struct {
	Status  string   `json:"status"`
	Code    int      `json:"code"`
	Return  int      `json:"return"`
	Message string   `json:"message"`
	Data    []*Alias `json:"data"`
}

type Alias struct {
	Name       string `json:"name"`
	URL        string `json:"url,omitempty"`
	Updatefreq string `json:"updatefreq,omitempty"`
	Address    string `json:"address"`
	Descr      string `json:"descr"`
	Type       string `json:"type"`
	Detail     string `json:"detail"`
}

type UpdateAliasRequest struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Descr   string   `json:"descr"`
	Address []string `json:"address"`
	Detail  []string `json:"detail"`
}

func (s *API) request(b *ban) {
	// read current block list first
	alias, err := s.readAlias()
	if err != nil {
		log.Println(err)
		return
	}

	// remove expired and add new block
	r := newUpdateRequest(alias)
	r.Address = append(r.Address, b.ip)
	r.Detail = append(r.Detail, strconv.FormatInt(time.Now().Add(time.Duration(b.timeoutInMinute)*time.Minute).Unix(), 10))

	if err = s.updateAlias(r); err != nil {
		log.Println(err)
	}
}

func (s *API) readAlias() (*Alias, error) {
	r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/api/v1/firewall/alias", s.address), nil)
	if err != nil {
		// it should not happen unless config invalid.
		return nil, fmt.Errorf("new request failed: %w", err)
	}
	r.Header.Add("Authorization", s.user+" "+s.pass)

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

	if o.Code != http.StatusOK {
		return nil, fmt.Errorf("get alias failed: code = %d, resp = %q", o.Code, string(b))
	}

	for _, a := range o.Data {
		if a.Name == blockListName {
			return a, nil
		}
	}

	return nil, fmt.Errorf("no 'block_list' alias in pfsense")
}

func newUpdateRequest(a *Alias) *UpdateAliasRequest {
	r := &UpdateAliasRequest{
		ID:    a.Name,
		Name:  a.Name,
		Descr: a.Descr,
		Type:  a.Type,
	}

	type banned struct {
		ip     string
		expiry int64
	}

	var curr []banned
	for _, ip := range strings.Split(a.Address, " ") {
		curr = append(curr, banned{ip: ip})
	}

	now := time.Now()
	expiries := strings.Split(a.Detail, "||")
	for i := 0; i < len(expiries); i++ {
		if i >= len(curr) {
			break
		}
		exp, err := strconv.ParseInt(expiries[i], 10, 64)
		if err != nil {
			exp = now.Add(defaultTTL).Unix()
		}
		curr[i].expiry = exp
	}

	for _, c := range curr {
		if c.expiry == 0 {
			c.expiry = now.Add(defaultTTL).Unix()
		}
	}

	// remove expiried banned ip
	nowTs := now.Unix()
	for _, c := range curr {
		if c.expiry <= nowTs {
			continue
		}
		r.Address = append(r.Address, c.ip)
		r.Detail = append(r.Detail, strconv.FormatInt(c.expiry, 10))
	}

	return r
}

func (s *API) updateAlias(o *UpdateAliasRequest) error {
	b, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("json.Marshal failed: %w", err)
	}

	r, err := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/api/v1/firewall/alias", s.address), bytes.NewReader(b))
	if err != nil {
		// it should not happen unless config invalid.
		return fmt.Errorf("new request failed: %w", err)
	}

	r.Header.Add("Authorization", s.user+" "+s.pass)

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("update alias failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("update get alias response failed: %w", err)
		}
		return fmt.Errorf("update alias failed: code = %d, resp = %q", resp.StatusCode, string(b))
	}

	return nil
}

func (s *API) BanIP(ip string, timeoutInMinute int) {
	s.request(&ban{ip: ip, timeoutInMinute: timeoutInMinute})
}
