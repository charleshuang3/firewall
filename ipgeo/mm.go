package ipgeo

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
)

const (
	checkUpdateInterval = 1 * time.Hour
)

// AutoUpdateMMIPGeo checks if database should update on GetIPGeo(). It is not locked, don't use on mutli-threading.
type AutoUpdateMMIPGeo struct {
	cityDBFile        string
	updatedCityDBFile string
	asnDBFile         string
	updatedASNDBFile  string
	mm                *MMIPGeo
	lastCheck         time.Time
}

func NewAutoUpdateMMIPGeo(cityDBFile, updatedCityDBFile, asnDBFile, updatedASNDBFile string) (*AutoUpdateMMIPGeo, error) {
	mm, err := NewMMIPGeo(cityDBFile, asnDBFile)
	if err != nil {
		return nil, err
	}
	db := &AutoUpdateMMIPGeo{
		cityDBFile:        cityDBFile,
		updatedCityDBFile: updatedCityDBFile,
		asnDBFile:         asnDBFile,
		updatedASNDBFile:  updatedASNDBFile,
		mm:                mm,
		lastCheck:         time.Time{},
	}

	db.update()

	return db, nil
}

// isFileUpdated compares 2 file last modify date and size
func isFileUpdated(currentFile, latestFile string) (bool, os.FileInfo, error) {
	currentStat, err := os.Stat(currentFile)
	if err != nil {
		return false, nil, err
	}

	latestStat, err := os.Stat(latestFile)
	if err != nil {
		return false, nil, err
	}

	if currentStat.Size() != latestStat.Size() {
		return true, latestStat, nil
	}

	if !currentStat.ModTime().Equal(latestStat.ModTime()) {
		return true, latestStat, nil
	}

	return false, nil, nil
}

func copy(src, dst string, srcStat os.FileInfo) error {
	if !srcStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)

	os.Chtimes(dst, time.Time{}, srcStat.ModTime())
	return err
}

func (db *AutoUpdateMMIPGeo) update() {
	// Too early to check
	if time.Since(db.lastCheck) < checkUpdateInterval {
		return
	}

	db.lastCheck = time.Now()

	cityDBUpdated, updatedCityDBStat, err := isFileUpdated(db.cityDBFile, db.updatedCityDBFile)
	if err != nil {
		log.Printf("Check city db update failed: %v", err)
		return
	}

	asnDBUpdated, updatedASNDBStat, err := isFileUpdated(db.asnDBFile, db.updatedASNDBFile)
	if err != nil {
		log.Printf("Check asn db update failed: %v", err)
		return
	}

	// No need to update
	if !cityDBUpdated && !asnDBUpdated {
		return
	}

	db.mm.Close()

	if cityDBUpdated {
		if err := copy(db.updatedCityDBFile, db.cityDBFile, updatedCityDBStat); err != nil {
			log.Printf("Copy city db failed: %v", err)
			return
		}
	}

	if asnDBUpdated {
		if err := copy(db.updatedASNDBFile, db.asnDBFile, updatedASNDBStat); err != nil {
			log.Printf("Copy asn db failed: %v", err)
			return
		}
	}

	db.mm, err = NewMMIPGeo(db.cityDBFile, db.asnDBFile)
	if err != nil {
		log.Printf("NewMMIPGeo failed: %v", err)
	}
}

func (db *AutoUpdateMMIPGeo) GetIPGeo(ip string) *IPGeo {
	db.update()

	if db.mm == nil {
		log.Printf("db.mm is nil")
		return &IPGeo{
			IP: ip,
		}
	}

	return db.mm.GetIPGeo(ip)
}

type MMIPGeo struct {
	cityDB *geoip2.Reader
	asnDB  *geoip2.Reader
}

func NewMMIPGeo(cityDBFile, asnDBFile string) (*MMIPGeo, error) {
	cityDB, err := geoip2.Open(cityDBFile)
	if err != nil {
		return nil, err
	}

	asnDB, err := geoip2.Open(asnDBFile)
	if err != nil {
		return nil, err
	}

	return &MMIPGeo{
		cityDB: cityDB,
		asnDB:  asnDB,
	}, nil
}

type IPGeo struct {
	IP                           string `json:"ip"`
	City                         string `json:"city"`
	Subdivision                  string `json:"subdivision"`
	Country                      string `json:"country"`
	Proxy                        bool   `json:"proxy"`
	Anycast                      bool   `json:"anycast"`
	Satellite                    bool   `json:"satellite"`
	AutonomousSystemOrganization string `json:"autonomous_system_organization"`
}

func (mm *MMIPGeo) GetIPGeo(ip string) *IPGeo {
	res := &IPGeo{
		IP: ip,
	}

	ipAddr := net.ParseIP(ip)
	if city, _ := mm.cityDB.City(ipAddr); city != nil {
		res.City = city.City.Names["en"]
		res.Country = city.Country.Names["en"]
		res.Proxy = city.Traits.IsAnonymousProxy
		res.Anycast = city.Traits.IsAnonymousProxy
		res.Satellite = city.Traits.IsSatelliteProvider

		subdivision := []string{}
		for _, s := range city.Subdivisions {
			subdivision = append(subdivision, s.Names["en"])
		}
		slices.Reverse(subdivision)
		res.Subdivision = strings.Join(subdivision, "/")
	}
	if asn, _ := mm.asnDB.ASN(ipAddr); asn != nil {
		res.AutonomousSystemOrganization = asn.AutonomousSystemOrganization
	}

	return res
}

func (mm *MMIPGeo) Close() {
	mm.cityDB.Close()
	mm.asnDB.Close()
}
