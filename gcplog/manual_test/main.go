package main

import (
	"flag"
	"log"
	"time"

	"github.com/charleshuang3/firewall/gcplog"
)

var (
	authFile  = flag.String("auth", ".local/auth.json", "")
	projectID = flag.String("project", "", "")
)

func main() {
	flag.Parse()

	logger, err := gcplog.New(*authFile, *projectID, "test-service")
	if err != nil {
		log.Fatalf("failed to create logger: %v", err)
	}

	logger.Log("10.0.0.1", time.Now().Add(time.Hour), []string{"for testing"}, "act", nil)

	logger.Close()
}
