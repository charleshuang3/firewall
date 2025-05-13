# Firewall

## Overview

Firewall is a Go library designed for connecting to various firewall providers. It is intended for use in a reverse proxy to block IP addresses at the firewall level.

It integrates with the following firewall providers:

- opnsense
- pfsense: Support for pfsense is included but may require verification with recent versions.
- routeros: Support for routeros is included but may require verification with recent versions.

It also integrates with the following log providers:

- zerolog: for local logging
- GCP Logging: useful for analysis on the Google Cloud Platform UI
