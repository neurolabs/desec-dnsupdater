# deSEC DNS Updater

A dynamic DNS client for [deSEC.io](https://desec.io) domains that updates A and AAAA records based on your current public IP addresses.

## Features

- Updates both A (IPv4) and AAAA (IPv6) records
- Supports multiple subdomains in a single run
- Dry run mode to preview changes without modifying DNS
- Customizable verbosity levels
- Can run as a one-time update (e.g. via cron) or in continuous mode (e.g. via a systemd unit)
- Respects API rate limits
- Configurable via command line or environment variables
- IPv6 detection from specific network interfaces
- Robust error handling and logging

## Installation

### Using pip

```bash
pip install desec-dnsupdater
```

### From source

```bash
git clone https://github.com/yourusername/desec-dnsupdater.git
cd desec-dnsupdater
pip install .
# OR using Poetry
poetry install
```

## Usage

### Basic usage

```bash
desec-dyndns --domain example.com --subdomain www --token YOUR_DESEC_TOKEN
```

### Updating multiple subdomains

```bash
desec-dyndns --domain example.com --subdomain www --subdomain api --token YOUR_DESEC_TOKEN
```

### Specifying a network interface for IPv6 detection

```bash
desec-dyndns --domain example.com --subdomain www --token YOUR_DESEC_TOKEN --interface eth0
```

### Dry run (preview changes without applying)

```bash
desec-dyndns --domain example.com --subdomain www --token YOUR_DESEC_TOKEN --dry-run
```

### Continuous mode (run as a daemon)

```bash
desec-dyndns --domain example.com --subdomain www --token YOUR_DESEC_TOKEN --continuous
```

### Increase verbosity

```bash
# Show only errors
desec-dyndns --domain example.com --subdomain www --token YOUR_DESEC_TOKEN

# Show warnings and errors
desec-dyndns --domain example.com --subdomain www --token YOUR_DESEC_TOKEN -v

# Show info, warnings, and errors
desec-dyndns --domain example.com --subdomain www --token YOUR_DESEC_TOKEN -vv

# Show debug messages, info, warnings, and errors
desec-dyndns --domain example.com --subdomain www --token YOUR_DESEC_TOKEN -vvv
```

## Command Reference

```
Usage: desec-dyndns [OPTIONS]

  Update DNS settings for a deSEC domain.

Options:
  -d, --domain TEXT               The domain to update in.  [required]
  -s, --subdomain TEXT            The subdomain(s) to update.  [required]
  -t, --token TEXT                The token to use for authentication.
                                  [required]
  -i, --interface TEXT            The network interface to use for determining
                                  the IPv6 address. If not set, IPv6 is not
                                  updated.
  -l, --log-file FILENAME         The file to write logs to. Defaults to
                                  stdout.  [default: -]
  -v, --verbose                   Increase verbosity of output (can be used
                                  multiple times for more verbosity, e.g.
                                  `-vvv`). Default is errors only. Once for
                                  warnings, twice for info, three times for
                                  debug.
  --dry-run                       Don't actually update the DNS records, just
                                  print what would be done.  [default: False]
  -c, --continuous                Run the update in a loop, waiting for the
                                  specified wait time between updates.
                                  [default: False]
  --wait-time-between-checks INTEGER
                                  The wait time between checks for updates in
                                  seconds (for continuous updates, see
                                  --continuous/-c).  [default: 60]
  --wait-time-between-api-calls INTEGER
                                  The wait time between domain update API calls
                                  in seconds (for respecting rate limits).
                                  [default: 5]
  -h, --help                      Show this message and exit.
```

## Environment Variables

All command-line options can also be specified via environment variables with the prefix `DESEC_DYNDNS_`:

- `DESEC_DYNDNS_DOMAIN` - The domain to update
- `DESEC_DYNDNS_SUBDOMAIN` - The subdomain(s) to update
- `DESEC_DYNDNS_TOKEN` - Your deSEC API token
- `DESEC_DYNDNS_INTERFACE` - Network interface for IPv6
- `DESEC_DYNDNS_LOG_FILE` - Log file path
- `DESEC_DYNDNS_VERBOSE` - Verbosity level (set to number 1-3)
- `DESEC_DYNDNS_DRY_RUN` - Set to any value to enable
- `DESEC_DYNDNS_CONTINUOUS` - Set to any value to enable
- `DESEC_DYNDNS_WAIT_TIME_BETWEEN_CHECKS` - Time between checks in continuous mode
- `DESEC_DYNDNS_WAIT_TIME_BETWEEN_API_CALLS` - Time between API calls

Example:
```bash
export DESEC_DYNDNS_DOMAIN=example.com
export DESEC_DYNDNS_SUBDOMAIN=www
export DESEC_DYNDNS_TOKEN=your_token_here
desec-dyndns  # Uses values from environment
```

## How It Works

1. The tool retrieves your current public IPv4 address from ipify.org
2. If specified, it detects your public IPv6 address from the given network interface
3. It compares these with the current DNS records for your domain
4. If different, it updates the records using the deSEC API via the `desec-dns` python client

### Assumptions

- You have created an API token with permission to modify your domain's DNS records
- For IPv6 updates, you need a globally routable IPv6 address on the specified interface which is derived from your MAC address (no privacy extensions)
- You have properly set up your domain with deSEC.io

## Running as a Service

### Systemd

Create a file at `/etc/systemd/system/desec-dyndns.service`:

```ini
[Unit]
Description=deSEC Dynamic DNS Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/path/to/desec-dyndns --domain example.com --subdomain www --token YOUR_TOKEN --interface eth0 --continuous
Restart=on-failure
RestartSec=60s

[Install]
WantedBy=multi-user.target
```

Then enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable desec-dyndns
sudo systemctl start desec-dyndns
```

## Troubleshooting

- If you get authentication errors, check your token
- For IPv6 issues, make sure your interface has a public IPv6 address
- Increase verbosity up to `-vvv` to see detailed debug information
- Use `--dry-run` to test without making changes

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.