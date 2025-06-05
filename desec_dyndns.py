"""Update DNS settings for a deSEC domain."""

import base64
import contextlib
import dataclasses
import fcntl
import ipaddress
import socket
import struct
import sys
from collections.abc import Mapping
from time import sleep
from typing import Any

import click
import desec  # type: ignore[import-untyped]

# Query A and AAAA records for a domain using dnspython and specific nameservers
import dns.resolver
import ifaddr
import netifaces
import requests  # type: ignore[import-untyped]
from requests.adapters import HTTPAdapter, Retry  # type: ignore[import-untyped]

# TODO: Allow usage via cron one-off with a click command,
# add other click command for systemd service

_log_target = sys.stdout


def _info(*args: Any, **kwargs: Any) -> None:
    kwargs["fg"] = "green"
    click.secho(*args, **kwargs)


def _warn(*args: Any, **kwargs: Any) -> None:
    kwargs["fg"] = "yellow"
    click.secho(*args, **kwargs)


def _error(*args: Any, **kwargs: Any) -> None:
    kwargs["fg"] = "red"
    click.secho(*args, **kwargs)


def resolve_nameservers() -> list[str]:
    """Resolve the nameservers for deSEC."""
    result = []
    for server in ["ns1.desec.io", "ns2.desec.org"]:
        with contextlib.suppress(Exception):
            result.append(socket.gethostbyname(server))
    if len(result) == 0:
        raise ValueError("No nameserver could be resolved")
    return result


resolver = dns.resolver.Resolver()
resolver.nameservers = resolve_nameservers()


def get_dns_info(hostname: str) -> Mapping[str, list[str]]:
    """Get DNS information for a given hostname."""
    result = {}
    for record_type in ["A", "AAAA"]:
        try:
            answers = resolver.resolve(hostname, record_type)
            result[record_type] = [rdata.address for rdata in answers]  # type: ignore[attr-defined]
        except Exception as e:
            print(f"Could not get {record_type} records: {e}")
    return result


def get_hwaddr(ifname: str) -> str:
    """Get the hardware address of a network interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", bytes(ifname, "utf-8")[:15]))
    return ":".join(f"{b:02x}" for b in info[18:24])


def update_dedyn(ipv4: str | None, ipv6: str | None) -> None:
    """Update the deSEC DDNS records for the given IPv4 and IPv6 addresses."""
    if not ipv4 or not ipv6:
        print("Skipping update: Missing IPv4 or IPv6 address")
        return
    for hostname in ["ddns.home.langbehn.family", "home.langbehn.family"]:
        resolved_addresses = get_dns_info(hostname)
        if ipv4 in resolved_addresses["A"] and ipv6 in resolved_addresses["AAAA"]:
            # print(f"No change for host {hostname}: v4 {ipv4} v6 {ipv6}")
            continue
        url = f"https://update.dedyn.io/nic/update?system=dyndns&hostname={hostname}&myip={ipv4}&myipv6={ipv6}"
        auth_value = base64.b64encode(f"{hostname}:ZPk6dSNEMGDgpYjDAXhBrqqQD8nF".encode()).decode("utf-8")
        headers = {"Authorization": f"Basic {auth_value}"}

        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            # print(f"Updated {hostname}: v4 {ipv4} v6 {ipv6},
            # resting a bit because of rate limit 1/min")
            sleep(61)
        except requests.RequestException as e:
            if e.response.status_code != 502:
                print(f"Error updating deSEC DDNS for host {hostname}: {e}")


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], auto_envvar_prefix="DESEC_DYNDNS")


def upd(
    domain: str, subdomain: list[str], token: str, interface: str, update_period: int, verbose: bool, dry_run: bool
) -> None:
    """Update DNS settings for a deSEC domain."""
    ipv4 = _get_public_ipv4()
    ipv6 = _get_public_ipv6(interface)
    update_dedyn(ipv4, ipv6)


desec._configure_cli_logging(10)


def _get_hardware_address(interface_name: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", bytes(interface_name, "utf-8")[:15]))
    return ":".join(f"{b:02x}" for b in info[18:24])


def _get_public_ipv4() -> str | None:
    try:
        s = requests.Session()
        s.mount(
            "http://",
            HTTPAdapter(max_retries=Retry(total=5, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])),
        )
        response = s.get("https://api.ipify.org/", timeout=5)
        response.raise_for_status()
        return response.text.strip()
    except requests.RequestException as e:
        print(f"Error retrieving public IPv4: {e}")
        return None


def _mac_to_ipv6_suffix(mac: str) -> str:
    mac_parts = mac.split(":")
    first_part_with_seventh_bit_inverted = f"{int(mac_parts[0], 16) ^ 0x02:02x}"
    mac_parts = [first_part_with_seventh_bit_inverted] + mac_parts[1:3] + ["ff", "fe"] + mac_parts[3:]
    return ":".join("".join(mac_parts[i : i + 2]) for i in range(0, len(mac_parts), 2))


def _get_public_ipv6(interface_name: str) -> str | None:
    mac = netifaces.ifaddresses(interface_name).get(netifaces.AF_PACKET)[0].get("addr")  # type: ignore[call-overload]
    mac_as_ipv6_suffix = _mac_to_ipv6_suffix(mac)
    print(f"Interface: {interface_name}, MAC: {mac}, suffix: {_mac_to_ipv6_suffix(mac)}")
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        if adapter.name == interface_name:
            for ip in adapter.ips:
                address = ipaddress.ip_address(ip.ip[0] if type(ip.ip) is tuple else ip.ip)  # type: ignore[arg-type]
                if address.version == 6 and address.is_global and address.exploded.endswith(mac_as_ipv6_suffix):
                    return address.compressed
    return None


@dataclasses.dataclass
class Updates:
    """data class for updates."""

    A: str | None = None
    AAAA: str | None = None

    def as_tuples(self) -> list[tuple[desec.DnsRecordTypeType, str]]:
        """Convert the updates to a list of tuples."""
        result: list[tuple[desec.DnsRecordTypeType, str]] = []
        if self.A:
            result.append(("A", self.A))
        if self.AAAA:
            result.append(("AAAA", self.AAAA))
        return result


def _get_dns_info(record_type: str, hostname: str) -> list[str]:
    answers = resolver.resolve(hostname, record_type)
    return [rdata.address for rdata in answers]  # type: ignore[attr-defined]


def _get_resolver_against_domain_nameservers(domain: str) -> dns.resolver.Resolver:
    """Get a DNS resolver configured to use deSEC nameservers."""
    resolver = dns.resolver.Resolver()
    # get nameservers from the domain
    try:
        ns_records = resolver.resolve(domain, "NS")
        resolver.nameservers = [str(ns.target) for ns in ns_records]  # type: ignore[attr-defined]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"No NS records found for domain {domain}, using default deSEC nameservers.")
        # If no NS records are found, use the default deSEC nameservers
        resolver.nameservers = resolve_nameservers()
    return resolver


@click.command(context_settings=CONTEXT_SETTINGS, help="Update DNS settings for a deSEC domain.")
@click.option("--domain", "-d", required=True, help="The domain to update in.")
@click.option("--subdomain", "-s", multiple=True, required=True, help="The subdomain(s) to update.")
@click.option("--token", "-t", required=True, help="The token to use for authentication.")
@click.option(
    "--interface",
    "-i",
    help="The network interface to use for determining the IPv6 address. If not set, IPv6 is not updated.",
)
@click.option(
    "--wait-time",
    "-w",
    type=int,
    default=5,
    show_default=True,
    help="The wait period between domain updates in seconds (for respecting rate limits).",
)
@click.option(
    "--log-file",
    "-l",
    type=click.Path(),
    default="-",
    show_default=True,
    help="The file to write logs to. Defaults to stdout.",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Increase verbosity of output (can be used multiple times for more verbosity, e.g. `-vvv`). Default is errors only. Once for info, twice or more for debug.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    show_default=True,
    default=False,
    help="Don't actually update the DNS records, just print what would be done",
)
def update(
    domain: str,
    subdomain: list[str],
    token: str,
    interface: str,
    wait_time: int,
    log_file: click.File,
    verbose: bool,
    dry_run: bool,
) -> None:
    """Update DNS settings for a deSEC domain."""
    _log_target = log_file
    to_update: Updates = Updates()
    # Get the public IPv4 address
    public_ipv4 = _get_public_ipv4()
    if not public_ipv4:
        _warn("Failed to retrieve public IPv4 address, skipping update of IPv4.")
    else:
        to_update.A = public_ipv4
    public_ipv6 = _get_public_ipv6(interface)
    if not public_ipv6:
        _warn("Failed to retrieve public IPv6 address, skipping update of IPv6.")
    else:
        to_update.AAAA = public_ipv6
    api_client = desec.APIClient(token=token, request_timeout=5, retry_limit=5)
    for rtype, public_ip in to_update.as_tuples():
        for subdomain_name in subdomain:
            records = api_client.get_records(domain=domain, rtype=rtype, subname=subdomain_name)
            ips = _get_dns_info(rtype, f"{subdomain_name}.{domain}")
            if ips:
                if len(ips) > 1:
                    print(f"Multiple {rtype} records found for {subdomain_name}.{domain}, skipping update of {rtype}")
                    continue
                if len(ips) == 1 and public_ipv4 in ips:
                    print(f"{rtype} record for {subdomain_name}.{domain} is already up to date.")
                    continue
            if dry_run:
                print(f"Dry run: Would create/update {rtype} record for {subdomain_name}.{domain} to {public_ip}")
            else:
                print(f"Creating/Updating {rtype} record for {subdomain_name}.{domain} to {public_ip}")
                if records and len(records):
                    api_client.change_record(domain=domain, subname=subdomain_name, rtype=rtype, rrset=[public_ip])
                else:
                    api_client.add_record(
                        domain=domain, subname=subdomain_name, rtype=rtype, rrset=[public_ip], ttl=3600
                    )
    sleep(wait_time)


if getattr(sys, "frozen", False):
    update(sys.argv[1:])
