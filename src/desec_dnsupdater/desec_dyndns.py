"""Update DNS settings for a deSEC domain."""

import contextlib
import dataclasses
import ipaddress
import socket
import sys
from time import sleep
from typing import Any

import click
import desec  # type: ignore[import-untyped]
import dns.resolver
import ifaddr
import netifaces
import requests  # type: ignore[import-untyped]
from requests.adapters import HTTPAdapter, Retry  # type: ignore[import-untyped]


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


_log_target = sys.stdout
_log_verbosity_level = 0


def _configure_logging(log_target: click.File, verbosity: int) -> None:
    """Configure logging for the script."""
    global _log_target, _log_verbosity_level
    _log_target = log_target
    _log_verbosity_level = verbosity
    # verbosity 3 -> level 10 (DEBUG), verbosity 2 -> level 20 (INFO), verbosity 1 -> level 30 (WARNING), verbosity 0 -> level 40 (ERROR)
    desec._configure_cli_logging(40 - verbosity * 10)


def _debug(*args: Any, **kwargs: Any) -> None:
    if _log_verbosity_level > 2:
        kwargs["file"] = _log_target
        click.secho(*args, **kwargs)


def _info(*args: Any, **kwargs: Any) -> None:
    if _log_verbosity_level > 1:
        kwargs["fg"] = "green"
        kwargs["file"] = _log_target
        click.secho(*args, **kwargs)


def _warn(*args: Any, **kwargs: Any) -> None:
    if _log_verbosity_level > 0:
        kwargs["fg"] = "yellow"
        kwargs["file"] = _log_target
        click.secho(*args, **kwargs)


def _error(*args: Any, **kwargs: Any) -> None:
    kwargs["fg"] = "red"
    kwargs["file"] = _log_target
    click.secho(*args, **kwargs)


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
        _warn(f"Error retrieving public IPv4, not updating IPv4: {e}")
        return None


def _get_public_ipv6(interface_name: str) -> str | None:
    def _mac_to_ipv6_suffix(mac: str) -> str:
        mac_parts = mac.split(":")
        first_part_with_seventh_bit_inverted = f"{int(mac_parts[0], 16) ^ 0x02:02x}"
        mac_parts = [first_part_with_seventh_bit_inverted] + mac_parts[1:3] + ["ff", "fe"] + mac_parts[3:]
        return ":".join("".join(mac_parts[i : i + 2]) for i in range(0, len(mac_parts), 2))

    mac = netifaces.ifaddresses(interface_name).get(netifaces.AF_PACKET)[0].get("addr")  # type: ignore[call-overload]
    mac_as_ipv6_suffix = _mac_to_ipv6_suffix(mac)
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        if adapter.name == interface_name:
            for ip in adapter.ips:
                address = ipaddress.ip_address(ip.ip[0] if type(ip.ip) is tuple else ip.ip)  # type: ignore[arg-type]
                if address.version == 6 and address.is_global and address.exploded.endswith(mac_as_ipv6_suffix):
                    _debug(f"Found public IPv6 address: {address}")
                    return address.compressed
    return None


def _get_resolver_against_domain_nameservers(domain: str) -> dns.resolver.Resolver:
    """Get a DNS resolver configured to use deSEC nameservers."""

    def _resolve_nameservers(servers: list[str]) -> list[str]:
        """Resolve the nameservers for deSEC."""
        result = []
        for server in servers:
            with contextlib.suppress(Exception):
                result.append(socket.gethostbyname(server))
        if len(result) == 0:
            _error("No nameserver could be resolved from hardcoded list of deSEC's DNS servers.")
            raise click.ClickException(
                "No nameserver could be resolved, neither from domain's NS records nor from hardcoded list of desec's DNS servers."
            )
        return result

    resolver = dns.resolver.Resolver()
    # get nameservers from the domain
    try:
        nameservers = [ns.to_text().strip(".") for ns in resolver.resolve(domain, "NS")]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        _warn(f"No NS records found for domain {domain}, using default deSEC nameservers.")
        nameservers = ["ns1.desec.io", "ns2.desec.org"]
        # If no NS records are found, use the default deSEC nameservers
    resolver.nameservers = _resolve_nameservers(nameservers)
    return resolver


def _update_once(
    domain: str,
    subdomain: list[str],
    token: str,
    interface: str | None,
    wait_time: int,
    dry_run: bool,
) -> None:
    """Update the DNS records for the given domain and subdomain."""
    to_update: Updates = Updates()
    # Get the public IPv4 address
    public_ipv4 = _get_public_ipv4()
    if not public_ipv4:
        _warn("Failed to retrieve public IPv4 address, skipping update of IPv4.")
    else:
        to_update.A = public_ipv4
    if interface:
        _debug(f"Using interface {interface} for IPv6 address retrieval.")
        public_ipv6 = _get_public_ipv6(interface)
        if not public_ipv6:
            _warn("Failed to retrieve public IPv6 address, skipping update of IPv6.")
        else:
            to_update.AAAA = public_ipv6
    for rtype, public_ip in to_update.as_tuples():
        for subdomain_name in subdomain:
            # handle special case of empty subdomain
            fqdn = f"{subdomain_name}.{domain}" if subdomain_name else domain
            ips = [
                rdata.address  # type: ignore[attr-defined]
                for rdata in _get_resolver_against_domain_nameservers(domain).resolve(fqdn, rtype)
            ]
            _debug(f"Resolved {rtype} records for {fqdn}: {ips}")
            if ips:
                if len(ips) > 1:
                    _warn(f"Multiple {rtype} records found for {fqdn}, skipping update of {rtype}")
                    continue
                if len(ips) == 1 and public_ip in ips:
                    _info(f"{rtype} record for {fqdn} is already up to date.")
                    continue
            if dry_run:
                _info(f"Dry run: Would create/update {rtype} record for {fqdn} to {public_ip}")
            else:
                _info(f"Creating/Updating {rtype} record for {fqdn} to {public_ip}")
                api_client = desec.APIClient(token=token, request_timeout=5, retry_limit=5)
                records = api_client.get_records(domain=domain, rtype=rtype, subname=subdomain_name)
                if records and len(records):
                    api_client.change_record(domain=domain, subname=subdomain_name, rtype=rtype, rrset=[public_ip])
                else:
                    api_client.add_record(
                        domain=domain, subname=subdomain_name, rtype=rtype, rrset=[public_ip], ttl=3600
                    )
                sleep(wait_time)


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], auto_envvar_prefix="DESEC_DYNDNS")


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
    "--log-file",
    "-l",
    type=click.File("w"),
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
    help="Don't actually update the DNS records, just print what would be done.",
)
@click.option(
    "--continuous",
    "-c",
    is_flag=True,
    show_default=True,
    default=False,
    help="Run the update in a loop, waiting for the specified wait time between updates.",
)
@click.option(
    "--wait-time-between-checks",
    type=int,
    default=60,
    show_default=True,
    help="The wait time between checks for updates in seconds (for continuous updates, see --continuous/-c).",
)
@click.option(
    "--wait-time-between-api-calls",
    type=int,
    default=5,
    show_default=True,
    help="The wait time between domain update api calls in seconds (for respecting rate limits).",
)
def update(
    domain: str,
    subdomain: list[str],
    token: str,
    interface: str | None,
    log_file: click.File,
    verbose: int,
    dry_run: bool,
    continuous: bool,
    wait_time_between_checks: int,
    wait_time_between_api_calls: int,
) -> None:
    """Update DNS settings for a deSEC domain."""
    _configure_logging(log_file, verbose)
    if continuous:
        _debug(f"Running in continuous mode, will update every {wait_time_between_checks} seconds.")
        while True:
            _update_once(domain, subdomain, token, interface, wait_time_between_api_calls, dry_run)
            sleep(wait_time_between_checks)
    else:
        _update_once(domain, subdomain, token, interface, wait_time_between_api_calls, dry_run)


if getattr(sys, "frozen", False):
    update(sys.argv[1:])
