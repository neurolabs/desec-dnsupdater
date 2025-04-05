"""Update DNS settings for a deSEC domain."""

import dataclasses
import fcntl
import ipaddress
import socket
import struct
from time import sleep

import click
import desec  # type: ignore[import-untyped]
import ifaddr
import netifaces
import requests  # type: ignore[import-untyped]
from requests.adapters import HTTPAdapter, Retry  # type: ignore[import-untyped]

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], auto_envvar_prefix="DESEC_DYNDNS")


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


@click.command(context_settings=CONTEXT_SETTINGS, help="Update DNS settings for a deSEC domain")
@click.option("--domain", "-d", required=True, help="The domain to update in")
@click.option("--subdomain", "-s", multiple=True, required=True, help="The subdomain(s) to update")
@click.option("--token", "-t", required=True, help="The token to use for authentication")
@click.option("--interface", "-i", required=True, help="The network interface to use fpr determining the IPv6 address")
@click.option("--update-period", "-p", type=int, default=300, show_default=True, help="The update period in seconds")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    show_default=True,
    default=False,
    help="Print debug information",
)
@click.option(
    "--dry-run",
    is_flag=True,
    show_default=True,
    default=False,
    help="Don't actually update the DNS records, just print what would be done",
)
def update(
    domain: str, subdomain: list[str], token: str, interface: str, update_period: int, verbose: bool, dry_run: bool
) -> None:
    """Update DNS settings for a deSEC domain."""
    api_client = desec.APIClient(token=token, request_timeout=5, retry_limit=5)
    while True:
        to_update: Updates = Updates()
        # Get the public IPv4 address
        public_ipv4 = _get_public_ipv4()
        if not public_ipv4:
            print("Failed to retrieve public IPv4 address, skipping update of IPv4.")
        else:
            to_update.A = public_ipv4
        public_ipv6 = _get_public_ipv6(interface)
        if not public_ipv6:
            print("Failed to retrieve public IPv6 address, skipping update of IPv6.")
        else:
            to_update.AAAA = public_ipv6

        for rtype, public_ip in to_update.as_tuples():
            for subdomain_name in subdomain:
                records = api_client.get_records(domain=domain, rtype=rtype, subname=subdomain_name)
                if records:
                    if len(records) > 1:
                        print(
                            f"Multiple {rtype} records found for {subdomain_name}.{domain}, skipping update of {rtype}"
                        )
                        continue
                    if len(records) == 1 and public_ipv4 in records[0]["records"]:
                        print(f"{rtype} record for {subdomain_name}.{domain} is already up to date.")
                        continue
                print(f"Creating/Updating {rtype} record for {subdomain_name}.{domain} to {public_ip}")
                if not dry_run:
                    api_client.update_record(
                        domain=domain, subname=subdomain_name, rtype=rtype, rrset=list(public_ip), ttl=300
                    )

        sleep(update_period)
