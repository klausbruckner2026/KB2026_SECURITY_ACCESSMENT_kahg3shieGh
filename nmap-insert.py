#!/usr/bin/env python3
"""
Generate random usable IPv4 addresses within a given CIDR subnet.

Useful for creating decoy/source IP lists for tools like nmap (--decoy, -D, or -S).

Excludes the network address and broadcast address.
"""
import argparse
import random
import sys
from ipaddress import IPv4Network, IPv4Address


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate random usable IP addresses in a CIDR subnet "
                    "(excludes network & broadcast addresses).",
        epilog="Example:\n"
               "  python3 random_ips.py -n 192.168.10.0/24 -c 50\n"
               "  python3 random_ips.py -n 10.0.0.0/16 -c 200 > decoys.txt"
    )
    parser.add_argument(
        "-n", "--network",
        required=True,
        help="CIDR network (e.g. 192.168.1.0/24, 10.13.0.0/16)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=10,
        help="Number of IP addresses to generate (default: 10)"
    )
    parser.add_argument(
        "--one-per-line",
        action="store_true",
        help="Print one IP per line (good for piping / nmap -iL)"
    )
    return parser.parse_args()


def generate_random_ips(network: str, count: int) -> list[str]:
    """
    Generate 'count' random usable host IPs from the given CIDR network.
    """
    try:
        net = IPv4Network(network, strict=False)
    except ValueError as e:
        sys.exit(f"Error: Invalid network '{network}': {e}")

    # Calculate number of usable hosts
    if net.prefixlen >= 31:
        usable = list(net.hosts())  # /31 and /32 have 0 or 1 usable host
        if not usable:
            sys.exit(f"Error: Network {net} has no usable host addresses (/31 or /32)")
        # For tiny subnets just return what we have (possibly duplicates if count > len)
        selected = random.choices(usable, k=count)
    else:
        # Efficient way: treat as integer offset from network address
        # (avoids building huge list for /16, /8, etc.)
        base = int(net.network_address)
        num_hosts = net.num_addresses - 2  # exclude net + broadcast

        if num_hosts < 1:
            sys.exit(f"Error: Network {net} has no usable hosts")

        selected = []
        for _ in range(count):
            offset = random.randrange(1, num_hosts + 1)  # 1 .. (num_hosts)
            ip_int = base + offset
            selected.append(str(IPv4Address(ip_int)))

    return selected


def main():
    args = parse_args()

    ips = generate_random_ips(args.network, args.count)

    if args.one_per_line:
        print("\n".join(ips))
    else:
        print(", ".join(ips))


if __name__ == "__main__":
    main()