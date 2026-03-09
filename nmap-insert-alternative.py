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
    try:
        net = IPv4Network(network, strict=False)
    except ValueError as e:
        sys.exit(f"Error: Invalid network '{network}': {e}")

    if net.num_addresses <= 2:
        sys.exit(f"Error: Network {net} has no usable hosts (/31 or smaller)")

    base_int = int(net.network_address)
    host_bits = 32 - net.prefixlen
    max_offset = (1 << host_bits) - 1   # 2**host_bits - 1

    ips = []
    for _ in range(count):
        # Random bits for host portion (0 = network, all-1s = broadcast)
        rand_bits = random.getrandbits(host_bits)
        # Avoid network (0) and broadcast (all 1s)
        if rand_bits == 0:
            rand_bits = 1
        elif rand_bits == max_offset:
            rand_bits -= 1

        ip_int = base_int | rand_bits
        ips.append(str(IPv4Address(ip_int)))

    return ips
    

def main():
    args = parse_args()

    ips = generate_random_ips(args.network, args.count)

    if args.one_per_line:
        print("\n".join(ips))
    else:
        print(", ".join(ips))


if __name__ == "__main__":
    main()