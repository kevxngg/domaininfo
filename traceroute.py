#!/usr/bin/env python3
"""
traceroute.py — Python traceroute fallback
Author: @kevxngg (Kevin)
Usage : python3 traceroute.py <host> [max_hops]
"""

import socket
import sys
import time

from i18n import tr


def traceroute(dest_name, max_hops=15, timeout=2):
    try:
        dest_addr = socket.gethostbyname(dest_name)
    except socket.gaierror as e:
        print("  [!] " + tr("Cannot resolve: {host} — {error}", host=dest_name, error=e))
        sys.exit(1)

    print("  " + tr("Traceroute to {host} ({address}), max {hops} hops", host=dest_name,
                    address=dest_addr, hops=max_hops) + "\n")

    port = 33434
    icmp = socket.getprotobyname('icmp')
    udp  = socket.getprotobyname('udp')

    for ttl in range(1, max_hops + 1):
        try:
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        except PermissionError:
            # A TCP connection cannot reveal intermediate routers without ICMP.
            if 'recv_socket' in locals():
                recv_socket.close()
            print('  [!] ' + tr('No RAW socket permission: hops cannot be measured with this method.'))
            print('  ' + tr('Use traceroute/tracepath or python domaininfo.py -m full.'))
            return

        recv_socket.settimeout(timeout)
        send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        recv_socket.bind(("", port))

        send_socket.sendto(b"", (dest_addr, port))
        curr_addr = None
        curr_name = None
        start = time.time()
        rtt = None

        try:
            _, curr_addr = recv_socket.recvfrom(512)
            rtt = round((time.time() - start) * 1000, 2)
            curr_addr = curr_addr[0]
            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]
            except socket.herror:
                curr_name = curr_addr
        except socket.timeout:
            pass
        finally:
            send_socket.close()
            recv_socket.close()

        if curr_addr:
            label = f"{curr_name} ({curr_addr})" if curr_name != curr_addr else curr_addr
            print(f"  {ttl:2d}  {label:<55}  {rtt} ms")
        else:
            print(f"  {ttl:2d}  * * *  (timeout)")

        if curr_addr == dest_addr:
            print("\n  " + tr("Destination reached."))
            break

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(tr("Usage: python3 {script} <host> [max_hops]", script=sys.argv[0]))
        sys.exit(1)
    host     = sys.argv[1]
    max_hops = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    traceroute(host, max_hops)
