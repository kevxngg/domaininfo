#!/usr/bin/env python3
"""
traceroute.py — Fallback de traceroute en Python
Autor: @kevxngg (Señor K)
Uso  : python3 traceroute.py <host> [max_hops]
"""

import socket
import sys
import time
import struct
import select
import os

def traceroute(dest_name, max_hops=15, timeout=2):
    try:
        dest_addr = socket.gethostbyname(dest_name)
    except socket.gaierror as e:
        print(f"  [!] No se puede resolver: {dest_name} — {e}")
        sys.exit(1)

    print(f"  Traceroute a {dest_name} ({dest_addr}), máx {max_hops} saltos\n")

    port = 33434
    icmp = socket.getprotobyname('icmp')
    udp  = socket.getprotobyname('udp')

    for ttl in range(1, max_hops + 1):
        try:
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        except PermissionError:
            # Termux / sin root — usar TCP connect como fallback
            _traceroute_tcp(dest_addr, dest_name, max_hops, timeout)
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
            print(f"\n  Destino alcanzado.")
            break

def _traceroute_tcp(dest_addr, dest_name, max_hops, timeout):
    """Fallback TCP para entornos sin permisos RAW socket (Termux sin root)"""
    print(f"  [!] Sin permisos RAW — usando TCP connect fallback\n")
    port = 80
    for ttl in range(1, max_hops + 1):
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((dest_addr, port))
            rtt = round((time.time() - start) * 1000, 2)
            s.close()
            if result == 0:
                print(f"  {ttl:2d}  {dest_addr:<55}  {rtt} ms  [REACHED]")
                break
            else:
                print(f"  {ttl:2d}  {dest_addr:<55}  {rtt} ms")
        except Exception:
            print(f"  {ttl:2d}  * * *")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: python3 {sys.argv[0]} <host> [max_hops]")
        sys.exit(1)
    host     = sys.argv[1]
    max_hops = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    traceroute(host, max_hops)
