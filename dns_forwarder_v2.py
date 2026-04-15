#!/usr/bin/env python3
"""
DNS forwarder - listens on 0.0.0.0:53 (all interfaces,供局域网其他机器使用)
Custom domains: local resolve (build clean response, strip EDNS from query)
Others: forward to upstream (strip EDNS)
"""
import socket
import struct
import logging

UPSTREAM = '59.215.244.10'
PORT = 53
TIMEOUT = 5

CUSTOM = {
    'cas.zrzy.gz.cegn.cn': '59.215.188.116',
    'entrygzportal8-vip.yw.zrzy.gz.cegn.cn': '172.29.97.91',
    'map.zrzy.gz.cegn.cn': '59.215.188.84',
}

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s',
    handlers=[logging.FileHandler('/tmp/dns_fwd.log'), logging.StreamHandler()])
log = logging.getLogger(__name__)

def remove_opt(data):
    """Remove EDNS OPT record from DNS message."""
    if len(data) < 12:
        return data
    qdcount = struct.unpack('>H', data[4:6])[0]
    ancount = struct.unpack('>H', data[6:8])[0]
    nscount = struct.unpack('>H', data[8:10])[0]
    arcount = struct.unpack('>H', data[10:12])[0]

    pos = 12
    for _ in range(qdcount):
        while pos < len(data) and data[pos] != 0:
            b = data[pos]
            if b >= 192:
                pos += 2
                break
            pos += b + 1
        else:
            pos += 1
        pos += 4

    total_rr = ancount + nscount + arcount
    for _ in range(total_rr):
        while pos < len(data) and data[pos] != 0:
            b = data[pos]
            if b >= 192:
                pos += 2
                break
            pos += b + 1
        else:
            pos += 1
        pos += 8
        if pos >= len(data):
            return data
        rdlen = struct.unpack('>H', data[pos-2:pos])[0]
        pos += rdlen
        if pos >= len(data):
            return data

    while pos < len(data):
        name_len = data[pos]
        if name_len == 0 and pos + 11 <= len(data):
            rtype = struct.unpack('>H', data[pos+1:pos+3])[0]
            if rtype == 41:
                rdlen = struct.unpack('>H', data[pos+9:pos+11])[0]
                opt_end = pos + 11 + rdlen
                return data[:pos] + data[opt_end:]
            break
        elif name_len >= 192:
            break
        else:
            pos += name_len + 1

    return data

def qname_str(data, start):
    parts = []
    i = start
    while i < len(data):
        b = data[i]
        if b == 0:
            i += 1
            break
        if b >= 192:
            ptr = struct.unpack('>H', data[i:i+2])[0] & 0x3FFF
            suffix, _ = qname_str(data, ptr)
            parts.append(suffix)
            i += 2
            break
        parts.append(data[i+1:i+1+b].decode('ascii', errors='replace'))
        i += b + 1
    return '.'.join(parts), i

def build_resp(query, domain_str, ip):
    q = remove_opt(query)
    pos = 12
    while pos < len(q) and q[pos] != 0:
        b = q[pos]
        if b >= 192:
            pos += 2
            break
        pos += b + 1
    else:
        pos += 1
    qname_bytes = q[12:pos]
    qtype = struct.unpack('>H', q[pos:pos+2])[0]
    qclass = struct.unpack('>H', q[pos+2:pos+4])[0]

    resp = query[:2]
    resp += struct.pack('>H', 0x8180)
    resp += struct.pack('>H', 1)
    resp += struct.pack('>H', 1)
    resp += struct.pack('>H', 0)
    resp += struct.pack('>H', 0)
    resp += qname_bytes
    resp += struct.pack('>HH', qtype, qclass)
    resp += struct.pack('>H', 0xC00C)
    resp += struct.pack('>HHIH', 1, 1, 300, 4)
    resp += socket.inet_aton(ip)
    return resp

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(None)
    sock.bind(('0.0.0.0', PORT))
    log.info(f'Listening on 0.0.0.0:{PORT}')
    log.info(f'Custom: {list(CUSTOM.keys())}')

    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.settimeout(TIMEOUT)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) < 13:
                continue

            s, _ = qname_str(data, 12)
            log.info(f'Query {addr}: "{s}"')

            matched = False
            for domain, ip in CUSTOM.items():
                if s == domain:
                    log.info(f'LOCAL: {s} -> {ip}')
                    resp = build_resp(data, s, ip)
                    sock.sendto(resp, addr)
                    matched = True
                    break

            if not matched:
                log.info(f'FWD to {UPSTREAM}')
                try:
                    clean_q = remove_opt(data)
                    upstream.sendto(clean_q, (UPSTREAM, PORT))
                    resp, _ = upstream.recvfrom(4096)
                    sock.sendto(resp, addr)
                except socket.timeout:
                    log.error('Upstream timeout')
        except Exception as e:
            log.error(f'Error: {e}')

if __name__ == '__main__':
    main()
