#!/usr/bin/env python3
"""
DNS forwarder - listens on 0.0.0.0:53 (all interfaces, 供局域网其他机器使用)
Custom domains: local resolve (build clean response, strip EDNS from query)
Others: forward to upstream (strip EDNS)

Robustness:
- Upstream socket recreated every N queries or after any upstream error
- All parse points guarded against malformed packets
- Domain matching is case-insensitive
"""
import socket
import struct
import logging
import time

UPSTREAM = '59.215.244.10'
PORT = 53
TIMEOUT = 3
UPSTREAM_REBUILD_EVERY = 100  # 每 N 次查询重建一次上游 socket

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
        if pos > len(data):
            return data

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
        pos += 10
        if pos + 2 > len(data):
            return data
        rdlen = struct.unpack('>H', data[pos:pos+2])[0]
        pos += 2 + rdlen
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
    """Parse DNS wire-format QNAME. Handles compression pointers."""
    parts = []
    i = start
    loop_guard = 0
    while i < len(data) and loop_guard < 128:
        loop_guard += 1
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


def build_resp(query, qtype, qclass, qname_bytes, ip):
    """Build a clean DNS response for local custom domains."""
    resp = query[:2]

    if qtype != 1:
        # Non-A: return NOERROR empty answer
        resp += struct.pack('>H', 0x8180)
        resp += struct.pack('>H', 1)
        resp += struct.pack('>H', 0)
        resp += struct.pack('>H', 0)
        resp += struct.pack('>H', 0)
        resp += qname_bytes
        resp += struct.pack('>HH', qtype, qclass)
        return resp

    # A query: return local IP answer
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


def make_upstream_sock():
    """Create a fresh upstream UDP socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    return s


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', PORT))
    log.info(f'Listening on 0.0.0.0:{PORT}')
    log.info(f'Custom: {list(CUSTOM.keys())}')

    upstream_sock = make_upstream_sock()
    query_count = 0

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) < 12:
                continue

            s, end_pos = qname_str(data, 12)
            s = s.lower().rstrip('.')
            if not s or len(s) > 253:
                continue

            log.info(f'Query {addr}: "{s}"')

            matched = False
            for domain, ip in CUSTOM.items():
                if s == domain.lower().rstrip('.'):
                    # Parse QTYPE/QCLASS from query
                    pos = end_pos
                    if pos + 4 > len(data):
                        continue
                    qtype  = struct.unpack('>H', data[pos:pos+2])[0]
                    qclass = struct.unpack('>H', data[pos+2:pos+4])[0]
                    # Build qname_bytes from cleaned query
                    q = remove_opt(data)
                    qname_end = 12
                    while qname_end < len(q):
                        b = q[qname_end]
                        if b == 0:
                            qname_end += 1
                            break
                        if b >= 192:
                            qname_end += 2
                            break
                        qname_end += b + 1
                    qname_bytes = q[12:qname_end]
                    resp = build_resp(q, qtype, qclass, qname_bytes, ip)
                    if resp:
                        sock.sendto(resp, addr)
                        log.info(f'LOCAL: {s} -> {ip}')
                    matched = True
                    break

            if not matched:
                query_count += 1
                # 定期重建上游 socket，防止长时间运行后卡死
                if query_count >= UPSTREAM_REBUILD_EVERY:
                    try:
                        upstream_sock.close()
                    except Exception:
                        pass
                    upstream_sock = make_upstream_sock()
                    query_count = 0
                    log.info('Upstream socket rebuilt (periodic)')

                log.info(f'FWD to {UPSTREAM}')
                try:
                    clean_q = remove_opt(data)
                    upstream_sock.sendto(clean_q, (UPSTREAM, PORT))
                    resp, _ = upstream_sock.recvfrom(4096)
                    sock.sendto(resp, addr)
                except socket.timeout:
                    log.warning('Upstream timeout')
                except OSError as e:
                    import errno
                    try:
                        upstream_sock.close()
                    except Exception:
                        pass
                    upstream_sock = make_upstream_sock()
                    query_count = 0
                    # 网络不可达时退避等待，避免开机时死循环
                    if e.errno == errno.ENETUNREACH:
                        log.warning(f'Network unreachable, waiting 5s for network...')
                        time.sleep(5)
                    else:
                        log.error(f'Upstream error: {e} — rebuilding socket')
                except Exception as e:
                    log.error(f'Upstream error: {e} — rebuilding socket')
                    try:
                        upstream_sock.close()
                    except Exception:
                        pass
                    upstream_sock = make_upstream_sock()
                    query_count = 0

        except Exception as e:
            log.error(f'Main loop error: {e}')
            time.sleep(0.5)


if __name__ == '__main__':
    main()
