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

    # 跳过 Question section
    for _ in range(qdcount):
        while pos < len(data):
            b = data[pos]
            if b == 0:
                pos += 1
                break
            if b >= 192:
                pos += 2
                break
            pos += b + 1
        pos += 4  # QTYPE + QCLASS

    # 跳过 Answer / NS section 的所有 RR，修复：固定部分应跳 10 字节
    total_rr = ancount + nscount
    for _ in range(total_rr):
        # 跳过 NAME
        while pos < len(data):
            b = data[pos]
            if b == 0:
                pos += 1
                break
            if b >= 192:
                pos += 2
                break
            pos += b + 1
        # TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) = 10 字节
        pos += 10
        if pos > len(data):
            return data
        rdlen = struct.unpack('>H', data[pos - 2:pos])[0]
        pos += rdlen
        if pos > len(data):
            return data

    # 在 Additional section 中查找并移除 OPT record
    new_arcount = arcount
    result = data
    for _ in range(arcount):
        if pos >= len(result):
            break
        rr_start = pos
        # 跳过 NAME
        while pos < len(result):
            b = result[pos]
            if b == 0:
                pos += 1
                break
            if b >= 192:
                pos += 2
                break
            pos += b + 1
        # 需要至少 10 字节的固定部分
        if pos + 10 > len(result):
            break
        rtype = struct.unpack('>H', result[pos:pos + 2])[0]
        pos += 10  # TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2)
        rdlen = struct.unpack('>H', result[pos - 2:pos])[0]
        rr_end = pos + rdlen
        if rtype == 41:  # OPT record，直接切掉
            result = result[:rr_start] + result[rr_end:]
            new_arcount -= 1
            pos = rr_start  # 位置回退到切除点继续
        else:
            pos = rr_end

    if new_arcount != arcount:
        # 更新 ARCOUNT
        result = result[:10] + struct.pack('>H', new_arcount) + result[12:]

    return result


def qname_str(data, start):
    parts = []
    i = start
    visited = set()
    while i < len(data):
        if i in visited:
            break
        visited.add(i)
        b = data[i]
        if b == 0:
            i += 1
            break
        if b >= 192:
            ptr = struct.unpack('>H', data[i:i + 2])[0] & 0x3FFF
            suffix, _ = qname_str(data, ptr)
            if suffix:
                parts.append(suffix)
            i += 2
            break
        parts.append(data[i + 1:i + 1 + b].decode('ascii', errors='replace'))
        i += b + 1
    return '.'.join(parts), i


def build_resp(query, ip):
    """
    构建 A 记录应答，或对非 A 查询返回 NOERROR 空应答。
    统一使用 remove_opt 后的 q 操作，避免偏移混乱。
    """
    q = remove_opt(query)

    # 解析 QNAME，修复：正确包含末尾 0x00
    pos = 12
    while pos < len(q):
        b = q[pos]
        if b == 0:
            pos += 1   # 跳过末尾 0x00，pos 现在指向 0x00 之后
            break
        if b >= 192:
            pos += 2
            break
        pos += b + 1

    qname_bytes = q[12:pos]  # 包含末尾 0x00（或压缩指针），结构完整

    if pos + 4 > len(q):
        return None

    qtype  = struct.unpack('>H', q[pos:pos + 2])[0]
    qclass = struct.unpack('>H', q[pos + 2:pos + 4])[0]

    # 非 A 查询（如 AAAA、MX 等）返回 NOERROR 空应答，避免客户端解析错误
    if qtype != 1:
        resp  = q[:2]                           # Transaction ID
        resp += struct.pack('>H', 0x8180)       # Flags: QR RD RA
        resp += struct.pack('>H', 1)            # QDCOUNT
        resp += struct.pack('>H', 0)            # ANCOUNT = 0
        resp += struct.pack('>H', 0)            # NSCOUNT
        resp += struct.pack('>H', 0)            # ARCOUNT
        resp += qname_bytes
        resp += struct.pack('>HH', qtype, qclass)
        return resp

    # A 查询，构建完整 A 记录应答
    resp  = q[:2]                               # Transaction ID
    resp += struct.pack('>H', 0x8180)           # Flags: QR RD RA
    resp += struct.pack('>H', 1)                # QDCOUNT
    resp += struct.pack('>H', 1)                # ANCOUNT
    resp += struct.pack('>H', 0)                # NSCOUNT
    resp += struct.pack('>H', 0)                # ARCOUNT
    # Question section
    resp += qname_bytes
    resp += struct.pack('>HH', qtype, qclass)
    # Answer section
    resp += struct.pack('>H', 0xC00C)           # NAME: 压缩指针指向 offset 12
    resp += struct.pack('>HHiH', 1, 1, 300, 4) # TYPE A, CLASS IN, TTL 300, RDLEN 4
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
            s = s.rstrip('.')  # 修复：统一去掉末尾的点再做匹配
            log.info(f'Query {addr}: "{s}"')

            matched = False
            for domain, ip in CUSTOM.items():
                if s == domain:
                    log.info(f'LOCAL: {s} -> {ip}')
                    resp = build_resp(data, ip)
                    if resp:
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
            log.error(f'Error: {e}', exc_info=True)


if __name__ == '__main__':
    main()