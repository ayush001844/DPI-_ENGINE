#!/usr/bin/env python3
"""
Generate a rich, realistic test PCAP file with various protocols and traffic patterns
for Deep Packet Inspection (DPI) and SIEM analysis.

Features:
- Configurable packet count (default 1500, easily set to 1000-2000+)
- Full multi-packet TLS 1.2/1.3 sessions with SNI and bidirectional application data
- HTTP 1.1 request & response flows with benign and attack payloads (SQLi, path traversal, scanner UAs)
- DNS queries and authoritative response pairs (A, PTR, DNS tunneling simulation)
- Blocked IP traffic (192.168.1.50) matching DPI engine rule checks
- Blocked application traffic (YouTube) matching DPI application filter checks
- Port scan / network reconnaissance sweeps (SYN scans with RST/ACK replies)
- SSH brute-force attack attempts
- DDoS / UDP flood burst
- ICMP echo requests and replies
- Realistic timestamp progression with sub-second / microsecond precision
"""

import argparse
import os
import random
import shutil
import struct
import sys


class PCAPWriter:
    """Standard libpcap file writer."""

    def __init__(self, filename: str, start_time: float = 1700000000.0):
        self.filename = filename
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = start_time
        self.packet_count = 0

    def write_global_header(self):
        # Magic (0xa1b2c3d4), version 2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype Ethernet (1)
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)

    def write_packet(self, data: bytes, dt: float = None):
        if dt is None:
            dt = random.uniform(0.0005, 0.015)
        self.timestamp += dt
        ts_sec = int(self.timestamp)
        ts_usec = int((self.timestamp - ts_sec) * 1_000_000)

        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)
        self.packet_count += 1

    def close(self):
        self.file.close()


def create_ethernet_header(src_mac: str, dst_mac: str, ethertype: int = 0x0800) -> bytes:
    return (
        bytes.fromhex(dst_mac.replace(':', '')) +
        bytes.fromhex(src_mac.replace(':', '')) +
        struct.pack('>H', ethertype)
    )


def create_ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int, ttl: int = 64) -> bytes:
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000  # Don't fragment
    checksum = 0

    header = struct.pack(
        '>BBHHHBBH',
        version_ihl, tos, total_len,
        ident, flags_frag,
        ttl, protocol, checksum
    )

    header += bytes([int(x) for x in src_ip.split('.')])
    header += bytes([int(x) for x in dst_ip.split('.')])
    return header


def create_tcp_header(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload_len: int = 0,
    window: int = 65535
) -> bytes:
    data_offset = 5 << 4  # 20 bytes header
    checksum = 0
    urgent = 0
    return struct.pack(
        '>HHIIBBHHH',
        src_port, dst_port,
        seq, ack,
        data_offset, flags,
        window, checksum, urgent
    )


def create_udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    length = 8 + payload_len
    checksum = 0
    return struct.pack('>HHHH', src_port, dst_port, length, checksum)


def create_icmp_echo(icmp_type: int, identifier: int = 1234, seq: int = 1, data: bytes = b'DPI-PING-TEST-PROBE') -> bytes:
    # icmp_type: 8 = echo request, 0 = echo reply
    checksum = 0
    header = struct.pack('>BBHHH', icmp_type, 0, checksum, identifier, seq)
    return header + data


def create_tls_client_hello(sni: str) -> bytes:
    """Create a standard TLS Client Hello with SNI extension."""
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list

    supported_versions = struct.pack('>HHB', 0x002b, 3, 2) + struct.pack('>H', 0x0304)
    extensions = sni_ext + supported_versions
    extensions_data = struct.pack('>H', len(extensions)) + extensions

    client_version = struct.pack('>H', 0x0303)  # TLS 1.2
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 0)
    cipher_suites = struct.pack('>H', 6) + struct.pack('>HHH', 0x1301, 0x1302, 0xc02f)
    compression = struct.pack('BB', 1, 0)

    client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data

    handshake = struct.pack('B', 0x01)
    handshake += struct.pack('>I', len(client_hello_body))[1:]
    handshake += client_hello_body

    record = struct.pack('B', 0x16)
    record += struct.pack('>H', 0x0301)
    record += struct.pack('>H', len(handshake))
    record += handshake
    return record


def create_tls_server_hello() -> bytes:
    """Create a simulated TLS Server Hello record."""
    server_version = struct.pack('>H', 0x0303)
    server_random = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 32) + bytes([random.randint(0, 255) for _ in range(32)])
    cipher_suite = struct.pack('>H', 0x1301)
    compression = struct.pack('B', 0)

    # Supported versions extension (TLS 1.3)
    ext = struct.pack('>HH', 0x002b, 2) + struct.pack('>H', 0x0304)
    ext_data = struct.pack('>H', len(ext)) + ext

    body = server_version + server_random + session_id + cipher_suite + compression + ext_data
    handshake = struct.pack('B', 0x02) + struct.pack('>I', len(body))[1:] + body
    record = struct.pack('B', 0x16) + struct.pack('>H', 0x0303) + struct.pack('>H', len(handshake)) + handshake
    return record


def create_tls_app_data(length: int = 180) -> bytes:
    """Create a simulated TLS Application Data record (type 0x17)."""
    payload = bytes([random.randint(0, 255) for _ in range(length)])
    record = struct.pack('B', 0x17) + struct.pack('>H', 0x0303) + struct.pack('>H', len(payload)) + payload
    return record


def create_http_request(host: str, path: str = '/', method: str = 'GET', user_agent: str = 'DPI-Test/2.0') -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode('utf-8')


def create_http_response(status_code: int = 200, status_text: str = 'OK', body_len: int = 350) -> bytes:
    body = ("<!DOCTYPE html><html><head><title>DPI Test</title></head>"
            "<body><h1>Deep Packet Inspection Validated</h1><p>Status: Active</p></body></html>")
    return (
        f"HTTP/1.1 {status_code} {status_text}\r\n"
        f"Content-Type: text/html; charset=UTF-8\r\n"
        f"Server: nginx/1.24.0\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: keep-alive\r\n\r\n{body}"
    ).encode('utf-8')


def create_dns_query(domain: str, qtype: int = 1) -> tuple[bytes, bytes]:
    """Create a DNS query payload and return (txid, payload)."""
    txid = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)  # Standard query with recursion desired
    counts = struct.pack('>HHHH', 1, 0, 0, 0)

    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode('ascii')
    question += struct.pack('B', 0)
    question += struct.pack('>HH', qtype, 1)  # Type, Class IN

    return txid, txid + flags + counts + question


def create_dns_response(domain: str, txid: bytes, ip_address: str = '93.184.216.34') -> bytes:
    """Create a matching DNS response payload."""
    flags = struct.pack('>H', 0x8180)  # Standard response, recursion available
    counts = struct.pack('>HHHH', 1, 1, 0, 0)

    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode('ascii')
    question += struct.pack('B', 0)
    question += struct.pack('>HH', 1, 1)

    # Answer using name compression pointer (0xc00c points to question name)
    answer = struct.pack('>HHHIH', 0xc00c, 1, 1, 300, 4)
    answer += bytes([int(x) for x in ip_address.split('.')])

    return txid + flags + counts + question + answer


# ─────────────────────────────────────────────────────────────────────────────
# Traffic Scenario Definitions
# ─────────────────────────────────────────────────────────────────────────────

TLS_DOMAINS = [
    # Top web & search
    ('142.250.185.206', 'www.google.com', 443),
    ('204.79.197.200', 'www.bing.com', 443),
    ('208.80.154.224', 'en.wikipedia.org', 443),
    # Social & media (YouTube triggers app blocking rule in test cases)
    ('142.250.185.110', 'www.youtube.com', 443),
    ('157.240.1.35', 'www.facebook.com', 443),
    ('157.240.1.174', 'www.instagram.com', 443),
    ('104.244.42.65', 'twitter.com', 443),
    ('99.86.0.100', 'www.tiktok.com', 443),
    ('151.101.65.140', 'www.reddit.com', 443),
    ('108.174.10.10', 'www.linkedin.com', 443),
    # Tech & development
    ('140.82.114.4', 'github.com', 443),
    ('172.65.251.78', 'gitlab.com', 443),
    ('151.101.1.69', 'stackoverflow.com', 443),
    ('151.101.0.223', 'pypi.org', 443),
    ('104.18.23.19', 'hub.docker.com', 443),
    # Cloud & infrastructure
    ('192.0.78.24', 'www.cloudflare.com', 443),
    ('52.94.236.248', 'www.amazon.com', 443),
    ('54.239.28.85', 'aws.amazon.com', 443),
    ('13.107.42.14', 'www.microsoft.com', 443),
    ('20.42.65.80', 'azure.microsoft.com', 443),
    # Streaming & communication
    ('23.52.167.61', 'www.netflix.com', 443),
    ('35.186.224.47', 'open.spotify.com', 443),
    ('151.101.66.167', 'www.twitch.tv', 443),
    ('104.16.85.20', 'discord.com', 443),
    ('35.186.224.25', 'zoom.us', 443),
    ('35.186.227.140', 'web.telegram.org', 443),
    ('54.148.37.100', 'slack.com', 443),
    ('17.253.144.10', 'www.apple.com', 443),
    ('104.18.12.122', 'openai.com', 443),
    # Suspicious C2 simulation
    ('198.51.100.99', 'c2-listener.darknet-command.org', 8443),
]

HTTP_SERVICES = [
    ('93.184.216.34', 'example.com', 80, '/', 'GET', 'Mozilla/5.0'),
    ('185.199.108.153', 'httpbin.org', 80, '/get', 'GET', 'DPI-Test/2.0'),
    ('104.16.124.96', 'detectportal.firefox.com', 80, '/success.txt', 'GET', 'Firefox/124.0'),
    ('172.217.16.206', 'connectivitycheck.gstatic.com', 80, '/generate_204', 'GET', 'Android/13'),
    ('151.101.193.140', 'news.ycombinator.com', 80, '/', 'GET', 'Chrome/122.0'),
    # Security attack test cases
    ('192.168.1.150', 'vulnerable-internal.local', 80, '/products?cat=1%20UNION%20SELECT%20username,password%20FROM%20users', 'GET', 'sqlmap/1.4.11'),
    ('192.168.1.150', 'vulnerable-internal.local', 80, '/download?file=../../../../etc/passwd', 'GET', 'Nikto/2.1.6'),
    ('192.168.1.150', 'vulnerable-internal.local', 80, '/comment?q=<script>alert(1)</script>', 'POST', 'Mozilla/5.0'),
]

DNS_DOMAINS = [
    'www.google.com', 'www.youtube.com', 'www.facebook.com', 'api.twitter.com',
    'github.com', 'en.wikipedia.org', 'aws.amazon.com', 'cloudflare.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com',
    'zoom.us', 'discord.com', 'telegram.org', 'openai.com',
    'reddit.com', 'linkedin.com', 'twitch.tv', 'docker.com',
    # Tunneling / DGA simulation
    'dGVzdC1leGZpbC0wMQ==.c2.threat-intel-test.com',
    '78a1bc4f2e99d10a.dga-botnet.cc',
]


def generate_pcap(
    output_path: str = 'test_dpi.pcap',
    target_packets: int = 1500,
    sync_to_backend: bool = True
) -> int:
    """Generate a test PCAP file with approximately `target_packets` packets."""
    print(f"[*] Generating PCAP file: {output_path}")
    print(f"[*] Target packet count: {target_packets}")

    writer = PCAPWriter(output_path)

    user_mac = '00:11:22:33:44:55'
    gateway_mac = 'aa:bb:cc:dd:ee:ff'
    server_mac = 'aa:bb:cc:dd:ee:ff'
    attacker_mac = '00:11:22:33:44:99'

    user_ip = '192.168.1.100'
    blocked_ip = '192.168.1.50'
    scanner_ip = '10.0.0.88'
    brute_force_ip = '198.51.100.23'
    ddos_victim_ip = '192.168.1.200'
    dns_server = '8.8.8.8'

    seq_base = 10000

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 1: TLS Connections (Full handshakes + bidirectional data chunks)
    # ─────────────────────────────────────────────────────────────────────────
    tls_rounds = max(1, (target_packets // 2) // (len(TLS_DOMAINS) * 12)) + 1
    for round_idx in range(tls_rounds):
        for dst_ip, sni, dst_port in TLS_DOMAINS:
            if writer.packet_count >= int(target_packets * 0.65):
                break

            src_port = random.randint(49152, 65535)
            c_seq = seq_base + 1
            s_seq = seq_base + 50000

            # 1. TCP SYN (Client -> Server)
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, c_seq, 0, 0x02)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            c_seq += 1

            # 2. TCP SYN-ACK (Server -> Client)
            eth = create_ethernet_header(server_mac, user_mac)
            tcp = create_tcp_header(dst_port, src_port, s_seq, c_seq, 0x12)
            ip = create_ip_header(dst_ip, user_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            s_seq += 1

            # 3. TCP ACK (Client -> Server)
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, c_seq, s_seq, 0x10)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

            # 4. TLS Client Hello with SNI (Client -> Server)
            tls_hello = create_tls_client_hello(sni)
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, c_seq, s_seq, 0x18)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(tls_hello))
            writer.write_packet(eth + ip + tcp + tls_hello)
            c_seq += len(tls_hello)

            # 5. TLS Server Hello / Handshake (Server -> Client)
            tls_s_hello = create_tls_server_hello()
            eth = create_ethernet_header(server_mac, user_mac)
            tcp = create_tcp_header(dst_port, src_port, s_seq, c_seq, 0x18)
            ip = create_ip_header(dst_ip, user_ip, 6, len(tcp) + len(tls_s_hello))
            writer.write_packet(eth + ip + tcp + tls_s_hello)
            s_seq += len(tls_s_hello)

            # 6. Client Finished ACK
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, c_seq, s_seq, 0x10)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

            # 7-16. Bidirectional TLS Application Data chunks (Simulate realistic web streaming / API calls)
            data_chunks = random.randint(6, 16)
            for chunk_i in range(data_chunks):
                if chunk_i % 2 == 0:
                    # Client sends data
                    app_data = create_tls_app_data(random.randint(80, 450))
                    eth = create_ethernet_header(user_mac, gateway_mac)
                    tcp = create_tcp_header(src_port, dst_port, c_seq, s_seq, 0x18)
                    ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(app_data))
                    writer.write_packet(eth + ip + tcp + app_data)
                    c_seq += len(app_data)
                else:
                    # Server sends response data
                    app_data = create_tls_app_data(random.randint(180, 1100))
                    eth = create_ethernet_header(server_mac, user_mac)
                    tcp = create_tcp_header(dst_port, src_port, s_seq, c_seq, 0x18)
                    ip = create_ip_header(dst_ip, user_ip, 6, len(tcp) + len(app_data))
                    writer.write_packet(eth + ip + tcp + app_data)
                    s_seq += len(app_data)

            # Close connection cleanly: FIN-ACK
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, c_seq, s_seq, 0x11)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

            eth = create_ethernet_header(server_mac, user_mac)
            tcp = create_tcp_header(dst_port, src_port, s_seq, c_seq + 1, 0x10)
            ip = create_ip_header(dst_ip, user_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

            seq_base += 100000

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 2: HTTP Web Traffic (Benign browsing + Web application attacks)
    # ─────────────────────────────────────────────────────────────────────────
    for _ in range(4):
        for dst_ip, host, dst_port, path, method, ua in HTTP_SERVICES:
            if writer.packet_count >= int(target_packets * 0.78):
                break

            src_port = random.randint(49152, 65535)
            c_seq = seq_base + 1
            s_seq = seq_base + 20000

            # TCP Handshake (SYN, SYN-ACK, ACK)
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, c_seq, 0, 0x02)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            c_seq += 1

            eth = create_ethernet_header(server_mac, user_mac)
            tcp = create_tcp_header(dst_port, src_port, s_seq, c_seq, 0x12)
            ip = create_ip_header(dst_ip, user_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
            s_seq += 1

            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, c_seq, s_seq, 0x10)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

            # HTTP Request
            http_req = create_http_request(host, path=path, method=method, user_agent=ua)
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, c_seq, s_seq, 0x18)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(http_req))
            writer.write_packet(eth + ip + tcp + http_req)
            c_seq += len(http_req)

            # HTTP Response
            http_resp = create_http_response()
            eth = create_ethernet_header(server_mac, user_mac)
            tcp = create_tcp_header(dst_port, src_port, s_seq, c_seq, 0x18)
            ip = create_ip_header(dst_ip, user_ip, 6, len(tcp) + len(http_resp))
            writer.write_packet(eth + ip + tcp + http_resp)
            s_seq += len(http_resp)

            # Client ACK
            eth = create_ethernet_header(user_mac, gateway_mac)
            tcp = create_tcp_header(src_port, dst_port, c_seq, s_seq, 0x10)
            ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

            seq_base += 50000

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 3: DNS Queries and Responses (UDP 53)
    # ─────────────────────────────────────────────────────────────────────────
    for _ in range(3):
        for domain in DNS_DOMAINS:
            if writer.packet_count >= int(target_packets * 0.88):
                break

            src_port = random.randint(49152, 65535)
            txid, dns_query = create_dns_query(domain)

            # Query (Client -> DNS Server)
            eth = create_ethernet_header(user_mac, gateway_mac)
            udp = create_udp_header(src_port, 53, len(dns_query))
            ip = create_ip_header(user_ip, dns_server, 17, len(udp) + len(dns_query))
            writer.write_packet(eth + ip + udp + dns_query)

            # Response (DNS Server -> Client)
            fake_ip = f"93.184.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dns_resp = create_dns_response(domain, txid, fake_ip)
            eth = create_ethernet_header(gateway_mac, user_mac)
            udp = create_udp_header(53, src_port, len(dns_resp))
            ip = create_ip_header(dns_server, user_ip, 17, len(udp) + len(dns_resp))
            writer.write_packet(eth + ip + udp + dns_resp)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 4: Blocked IP Traffic (192.168.1.50)
    # ─────────────────────────────────────────────────────────────────────────
    blocked_targets = ['142.250.185.206', '104.244.42.65', '157.240.1.35', '172.217.0.100', '8.8.8.8']
    for i in range(25):
        dst_ip = random.choice(blocked_targets)
        src_port = random.randint(49152, 65535)
        dst_port = random.choice([80, 443, 8080, 53])

        eth = create_ethernet_header('00:11:22:33:44:56', gateway_mac)
        if dst_port == 53:
            _, dns_data = create_dns_query('www.blocked-test.org')
            udp = create_udp_header(src_port, 53, len(dns_data))
            ip = create_ip_header(blocked_ip, dst_ip, 17, len(udp) + len(dns_data))
            writer.write_packet(eth + ip + udp + dns_data)
        else:
            tcp = create_tcp_header(src_port, dst_port, seq_base + i * 100, 0, 0x02)
            ip = create_ip_header(blocked_ip, dst_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 5: Port Scan Reconnaissance (SYN scan from single source)
    # ─────────────────────────────────────────────────────────────────────────
    scan_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
        8000, 8080, 8443, 8888, 9200, 27017
    ]
    scan_target = '192.168.1.10'
    for port in scan_ports:
        src_p = random.randint(40000, 60000)
        # Probe: SYN
        eth = create_ethernet_header(attacker_mac, gateway_mac)
        tcp = create_tcp_header(src_p, port, random.randint(1000, 999999), 0, 0x02)
        ip = create_ip_header(scanner_ip, scan_target, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        # Target replies with RST/ACK for closed ports or SYN-ACK for open ports
        if port in (80, 443, 22):
            eth = create_ethernet_header(server_mac, attacker_mac)
            tcp = create_tcp_header(port, src_p, random.randint(1000, 999999), 1, 0x12)
            ip = create_ip_header(scan_target, scanner_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)
        else:
            eth = create_ethernet_header(server_mac, attacker_mac)
            tcp = create_tcp_header(port, src_p, 0, 1, 0x14)  # RST-ACK
            ip = create_ip_header(scan_target, scanner_ip, 6, len(tcp))
            writer.write_packet(eth + ip + tcp)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 6: SSH Brute Force Attacks (Port 22 bursts)
    # ─────────────────────────────────────────────────────────────────────────
    ssh_target = '192.168.1.25'
    for attempt in range(12):
        s_port = random.randint(45000, 65000)
        eth = create_ethernet_header(attacker_mac, gateway_mac)
        tcp = create_tcp_header(s_port, 22, attempt * 1000 + 1, 0, 0x02)
        ip = create_ip_header(brute_force_ip, ssh_target, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        # Simulated SSH banner attempt payload
        ssh_payload = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        eth = create_ethernet_header(attacker_mac, gateway_mac)
        tcp = create_tcp_header(s_port, 22, attempt * 1000 + 2, 100, 0x18)
        ip = create_ip_header(brute_force_ip, ssh_target, 6, len(tcp) + len(ssh_payload))
        writer.write_packet(eth + ip + tcp + ssh_payload)

        # Target resets connection
        eth = create_ethernet_header(server_mac, attacker_mac)
        tcp = create_tcp_header(22, s_port, 0, attempt * 1000 + 2 + len(ssh_payload), 0x14)
        ip = create_ip_header(ssh_target, brute_force_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 7: DDoS / UDP Flood Burst
    # ─────────────────────────────────────────────────────────────────────────
    for flood_i in range(60):
        spoofed_src = f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}"
        src_p = random.randint(1024, 65535)
        flood_payload = bytes([random.randint(65, 90) for _ in range(64)])

        eth = create_ethernet_header(attacker_mac, gateway_mac)
        udp = create_udp_header(src_p, 80, len(flood_payload))
        ip = create_ip_header(spoofed_src, ddos_victim_ip, 17, len(udp) + len(flood_payload))
        writer.write_packet(eth + ip + udp + flood_payload, dt=0.0001)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 8: Health Check & Network Probes (TCP Port 53 / 80 / 443 probes)
    # ─────────────────────────────────────────────────────────────────────────
    for probe_seq in range(1, 16):
        src_p = random.randint(50000, 60000)
        # Probe SYN to 8.8.8.8:53
        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_p, 53, probe_seq * 1000, 0, 0x02)
        ip = create_ip_header(user_ip, '8.8.8.8', 6, len(tcp))
        writer.write_packet(eth + ip + tcp, dt=0.01)

        # SYN-ACK response
        eth = create_ethernet_header(gateway_mac, user_mac)
        tcp = create_tcp_header(53, src_p, probe_seq * 5000, probe_seq * 1000 + 1, 0x12)
        ip = create_ip_header('8.8.8.8', user_ip, 6, len(tcp), ttl=118)
        writer.write_packet(eth + ip + tcp, dt=0.01)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 9: Fill remaining to reach exact target range if needed
    # ─────────────────────────────────────────────────────────────────────────
    filler_domains = [d for d in TLS_DOMAINS if d[1] != 'www.youtube.com']
    while writer.packet_count < target_packets:
        dst_ip, sni, dst_port = random.choice(filler_domains)
        src_port = random.randint(49152, 65535)
        c_seq = random.randint(100000, 9999999)

        # Client Hello
        tls_data = create_tls_client_hello(sni)
        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, c_seq, 1000, 0x18)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(tls_data))
        writer.write_packet(eth + ip + tcp + tls_data)

        if writer.packet_count >= target_packets:
            break

        # Follow-up application data
        app_data = create_tls_app_data(random.randint(100, 500))
        eth = create_ethernet_header(server_mac, user_mac)
        tcp = create_tcp_header(dst_port, src_port, 1000, c_seq + len(tls_data), 0x18)
        ip = create_ip_header(dst_ip, user_ip, 6, len(tcp) + len(app_data))
        writer.write_packet(eth + ip + tcp + app_data)

    writer.close()
    final_count = writer.packet_count
    file_size_kb = os.path.getsize(output_path) / 1024.0

    print(f"[✓] Created {output_path} successfully!")
    print(f"    - Total Packets : {final_count}")
    print(f"    - File Size     : {file_size_kb:.1f} KB")

    # Sync to backend upload directory if requested
    if sync_to_backend:
        backend_dest = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '..', 'backend', 'data', 'uploads', os.path.basename(output_path))
        )
        if os.path.exists(os.path.dirname(backend_dest)):
            try:
                shutil.copy2(output_path, backend_dest)
                print(f"[✓] Synced {final_count} packets to backend: {backend_dest}")
            except Exception as e:
                print(f"[!] Note: Could not sync to backend ({e})")

    return final_count


def main():
    parser = argparse.ArgumentParser(
        description="Generate test PCAP with configurable packet counts (1000-2000+) for DPI & SIEM analysis"
    )
    parser.add_argument(
        '-n', '--count', '--packets',
        dest='packets',
        type=int,
        default=1500,
        help="Target number of packets to generate (default: 1500, recommend 1000-2000)"
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='test_dpi.pcap',
        help="Output PCAP filename (default: test_dpi.pcap)"
    )
    parser.add_argument(
        '--no-sync',
        action='store_true',
        help="Do not sync output to backend/data/uploads/"
    )

    args = parser.parse_args()

    # If relative path, ensure we run inside Packet_analyzer directory if appropriate
    generate_pcap(
        output_path=args.output,
        target_packets=args.packets,
        sync_to_backend=not args.no_sync
    )


if __name__ == '__main__':
    main()
