#!/usr/bin/env python
"""
Synology NAS discovery via findhostd UDP broadcast (port 9999).
Compatible with Python 2 (DSM 6) and Python 3 (DSM 7).

Uses the syno_finder plaintext protocol (magic 0x12345678_SYNO).
Requires binding to UDP port 9999 on Windows to receive responses.
On Linux, findhostd blocks same-subnet queries, so this script is
intended to be run from a PC, not from a NAS.

Usage:
    python syno_discover.py
    python syno_discover.py --timeout 5
    python syno_discover.py --json
"""

from __future__ import print_function
import socket
import struct
import sys
import os
import json

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------
MAGIC        = b'\x12\x34\x56\x78\x53\x59\x4e\x4f'
BCAST_PORT   = 9999
BCAST_ADDR   = '255.255.255.255'
DEFAULT_TIMEOUT = 3

# Non-Synology MAC to use in 0x7c fields - findhostd ignores queries
# from Synology OUI MACs (00:11:32, 90:09:d0). VMware OUI works fine.
VMWARE_MAC   = b'00:50:56:c0:00:08'

# TLV pkt_ids (response fields we care about)
PKT_MAC        = 0x19  # NAS MAC address (17-byte ASCII)
PKT_IP         = 0x12  # NAS IP address (4 bytes big-endian)
PKT_HOSTNAME   = 0x11  # NAS hostname (ASCII string)
PKT_HTTP_PORT  = 0x75  # DSM HTTP port (4 bytes little-endian)
PKT_HTTPS_PORT = 0x76  # DSM HTTPS port (4 bytes little-endian)
PKT_DSM_BUILD  = 0x49  # DSM build number (4 bytes little-endian)
PKT_DSM_VER    = 0x77  # DSM version string (e.g. "7.3.2")
PKT_MODEL      = 0x78  # NAS model (e.g. "DS1821+")
PKT_PLATFORM   = 0x70  # Platform/codename
PKT_SERIAL     = 0xc0  # Serial number (ASCII string)


def make_tlv(pkt_id, data):
    """Build a TLV: 1-byte id + 1-byte length + data bytes."""
    length = min(len(data), 0xff)
    if sys.version_info[0] >= 3:
        return bytes([pkt_id, length]) + data[:length]
    else:
        return chr(pkt_id) + chr(length) + data[:length]


def build_query():
    """
    Build the plaintext discovery query packet.

    Key findings from Wireshark reverse engineering:
    - Packet type 0x01 field must be \x00\x00\x00\x01 (not \x00\x00\x00\x00)
    - Must include four 0x7c MAC fields
    - MAC in 0x7c must be a non-Synology OUI or findhostd ignores it
    - Synology Assistant sends pkt1 (type=0x00) then pkt2 (type=0x01);
      NAS only respond to pkt2
    """
    pkt  = MAGIC
    pkt += make_tlv(0xa4, b'\x00\x00\x02\x01')
    pkt += make_tlv(0xa6, b'\x78\x00\x00\x00')
    pkt += make_tlv(0x01, b'\x01\x00\x00\x00')   # type=1, little-endian
    pkt += make_tlv(0xb0, b'\xc0\x01\x00\x00\x00\x00\x00\x00')
    pkt += make_tlv(0xb1, b'\x00\x00\x00\x00\x00\x00\x00\x00')
    pkt += make_tlv(0xb8, b'\xc0\x01\x00\x00\x00\x00\x00\x00')
    pkt += make_tlv(0xb9, b'\x00\x00\x00\x00\x00\x00\x00\x00')
    pkt += make_tlv(0x7c, VMWARE_MAC)
    pkt += make_tlv(0x7c, VMWARE_MAC)
    pkt += make_tlv(0x7c, VMWARE_MAC)
    pkt += make_tlv(0x7c, VMWARE_MAC)
    return pkt


def parse_response(data):
    """
    Parse a findhostd plaintext response packet.
    Returns a dict of fields, or None if the magic is wrong.
    """
    if len(data) < 8:
        return None
    if data[:8] != MAGIC:
        return None

    result = {}
    pos = 8
    while pos + 1 < len(data):
        if sys.version_info[0] >= 3:
            pkt_id = data[pos]
            length = data[pos + 1]
        else:
            pkt_id = ord(data[pos])
            length = ord(data[pos + 1])
        pos += 2
        if pos + length > len(data):
            break
        value = data[pos:pos + length]
        pos += length

        if pkt_id == PKT_HOSTNAME:
            result['hostname'] = value.decode('utf-8', errors='replace')

        elif pkt_id == PKT_MAC:
            result['mac'] = value.decode('ascii', errors='replace')

        elif pkt_id == PKT_IP:
            if len(value) == 4:
                if sys.version_info[0] >= 3:
                    result['ip'] = '%d.%d.%d.%d' % (
                        value[0], value[1], value[2], value[3])
                else:
                    result['ip'] = '%d.%d.%d.%d' % (
                        ord(value[0]), ord(value[1]),
                        ord(value[2]), ord(value[3]))

        elif pkt_id == PKT_HTTP_PORT:
            if len(value) == 4:
                result['http_port'] = struct.unpack('<I', value)[0]

        elif pkt_id == PKT_HTTPS_PORT:
            if len(value) == 4:
                result['https_port'] = struct.unpack('<I', value)[0]

        elif pkt_id == PKT_DSM_VER:
            # Strip trailing non-printable bytes (e.g. 0x90 build separator)
            ver = value.decode('ascii', errors='replace')
            if sys.version_info[0] >= 3:
                result['dsm_version'] = ''.join(
                    c for c in ver if c.isprintable() and ord(c) < 128)
            else:
                result['dsm_version'] = ''.join(
                    c for c in ver if 0x20 <= ord(c) < 0x80)

        elif pkt_id == PKT_DSM_BUILD:
            if len(value) == 4:
                result['dsm_build'] = struct.unpack('<I', value)[0]

        elif pkt_id == PKT_MODEL:
            result['model'] = value.decode('utf-8', errors='replace')

        elif pkt_id == PKT_PLATFORM:
            result['platform'] = value.decode('utf-8', errors='replace')

        elif pkt_id == PKT_SERIAL:
            result['serial'] = value.decode('ascii', errors='replace')

    return result if result else None


def discover(timeout=DEFAULT_TIMEOUT):
    """
    Broadcast a discovery query and collect responses.
    Returns a list of dicts, one per responding NAS.
    Deduplicates by MAC address (each NAS sends 2 responses).
    """
    query = build_query()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(('0.0.0.0', BCAST_PORT))
    except Exception as e:
        sys.stderr.write('WARNING: Could not bind to port %d: %s\n' % (BCAST_PORT, e))
        try:
            sock.bind(('0.0.0.0', 0))  # random port - may still work on Linux
            sys.stderr.write('WARNING: Bound to random port instead.\n')
        except Exception:
            pass

    sock.settimeout(timeout)

    try:
        sock.sendto(query, (BCAST_ADDR, BCAST_PORT))
    except Exception as e:
        sys.stderr.write('ERROR: Failed to send broadcast: %s\n' % e)
        sock.close()
        return []

    seen_macs = set()
    results = []

    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            break
        except Exception as e:
            sys.stderr.write('WARNING: recvfrom error: %s\n' % e)
            break

        parsed = parse_response(data)
        if parsed is None:
            continue

        # Deduplicate - each NAS sends 2 responses (broadcast + unicast)
        mac = parsed.get('mac', addr[0])
        if mac in seen_macs:
            continue
        seen_macs.add(mac)

        # Use source IP from UDP packet if not in payload
        if 'ip' not in parsed:
            parsed['ip'] = addr[0]

        # Default ports if not present
        parsed.setdefault('http_port', 5000)
        parsed.setdefault('https_port', 5001)

        results.append(parsed)

    sock.close()

    # Sort by IP for consistent output
    results.sort(key=lambda x: tuple(
        int(o) for o in x.get('ip', '0.0.0.0').split('.')))
    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Discover Synology NAS on local network.')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='Seconds to wait for responses (default: %d)' % DEFAULT_TIMEOUT)
    parser.add_argument('--json', action='store_true',
                        help='Output as JSON')
    args = parser.parse_args()

    nas_list = discover(timeout=args.timeout)

    if args.json:
        print(json.dumps(nas_list, indent=2))
        return

    if not nas_list:
        print('No Synology NAS found.')
        return

    print('Found %d Synology NAS:\n' % len(nas_list))
    #fmt = '%-20s %-17s %-16s %-6s %-6s %s'
    #fmt = '%-12s %-19s %-15s %-5s %-5s %s'
    fmt = '%-15s %-19s %-17s %-6s %-6s %s'
    print(fmt % ('Hostname', 'MAC', 'IP', 'HTTP', 'HTTPS', 'Model'))
    print('' + '-' * 79)
    for nas in nas_list:
        print(fmt % (
            nas.get('hostname', '?'),
            nas.get('mac', '?'),
            nas.get('ip', '?'),
            nas.get('http_port', '?'),
            nas.get('https_port', '?'),
            nas.get('model', '?'),
        ))
        #if 'dsm_version' in nas:
        #    build = nas.get('dsm_build', '')
        #    print('  %s DSM %s%s' % (
        #        ' ' * 20,
        #        nas['dsm_version'],
        #        (' build %s' % build) if build else ''
        #    ))
    print()


if __name__ == '__main__':
    main()
