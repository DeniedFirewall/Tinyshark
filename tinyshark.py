import socket
import struct
import argparse
from rich import print  # For colored output

# Parse Ethernet Header
def parse_ethernet_header(data):
    dest_mac, src_mac, eth_type = struct.unpack("!6s6sH", data[:14])
    return format_mac(dest_mac), format_mac(src_mac), eth_type, data[14:]

# Format MAC Address
def format_mac(mac):
    return ":".join(map("{:02x}".format, mac))

# Parse IP Header
def parse_ip_header(data):
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version = ip_header[0] >> 4
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    protocol = ip_header[6]
    return version, src_ip, dst_ip, protocol, data[20:]

# Parse TCP Header
def parse_tcp_header(data):
    src_port, dst_port = struct.unpack("!HH", data[:4])
    return src_port, dst_port

# Parse UDP Header
def parse_udp_header(data):
    src_port, dst_port = struct.unpack("!HH", data[:4])
    return src_port, dst_port

# Packet Sniffing Function
def sniff(interface, filter_protocol=None, filter_ip=None, filter_port=None):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # Linux only
        sock.bind((interface, 0))

        print(f"[green]Sniffing on {interface}... (Press Ctrl+C to stop)[/green]\n")

        while True:
            raw_data, _ = sock.recvfrom(65535)
            dest_mac, src_mac, eth_type, payload = parse_ethernet_header(raw_data)

            if eth_type == 0x0800:  # IPv4
                version, src_ip, dst_ip, protocol, payload = parse_ip_header(payload)

                # TCP Packet
                if protocol == 6:
                    src_port, dst_port = parse_tcp_header(payload)
                    if not filter_protocol or filter_protocol.lower() == "tcp":
                        if (not filter_ip or filter_ip in (src_ip, dst_ip)) and (not filter_port or filter_port in (src_port, dst_port)):
                            print(f"[cyan][TCP][/cyan] {src_ip}:{src_port} → {dst_ip}:{dst_port}")

                # UDP Packet
                elif protocol == 17:
                    src_port, dst_port = parse_udp_header(payload)
                    if not filter_protocol or filter_protocol.lower() == "udp":
                        if (not filter_ip or filter_ip in (src_ip, dst_ip)) and (not filter_port or filter_port in (src_port, dst_port)):
                            print(f"[yellow][UDP][/yellow] {src_ip}:{src_port} → {dst_ip}:{dst_port}")

    except KeyboardInterrupt:
        print("\n[red]Stopping packet sniffing...[/red]")
    except PermissionError:
        print("\n[red]Permission denied! Run as root (sudo).[/red]")

# Command-Line Argument Parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight CLI Packet Sniffer")
    parser.add_argument("--interface", type=str, required=True, help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("--protocol", type=str, choices=["tcp", "udp"], help="Filter by protocol")
    parser.add_argument("--ip", type=str, help="Filter by source or destination IP")
    parser.add_argument("--port", type=int, help="Filter by source or destination port")
    
    args = parser.parse_args()
    sniff(args.interface, args.protocol, args.ip, args.port)
