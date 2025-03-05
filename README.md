# Tinyshark

**Lightweight CLI Packet Sniffer with Multi-threading**

This Python script is a **multi-threaded packet sniffer** designed to capture and process Ethernet, IP, TCP, and
UDP packets. It utilizes raw sockets for live packet capture and uses the `threading` module to handle packet
sniffing and processing concurrently, making it fast and responsive.

### Features:
1. **Multi-threaded design**: Separate threads are dedicated to capturing and processing packets.
2. **Live packet sniffing**: No logging or file storage — just live traffic analysis.
3. **Command-line filters**:
   - Filter by protocol (TCP/UDP).
   - Filter by IP address.
   - Filter by port number.
4. **Real-time packet summary**: Displays live network traffic on the terminal.

### Technical Details:
- **Programming language**: Python
- **Packet types captured**: Ethernet, IP, TCP, UDP
- **Concurrency**: Uses threading for fast and responsive packet handling

---
