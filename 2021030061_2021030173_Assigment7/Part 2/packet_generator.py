from scapy.all import *
from datetime import datetime
import base64

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
student_name = "NAME"
student_id = "ID"
output_file = "snort/lab/custom_packets.pcap"
packets = []

# 1. Student's Packet
student_packet = IP(src="192.168.0.100", dst="192.168.1.1") / TCP(dport=54321) / Raw(load=f"{student_name}-{student_id} {timestamp}")
packets.append(student_packet)

# 2. 10 Port Scan Packets
services_ports = {
    "HTTP": 80, "HTTPS": 443, "SSH": 22, "TELNET": 23, "FTP": 21,
    "DNS": 53, "RTSP": 554, "SQL": 1433, "RDP": 3389, "MQTT": 1883
}
for service, port in services_ports.items():
    port_scan_packet = IP(src="192.168.0.101", dst="192.168.1.2") / TCP(dport=port) / Raw(load=f"{student_name}-{student_id} {timestamp}")
    packets.append(port_scan_packet)

# 3. 5 Base64 Malicious Packets
malicious_payload = base64.b64encode(student_id.encode()).decode()
for _ in range(5):
    malicious_packet = IP(src="192.168.0.102", dst="192.168.1.3") / TCP(dport=8080) / Raw(load=malicious_payload)
    packets.append(malicious_packet)

# 4. DNS Suspicious Domain Packet
dns_packet = IP(src="192.168.0.103", dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="malicious.example.com"))
packets.append(dns_packet)

# 5. Ping Test Packet
ping_packet = IP(src="192.168.0.104", dst="192.168.1.4") / ICMP() / Raw(load="PingTest-2024")
packets.append(ping_packet)

# Save all packets to the PCAP file
wrpcap(output_file, packets)

print(f"Packets have been created and saved to {output_file}")

