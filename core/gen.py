from scapy.all import IP, TCP, UDP, ICMP, wrpcap, RandShort
import random
import os

os.makedirs("pcaps", exist_ok=True)

def generate_normal_traffic(filename="pcaps/normal.pcap", packet_count=1000):
    packets = []
    for _ in range(packet_count):
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53, 123])
        pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=src_port, dport=dst_port, flags="PA") / b"GET / HTTP/1.1"
        packets.append(pkt)
    wrpcap(filename, packets)
    return filename

def generate_syn_flood(filename="pcaps/syn_flood.pcap", packet_count=100):
    packets = []
    for _ in range(packet_count):
        pkt = IP(src=f"10.0.0.{random.randint(2, 254)}", dst="192.168.1.1") / TCP(sport=RandShort(), dport=80, flags="S")
        packets.append(pkt)
    wrpcap(filename, packets)
    return filename

def generate_udp_flood(filename="pcaps/udp_flood.pcap", packet_count=100):
    packets = []
    for _ in range(packet_count):
        pkt = IP(src=f"10.0.0.{random.randint(2, 254)}", dst="192.168.1.1") / UDP(sport=RandShort(), dport=123) / ("X" * 1400)
        packets.append(pkt)
    wrpcap(filename, packets)
    return filename

def generate_icmp_flood(filename="pcaps/icmp_flood.pcap", packet_count=100):
    packets = []
    for _ in range(packet_count):
        pkt = IP(src=f"172.16.0.{random.randint(2, 254)}", dst="192.168.1.1") / ICMP()
        packets.append(pkt)
    wrpcap(filename, packets)
    return filename

def generate_ddos_attack(filename="pcaps/ddos.pcap", packet_count=1000):
    packets = []
    for _ in range(packet_count):
        src_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        protocol = random.choice(["TCP", "UDP", "ICMP"])

        if protocol == "TCP":
            pkt = IP(src=src_ip, dst="192.168.1.1") / TCP(sport=RandShort(), dport=random.choice([80, 443, 22]), flags="S")
        elif protocol == "UDP":
            pkt = IP(src=src_ip, dst="192.168.1.1") / UDP(sport=RandShort(), dport=random.choice([53, 123])) / ("X" * 1200)
        else:
            pkt = IP(src=src_ip, dst="192.168.1.1") / ICMP()
        packets.append(pkt)

    wrpcap(filename, packets)
    return filename

if __name__ == "__main__":
    print("Генерация трафика:")
    print("+", generate_normal_traffic())
    print("+", generate_syn_flood())
    print("+", generate_udp_flood())
    print("+", generate_icmp_flood())
    print("+", generate_ddos_attack())
