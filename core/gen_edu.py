import pandas as pd
import os
from parse import parse_pcap
from gen import (
    generate_normal_traffic,
    generate_syn_flood,
    generate_udp_flood,
    generate_icmp_flood,
    generate_ddos_attack
)

# === 1. Генерация pcap-файлов ===
print("Генерация pcap-трафика...")
generate_normal_traffic("pcaps/normal.pcap", packet_count=500)
generate_syn_flood("pcaps/syn_flood.pcap", packet_count=500)
generate_udp_flood("pcaps/udp_flood.pcap", packet_count=500)
generate_icmp_flood("pcaps/icmp_flood.pcap", packet_count=500)
generate_ddos_attack("pcaps/ddos.pcap", packet_count=1000)

# === 2. Парсинг pcap-файлов ===
print("Парсинг pcap-файлов...")
dfs = []
dfs.append(parse_pcap("pcaps/normal.pcap", label="normal"))
dfs.append(parse_pcap("pcaps/syn_flood.pcap", label="syn_flood"))
dfs.append(parse_pcap("pcaps/udp_flood.pcap", label="udp_flood"))
dfs.append(parse_pcap("pcaps/icmp_flood.pcap", label="icmp_flood"))
dfs.append(parse_pcap("pcaps/ddos.pcap", label="ddos"))

# === 3. Объединение и сохранение итогового датасета ===
print("Сохранение объединённого датасета...")
os.makedirs("parsed", exist_ok=True)
df_total = pd.concat(dfs, ignore_index=True)
df_total.to_csv("parsed/edu_dataset.csv", index=False)

print("Датасет успешно сохранён: parsed/edu_dataset.csv")