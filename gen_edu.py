import pandas as pd
from parser import parse_pcap
from gen import (
    generate_normal_traffic,
    generate_syn_flood,
    generate_udp_flood,
    generate_icmp_flood,
    generate_ddos_attack
)

# === 1. Генерация pcap файлов ===
generate_normal_traffic("pcaps/normal.pcap", packet_count=500)
generate_syn_flood("pcaps/syn_flood.pcap", packet_count=500)
generate_udp_flood("pcaps/udp_flood.pcap", packet_count=500)
generate_icmp_flood("pcaps/icmp_flood.pcap", packet_count=500)
generate_ddos_attack("pcaps/ddos.pcap", packet_count=1000)

# === 2. Парсинг ===
dfs = []
dfs.append(parse_pcap("pcaps/normal.pcap", label="normal"))
dfs.append(parse_pcap("pcaps/syn_flood.pcap", label="syn_flood"))
dfs.append(parse_pcap("pcaps/udp_flood.pcap", label="udp_flood"))
dfs.append(parse_pcap("pcaps/icmp_flood.pcap", label="icmp_flood"))
dfs.append(parse_pcap("pcaps/ddos.pcap", label="ddos"))

# === 3. Объединение и сохранение ===
df_total = pd.concat(dfs, ignore_index=True)
df_total.to_csv("dir_dataset.csv", index=False)

print("✅ Датасет успешно сгенерирован: parsed/traffic_dataset.csv")
