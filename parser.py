import pyshark
import pandas as pd

def parse_pcap(file_path: str, label: str) -> pd.DataFrame:
    capture = pyshark.FileCapture(file_path, use_json=True, include_raw=False)
    data = []

    prev_time = None
    for pkt in capture:
        try:
            protocol = pkt.transport_layer if hasattr(pkt, 'transport_layer') else 'OTHER'
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None
            src_port = pkt[pkt.transport_layer].srcport if protocol in pkt else None
            dst_port = pkt[pkt.transport_layer].dstport if protocol in pkt else None
            length = int(pkt.length)
            flags = pkt.tcp.flags if protocol == 'TCP' and hasattr(pkt, 'tcp') else None
            timestamp = float(pkt.sniff_timestamp)

            inter_arrival = None
            if prev_time is not None:
                inter_arrival = timestamp - prev_time
            prev_time = timestamp

            data.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'length': length,
                'flags': flags,
                'timestamp': timestamp,
                'inter_arrival': inter_arrival,
                'label': label
            })
        except Exception:
            continue  # пропускаем битые пакеты

    capture.close()
    return pd.DataFrame(data)


path = "normal_traffic.pcap"
tr_lab = "normal"

df = parse_pcap(path, label=tr_lab)

df.to_csv("normal.csv", index=False)

print(df.head())