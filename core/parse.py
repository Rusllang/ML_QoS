import argparse
import os
import pandas as pd
import pyshark

def parse_pcap(file_path: str, label: str) -> pd.DataFrame:
    import pyshark
    import pandas as pd

    capture = pyshark.FileCapture(file_path, use_json=True, include_raw=False)
    data = []
    prev_time = None

    for pkt in capture:
        try:
            # Общая информация
            timestamp = float(pkt.sniff_timestamp)
            inter_arrival = timestamp - prev_time if prev_time is not None else None
            prev_time = timestamp

            protocol = pkt.transport_layer if hasattr(pkt, 'transport_layer') else 'OTHER'
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None

            # Безопасная обработка портов
            src_port = dst_port = None
            if protocol == 'TCP' and hasattr(pkt, 'tcp'):
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                flags = pkt.tcp.flags
            elif protocol == 'UDP' and hasattr(pkt, 'udp'):
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport
                flags = None
            else:
                flags = None

            length = int(pkt.length)

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

        except Exception as e:
            # Если нужно отладить: print(f"Ошибка в пакете: {e}")
            continue

    capture.close()
    return pd.DataFrame(data)

def parse_generic_pcap(file_path: str) -> pd.DataFrame:
    """
    Универсальный парсер pcap-файлов без метки.
    Подходит для анализа любых PCAP, включая миксы или неизвестные форматы.
    """
    import pyshark
    import pandas as pd

    capture = pyshark.FileCapture(file_path, use_json=True, include_raw=False)
    data = []
    prev_time = None

    for pkt in capture:
        try:
            timestamp = float(pkt.sniff_timestamp)
            inter_arrival = timestamp - prev_time if prev_time is not None else None
            prev_time = timestamp

            protocol = pkt.transport_layer if hasattr(pkt, 'transport_layer') else 'OTHER'
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None

            src_port = dst_port = flags = None
            if protocol == 'TCP' and hasattr(pkt, 'tcp'):
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                flags = pkt.tcp.flags
            elif protocol == 'UDP' and hasattr(pkt, 'udp'):
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport
            elif protocol == 'ICMP':
                pass  # ICMP не использует порты

            length = int(pkt.length)

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
            })

        except Exception:
            continue

    capture.close()
    return pd.DataFrame(data)


def main():
    parser = argparse.ArgumentParser(description="Парсинг pcap-файлов с метками класса трафика")
    parser.add_argument('--normal_traffic', action='store_true', help='PCAP-файл: normal.pcap')
    parser.add_argument('--syn_flood', action='store_true', help='PCAP-файл: syn_flood.pcap')
    parser.add_argument('--udp_flood', action='store_true', help='PCAP-файл: udp_flood.pcap')
    parser.add_argument('--icmp_flood', action='store_true', help='PCAP-файл: icmp_flood.pcap')
    parser.add_argument('--ddos', action='store_true', help='PCAP-файл: ddos.pcap')
    parser.add_argument('--all', action='store_true', help='Парсить все доступные типы трафика')

    args = parser.parse_args()

    traffic_types = {
        'normal_traffic': ('pcaps/normal.pcap', 'normal'),
        'syn_flood': ('pcaps/syn_flood.pcap', 'syn_flood'),
        'udp_flood': ('pcaps/udp_flood.pcap', 'udp_flood'),
        'icmp_flood': ('pcaps/icmp_flood.pcap', 'icmp_flood'),
        'ddos': ('pcaps/ddos.pcap', 'ddos'),
        'wireshark' : ('pcaps/wireshark.pcap','')
    }

    os.makedirs("parsed", exist_ok=True)

    if args.all:
        selected = traffic_types.items()
    else:
        selected = [(key, traffic_types[key]) for key in traffic_types if getattr(args, key)]

    if not selected:
        print("Не указано ни одного источника. Используй --all или отдельные флаги.")
        return

    for key, (file_path, label) in selected:
        print(f"Парсинг {file_path} → label: {label}")
        df = parse_pcap(file_path, label)
        out_path = f"parsed/{label}.csv"
        df.to_csv(out_path, index=False)
        print(f"Сохранено: {out_path}")

if __name__ == '__main__':
    main()
