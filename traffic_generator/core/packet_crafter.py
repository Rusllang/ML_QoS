from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import yaml
import threading

class TrafficGenerator:
    def __init__(self, scenario_path: str):
        with open(scenario_path) as f:
            self.scenarios = yaml.safe_load(f)
        self._stop_event = threading.Event()

    def _generate_voip(self, params: dict):
        while not self._stop_event.is_set():
            send(IP(dst=params['target_ip'])/UDP()/Raw(load="VOIP_PAYLOAD"), verbose=0)
            time.sleep(1/params['packet_rate'])

    def run_scenario(self, scenario_name: str):
        scenario = self.scenarios[scenario_name']
        threads = []
        for profile in scenario['profiles']:
            if profile['type'] == 'voip':
                t = threading.Thread(target=self._generate_voip, args=(profile,))
                t.start()
                threads.append(t)
        return threads