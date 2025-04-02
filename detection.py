from scapy.all import sniff, sendp, getmacbyip, conf, ARP, IP, TCP, UDP, srp, Ether
from scapy.arch.windows import get_windows_if_list
import pandas as pd
import joblib
import time
import threading
import sys
import warnings
from ipaddress import IPv4Network
from threading import Thread
from contextlib import contextmanager
from joblib import parallel_backend, Parallel
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

@contextmanager
def suppress_output():
    """Context manager para suprimir salidas no deseadas"""
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            with parallel_backend('threading', n_jobs=1):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    yield
        finally:
            sys.stdout = old_stdout

class RealTimeDetector:
    def __init__(self, debug=False):
        self.gateway_ip = conf.route.route("0.0.0.0")[2]
        self.model = self._load_model("network_model.pkl")
        self.iface = self._get_network_interface()
        self.local_ips = self._get_local_ips()
        self.forwarding = True
        self.active_ips = []
        self.network = self._get_network_info()
        self.mac_cache = {}
        self.debug = debug
        self.expected_columns = ['hour', 'sport', 'dport', 'length', 'local_ip',
                               'proto_2', 'proto_6', 'proto_17', 'payload_ratio']
        
        # Configuración de detección
        self.whitelist_ports = {80, 443, 53, 67, 68}
        self.MIN_PACKET_LENGTH = 128
        self.alert_cooldown = {}
        self.cooldown_time = 30
        self.local_network = "192.168.1.0/24"
        self.ANOMALY_THRESHOLD = -0.5

    def _load_model(self, model_path):
        """Carga el modelo suprimiendo salidas no deseadas"""
        try:
            with suppress_output():
                model_data = joblib.load(model_path)
            
            if isinstance(model_data, dict):
                return model_data['model']
            return model_data
            
        except Exception as e:
            print(f"[!] Error cargando el modelo: {str(e)}")
            sys.exit(1)

    def _get_network_info(self):
        try:
            return IPv4Network(f"{self.gateway_ip}/24", strict=False)
        except Exception as e:
            print(f"[!] Error obteniendo información de red: {str(e)}")
            return None

    def _get_network_interface(self):
        try:
            interfaces = get_windows_if_list()
            print("\n[+] Interfaces de red disponibles:")
            for i, iface in enumerate(interfaces):
                print(f"    {i+1}. {iface['name']} - IPs: {iface.get('ips', ['N/A'])}")
            
            for iface in interfaces:
                if any('.' in ip for ip in iface.get('ips', [])):
                    print(f"\n[+] Seleccionada interfaz: {iface['name']}")
                    return iface['name']
            
            return conf.iface.name
        except Exception as e:
            print(f"[!] Error seleccionando interfaz: {str(e)}")
            return conf.iface.name

    def _get_local_ips(self):
        try:
            interfaces = get_windows_if_list()
            for iface in interfaces:
                if iface['name'] == self.iface:
                    return [ip for ip in iface.get('ips', []) if '.' in ip]
            return [self.gateway_ip]
        except Exception as e:
            return [self.gateway_ip]

    def _discover_active_hosts(self):
        try:
            if not self.network:
                print("[!] No se pudo determinar la red para escanear")
                return

            print(f"\n[+] Escaneando red {self.network} en {self.iface}")
            all_ips = [str(ip) for ip in self.network.hosts()]
            
            chunk_size = 50
            ip_chunks = [all_ips[i:i + chunk_size] for i in range(0, len(all_ips), chunk_size)]
            
            threads = []
            results = []

            def arp_scan(ip_list):
                answered, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_list),
                    timeout=2,
                    iface=self.iface,
                    verbose=0,
                    retry=1
                )
                results.extend([rcv[ARP].psrc for _, rcv in answered])

            for chunk in ip_chunks:
                t = Thread(target=arp_scan, args=(chunk,))
                t.start()
                threads.append(t)

            for t in threads:
                t.join()

            self.active_ips = list(set(results))
            
            print(f"\n[+] Escaneo completado")
            print(f"    Hosts activos detectados ({len(self.active_ips)}):")
            for ip in self.active_ips:
                print(f"        • {ip}")

        except Exception as e:
            print(f"[!] Error en escaneo ARP: {str(e)}")
            self.active_ips = []

    def _get_mac(self, ip):
        if ip in self.mac_cache:
            return self.mac_cache[ip]
        
        mac = getmacbyip(ip)
        if not mac:
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                timeout=2,
                iface=self.iface,
                verbose=0
            )
            if answered:
                mac = answered[0][1].hwsrc
        if mac:
            self.mac_cache[ip] = mac
        return mac

    def _arp_spoof(self, target_ip):
        try:
            if target_ip == self.gateway_ip:
                return

            target_mac = self._get_mac(target_ip)
            gateway_mac = self._get_mac(self.gateway_ip)
            
            if not target_mac or not gateway_mac:
                return
            
            sendp(
                Ether(dst=target_mac) / ARP(
                    op=2, 
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=self.gateway_ip
                ),
                iface=self.iface,
                verbose=0
            )
            
            sendp(
                Ether(dst=gateway_mac) / ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=gateway_mac,
                    psrc=target_ip
                ),
                iface=self.iface,
                verbose=0
            )
            
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error ARP: {str(e)}")

    def _packet_handler(self, pkt):
        try:
            if pkt.haslayer(IP):
                self._process_features(pkt)
                self._forward_packet(pkt)
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Packet error: {str(e)}")

    def _forward_packet(self, pkt):
        if self.forwarding and pkt[IP].src not in self.local_ips:
            sendp(pkt, iface=self.iface, verbose=0)

    def _process_features(self, pkt):
        ip = pkt[IP]
        
        # Filtrado básico
        if ip.dport in self.whitelist_ports or ip.sport in self.whitelist_ports:
            return
            
        if len(pkt) < self.MIN_PACKET_LENGTH:
            return
            
        if IPv4Network(self.local_network, strict=False).overlaps(IPv4Network(f"{ip.src}/32", strict=False)) and \
           IPv4Network(self.local_network, strict=False).overlaps(IPv4Network(f"{ip.dst}/32", strict=False)):
            return

        try:
            payload_ratio = len(pkt.payload) / len(pkt) if len(pkt) > 0 else 0
        except:
            payload_ratio = 0

        features = {
            'hour': pd.Timestamp.now().hour,
            'sport': pkt.sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0,
            'dport': pkt.dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0,
            'length': len(pkt),
            'local_ip': int(ip.src in self.local_ips),
            'proto_2': 1 if ip.proto == 2 else 0,
            'proto_6': 1 if ip.proto == 6 else 0,
            'proto_17': 1 if ip.proto == 17 else 0,
            'payload_ratio': payload_ratio
        }
        
        try:
            df = pd.DataFrame([features], columns=self.expected_columns)
            
            # Predicción silenciosa
            with suppress_output():
                anomaly_score = self.model.score_samples(df)[0]
            
            severity = self._score_to_severity(anomaly_score)
            
            if anomaly_score < self.ANOMALY_THRESHOLD:
                alert_key = f"{ip.src}:{features['sport']}-{ip.dst}:{features['dport']}"
                current_time = time.time()
                
                if alert_key not in self.alert_cooldown or (current_time - self.alert_cooldown[alert_key]) > self.cooldown_time:
                    print(f"\n[!] ALERTA: Anomalía detectada [{pd.Timestamp.now()}]")
                    print(f"    Score: {anomaly_score:.2f} | Severidad: {severity}%")
                    print(f"    Origen: {ip.src}:{features['sport']}")
                    print(f"    Destino: {ip.dst}:{features['dport']}")
                    print(f"    Protocolo: {'TCP' if ip.proto == 6 else 'UDP' if ip.proto == 17 else 'Otro'}")
                    print(f"    Tamaño: {len(pkt)} bytes | Ratio payload: {payload_ratio:.2f}")
                    
                    self.alert_cooldown[alert_key] = current_time
                    
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Processing error: {str(e)}")

    def _score_to_severity(self, score):
        """Convierte el score de anomalía a porcentaje de severidad"""
        min_score = -0.7
        max_score = 0.1
        return max(0, min(100, int(100 * (score - min_score) / (max_score - min_score))))

    def start(self):
        print("=== Sistema de Detección en Tiempo Real ===")
        print(f"Gateway: {self.gateway_ip}")
        print(f"Interfaz: {self.iface}")
        print(f"IP local: {self.local_ips[0] if self.local_ips else 'N/A'}")
        
        self._discover_active_hosts()
        
        def arp_loop():
            with ThreadPoolExecutor(max_workers=3) as executor:
                while self.forwarding:
                    futures = []
                    try:
                        for ip in self.active_ips:
                            if ip not in self.local_ips and ip != self.gateway_ip:
                                futures.append(executor.submit(self._arp_spoof, ip))
                        for future in as_completed(futures):
                            future.result()
                        time.sleep(15)
                    except Exception as e:
                        if self.debug:
                            print(f"[DEBUG] ARP error: {str(e)}")
        
        threading.Thread(target=arp_loop, daemon=True).start()
        
        try:
            sniff(
                prn=self._packet_handler,
                filter="ip",
                store=0,
                iface=self.iface,
                stop_filter=lambda x: not self.forwarding
            )
        except Exception as e:
            print(f"[!] Sniffer error: {str(e)}")

if __name__ == "__main__":
    try:
        detector = RealTimeDetector(debug=True)
        detector.start()
    except KeyboardInterrupt:
        detector.forwarding = False
        print("\n[+] Sistema detenido correctamente")
    except Exception as e:
        print(f"[!] Error crítico: {str(e)}")