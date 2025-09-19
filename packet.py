from scapy.all import *

# Trame Ethernet + IP + UDP avec payload personnalisé
packet = Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66") / \
         IP(dst="10.0.0.1", src="10.0.0.42") / \
         UDP(dport=1234, sport=4321) / \
         Raw(load="Données faites maison")

sendp(packet, iface="eth0")