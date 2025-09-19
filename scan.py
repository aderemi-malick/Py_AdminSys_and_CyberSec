from scapy.all import *

# Define the target IP range
target_ip = "192.168.1.0/24"
# Define the ports to scan
target_ports = [22, 80, 443]

def scan_host(ip):
    print(f"\nScanning host: {ip}")
    for port in target_ports:
        sc_port = RandShort()
        pkt = IP(dst=ip)/TCP(sport=sc_port, dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp is not None:
            if resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:  # SYN-ACK
                    print(f"Port {port} is open")
                    # Send RST to close the connection
                    sr(IP(dst=ip)/TCP(sport=sc_port, dport=port, flags="R"), timeout=1, verbose=0)
                elif resp[TCP].flags == 0x14:  # RST-ACK
                    print(f"Port {port} is closed")
            elif resp.haslayer(ICMP):
                if int(resp[ICMP].type) == 3 and int(resp[ICMP].code) in [1, 2, 3, 9, 10, 13]:
                    print(f"Port {port} is filtered")
        else:
            print(f"Port {port} is filtered (no response)")

def main():
    print(f"Scanning IP range: {target_ip}")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=2, verbose=0)
    for snd, rcv in ans:
        scan_host(rcv.psrc)

if __name__ == "__main__":
    main()
