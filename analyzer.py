import sys
import os
import glob
from scapy.all import rdpcap, IP, TCP, UDP, Ether
from collections import Counter

def show_logo():
    # ANSI escape sequence for a clickable hyperlink in supporting terminals
    link = "https://github.com/6-ft"
    label = "github.com/6-ft"
    hyperlink = f"\u001b]8;;{link}\u001b\\{label}\u001b]8;;\u001b\\"

    logo = rf"""
   _____ _    _          _____  _  __
  / ____| |  | |   /\   |  __ \| |/ /
 | (___ | |__| |  /  \  | |__) | ' / 
  \___ \|  __  | / /\ \ |  _  /|  <  
  ____) | |  | |/ ____ \| | \ \| . \ 
 |_____/|_|  |_/_/    \_\_|  \_\_|\_\
    
    >> NETWORK TRAFFIC ANALYZER <<
    Developed by: {hyperlink}
    ---------------------------------
    """
    print(logo)



def get_target():
    files = glob.glob("*.pcap")
    user_file = [f for f in files if f.lower() != "demo.pcap"]
    
    if user_file:
        return user_file[0], False
    elif os.path.exists("demo.pcap"):
        return "demo.pcap", True
    return None, False

def analyze():
    target, is_demo = get_target()
    if not target:
        print("[-] No file found. Add a .pcap to this folder.")
        return

    try:
        packets = rdpcap(target)
        ip_list = []
        
        print(f"\n[+] ANALYZING: {target}")
        print("-" * 85)
        print(f"{'SOURCE IP':<18} | {'DEST IP':<18} | {'PORT':<6} | {'MAC ADDRESS'}")
        print("-" * 85)

        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                ip_list.append(dst_ip)
                
                # Feature: Port Detection
                port = ""
                if TCP in pkt: port = pkt[TCP].dport
                elif UDP in pkt: port = pkt[UDP].dport
                
                # Feature: MAC Address Extraction
                mac = pkt[Ether].src if Ether in pkt else "Unknown"

                print(f"{src_ip:<18} | {dst_ip:<18} | {port:<6} | {mac}")

        # Feature: Traffic Statistics Summary
        print("\n" + "="*30)
        print("   TOP DESTINATION TARGETS")
        print("="*30)
        stats = Counter(ip_list).most_common(5)
        for ip, count in stats:
            print(f"{ip:<18} : {count} packets")

        if is_demo:
            print("\n" + "!" * 60)
            print("FINISHED RUNNING DEMO DATA.")
            print(f"DIRECTIONS: Drop your Wireshark '.pcap' file here to scan it.")
            print(f"Current Path: {os.getcwd()}")
            print("!" * 60)

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    analyze()
