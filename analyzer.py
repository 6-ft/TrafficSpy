import sys
import os
import glob
from scapy.all import rdpcap, IP
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

import os
import glob
from scapy.all import rdpcap, IP

def start_spy():
    # Find any pcap file that isn't the demo
    files = glob.glob("*.pcap")
    user_file = [f for f in files if f.lower() != "demo.pcap"]
    
    if user_file:
        target = user_file[0]
        is_demo = False
    elif os.path.exists("demo.pcap"):
        target = "demo.pcap"
        is_demo = True
    else:
        print("[-] No pcap files found. Drop a .pcap file in this folder.")
        return

    try:
        packets = rdpcap(target)
        print(f"\n[+] TARGET: {target} | TOTAL PACKETS: {len(packets)}")
        print("-" * 60)
        print(f"{'SRC IP':<20} | {'DST IP':<20} | {'PROTO'}")
        print("-" * 60)

        for pkt in packets:
            if IP in pkt:
                proto = pkt.sprintf("%IP.proto%")
                print(f"{pkt[IP].src:<20} | {pkt[IP].dst:<20} | {proto}")

        if is_demo:
            print("\n" + "!" * 60)
            print("FINISHED RUNNING DEMO DATA.")
            print(f"TO RUN YOUR OWN: Save your Wireshark capture as .pcap (NOT pcapng)")
            print(f"and drop it into: {os.getcwd()}")
            print("!" * 60)

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    start_spy()
