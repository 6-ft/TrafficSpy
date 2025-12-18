import sys
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

def analyze():
    # Display the logo/watermark first
    show_logo()
    
    try:
        # Read the file 
        packets = rdpcap("demo.pcap")
        
        # Extract all Source IPs
        sources = [pkt[IP].src for pkt in packets if IP in pkt]
        
        print("=== Network Analysis Report ===")
        print(f"[*] Total Packets Analyzed: {len(packets)}")
        
        print("\n[+] Most Active Devices (IPs):")
        # Use .most_common() to show the biggest talkers at the top
        for ip, count in Counter(sources).most_common():
            print(f" -> {ip}: {count} packets")
            
        print("\n" + "="*33)
        print("Analysis Complete by Pulkit")
        print("="*33)
            
    except FileNotFoundError:
        print("Error: 'demo.pcap' not found. Please ensure the file is in the same directory.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    analyze()