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

def get_pcap_file():
    # Look for all .pcap files
    all_pcap_files = glob.glob("*.pcap")
    
    # Identify user files (anything that isn't named demo.pcap)
    user_files = [f for f in all_pcap_files if f.lower() != "demo.pcap"]

    if user_files:
        selected_file = user_files[0]
        print(f"\n[+] User file detected: {selected_file}")
        return selected_file, True # True means it is a user file
    elif os.path.exists("demo.pcap"):
        print("\n[!] No user file found. Running 'demo.pcap' by default...")
        return "demo.pcap", False # False means it is the demo
    else:
        print("\n[X] Error: No .pcap files found at all!")
        return None, False

def run_analysis():
    target_file, is_user_file = get_pcap_file()
    
    if not target_file:
        print("Please add a .pcap file to the TrafficSpy folder and restart.")
        return

    try:
        # Load and analyze packets
        packets = rdpcap(target_file)
        print(f"[*] Analysis complete. Processed {len(packets)} packets from {target_file}.")
        
        # --- YOUR ANALYSIS CODE HERE ---

        # After the analysis is finished:
        if not is_user_file:
            print("\n" + "="*50)
            print("NOTICE: You just viewed the DEMO analysis.")
            print("To analyze your own traffic:")
            print("1. Capture traffic in Wireshark.")
            print("2. Save it as 'pcap' (not pcapng).")
            print(f"3. Drop the file into this folder: {os.getcwd()}")
            print("4. Run this script again.")
            print("="*50)

    except Exception as e:
        print(f"\n[X] An error occurred while reading {target_file}: {e}")
        print("Ensure the file is a standard 'pcap' format.")

if __name__ == "__main__":
    run_analysis()
