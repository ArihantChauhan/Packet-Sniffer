from scapy.all import sniff, IP, TCP, UDP, Raw, ARP
from scapy.layers.http import HTTPRequest, HTTPResponse
from datetime import datetime, timedelta
import json, os, socket

syn_flood_tracker = {"count": 0, "start_time": datetime.now()}

timestamp1 = datetime.now().strftime("%H:%M:%S")
timestamp2 = datetime.now().strftime("%D | %H:%M:%S")

CACHE_FILE = "arp_cache.json"
CACHE_TTL_SECONDS = 24 * 60 * 60

def load_arp_cache():
    """Loads the existing ARP cache or creates a new one if it doesn't exist."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as file:
            data = json.load(file)
            if isinstance(data, dict):
                normalized = {}
                for ip, entry in data.items():
                    if isinstance(entry, dict) and "mac" in entry and "last_seen" in entry:
                        normalized[ip] = entry
                    else:
                        normalized[ip] = {
                            "mac": entry,
                            "last_seen": datetime.now().isoformat(),
                        }
                return normalized
    return {}

def save_arp_cache(cache):
    """Saves the updated ARP cache back to the storage file."""
    with open(CACHE_FILE, "w") as file:
        json.dump(cache, file, indent=4)

def remove_stale_arp_entries(cache):
    cutoff = datetime.now() - timedelta(seconds=CACHE_TTL_SECONDS)
    stale_ips = [ip for ip, entry in cache.items() if datetime.fromisoformat(entry["last_seen"]) < cutoff]
    for ip in stale_ips:
        del cache[ip]
    return stale_ips

def update_arp_entry(cache, ip, mac):
    cache[ip] = {
        "mac": mac,
        "last_seen": datetime.now().isoformat(),
    }
    stale_ips = remove_stale_arp_entries(cache)
    if stale_ips:
        print(f"Removed stale ARP entries: {', '.join(stale_ips)}")
    save_arp_cache(cache)

def get_hostname_by_ip(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        pass  # Router doesn't know, move to Try 2

    # Try 2: Local Multi-cast DNS / LLMNR
    try:
        # getnameinfo queries the local network infrastructure directly
        name_info = socket.getnameinfo((ip_address, 0), socket.NI_NAMEREQD)
        return name_info[0]
    except Exception:
        pass

    return "Unknown Device"

port_scan_tracker = {}
PORT_SCAN_THRESHOLD = 15
TIME_WINDOW = 2

def check_port_scan(src_ip, dst_port):
    global port_scan_tracker
    curr_time = datetime.now()

    if src_ip not in port_scan_tracker:
        port_scan_tracker[src_ip] = {"ports": {dst_port}, "start_time": curr_time}
        return
    record = port_scan_tracker[src_ip]
    elapsed_time = (curr_time - record["start_time"]).total_seconds()

    if elapsed_time > TIME_WINDOW:
        port_scan_tracker[src_ip] = {"ports": {dst_port}, "start_time": curr_time}
    else:
        record["ports".add(dst_port)]
        if len(record["ports"] > PORT_SCAN_THRESHOLD):
            print(f"{timestamp1}: !!! PORT SCAN DETECTED !!!")
            print(f"Offender IP: {src_ip} | Scanned Ports: {len(record["ports"])} unique ports in {elapsed_time: .2f}s")

arp_table = load_arp_cache()
print(f"Loaded {len(arp_table)} existing ARP records.")

def packet_sniffer(packet):
    src_ip = "n/a"
    dst_ip = "n/a"
    src_port = "n/a"
    dst_port = "n/a"
    trans_proto = "unknown"
    payload = "none"
    app_proto = "unknown"
    curr_time = datetime.now()
    syn_threshold = 50
    time_window = 2
    tcp_flags = "none"
    global syn_flood_tracker
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = packet[TCP].flags
            if packet.haslayer(Raw):
                raw_payload = packet[Raw].load
                try:
                    payload = raw_payload.decode("utf-8", errors = "ignore")
                except Exception as e:
                    payload = "[encrypted]"
            trans_proto = "TCP"
            if tcp_flags == "S":
                time_elapsed = (curr_time - syn_flood_tracker["start_time"]).total_seconds()
                if time_elapsed > time_window:
                    syn_flood_tracker = {"count": 0, "start_time": curr_time}
                else:
                    syn_flood_tracker["count"] += 1
                    if syn_flood_tracker["count"] > syn_threshold:
                        print(f"[{timestamp2}] !!! TCP SYN FLOOD DETECTED !!!")
                        print(f"Sample Offending IP: {src_ip} | Target Port: {dst_port}")
                        print(f"Volume: {syn_flood_tracker['syn_count']} SYN packets in < {time_window} seconds.")
                        print("!" * 65 + "\n")
            if src_port == 80 or dst_port == 80:
                app_proto = "HTTP (Web Traffic)"
            elif src_port == 443 or dst_port == 443:
                app_proto = "HTTPS (Secure Web Traffic)"
            elif src_port == 25 or dst_port == 25 or src_port == 465 or dst_port == 465:
                app_proto = "SMTP (Email Communications)"
            elif src_port == 21 or dst_port == 21:
                app_proto = "FTP (File Transfer)"
            elif src_port == 22 or dst_port == 22:
                app_proto = "SSH (Secure Remote Access)"
            elif src_port == 8080 or dst_port == 8080:
                app_proto = "HTTP Proxy"
            elif src_port == 5223 or dst_port == 5223:
                app_proto = "Apple Push Notifications (APN)"
            elif src_port == 5228 or dst_port == 5228:
                app_proto = "Google Android Push Notifications"
            
            print(f"{timestamp1}: [TCP] [{app_proto}] || S: {src_ip}:{src_port} || D: {dst_ip}:{dst_port} || F: {tcp_flags}")
            if packet.haslayer(HTTPRequest):
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                print(f"^^^ [HTTP Request] from {src_ip} to {url} ^^^")
            elif packet.haslayer(HTTPResponse):
                server_sw = packet[HTTPResponse].Server.decode(errors = 'ignore')
                status_code = packet[HTTPResponse].Status_Code.decode(errors='ignore')
                reason = packet[HTTPResponse].Reason_Phrase.decode(errors='ignore')
                if server_sw in ["WebServer, SecureServer"]:
                    server_sw = "Hidden"
                print(f"^^^ [HTTP Response] Web Server ({src_ip}) responded to {dst_ip} || Status: {status_code} {reason} || SW: {server_sw} ^^^")
        elif packet.haslayer(UDP):
            if packet.haslayer(Raw):
                raw_payload = packet[Raw].load
                payload = raw_payload.decode("utf-8", errors = "ignore")
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if src_port == 53 or dst_port == 53:
                app_proto = "DNS (Domain Lookup)"
            elif src_port == 5353 or dst_port == 5353 or dst_ip == "224.0.0.251":
                app_proto = "mDNS (Local Device Discovery)"
            elif src_port == 443 or dst_port == 443:
                app_proto = "HTTP/3 (QUIC)"
            elif src_port == 15600 or dst_port == 15600 or dst_ip == "239.255.255.250" or dst_port == 1900:
                app_proto = "SSDP (Media Streaming Discovery)"
            elif dst_ip == "192.168.1.255":
                app_proto = "Forced Broadcast"
            trans_proto = "UDP"
            print(f"{timestamp1}: [UDP] [{app_proto}] S: {src_ip}:{src_port} || D: {dst_ip}:{dst_port}")
        else:
            trans_proto = packet[IP].proto
            print(f"Transport Protocol: {trans_proto} || S: {src_ip}:{src_port} || D: {dst_ip}:{dst_port}")
        with open("network_traffic_log.txt", "a") as f:
            f.write("=" * 50 + "\n")
            f.write(f"Timestamp: {timestamp2}\n")
            f.write(f"Transport Protocol: {trans_proto}\n")
            f.write(f"Application Protocol: {app_proto}\n")
            f.write(f"S: {src_ip}:{src_port}\n")
            f.write(f"D: {dst_ip}:{dst_port}\n")
            f.write(f"F: {tcp_flags}\n")
            f.write(f"Packet Length: {len(packet)} bytes\n")
            f.write(f"Payload: {payload}\n")
            f.write("=" * 50 + "\n\n")
    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        src_mac = packet[ARP].hwsrc
        dst_mac = packet[ARP].hwdst
        op = packet[ARP].op
        if op == 1:
            proto_desc = "ARP Request (Who-has)"
            if src_ip == dst_ip:
                proto_desc = "GARP Request"
                if dst_mac == "00:00:00:00:00:00":
                    print(f"{timestamp1}: [GARP] [Request] {src_ip} ({get_hostname_by_ip(src_ip)}) is checking for potential IP conflicts")
                elif dst_mac == "ff:ff:ff:ff:ff:ff":
                    print(f"{timestamp1}: [GARP] [Request] {src_ip} ({get_hostname_by_ip(src_ip)}) is announcing itself and pushing an update in neighboring caches")
            else:
                print(f"{timestamp1}: [ARP] [Request] {src_ip} ({get_hostname_by_ip(src_ip)}) is asking who has {dst_ip} ({get_hostname_by_ip(dst_ip)})")
            log_msg = f"Timestamp: {timestamp2}\nProtocol Desc: {proto_desc}\nS IP: {src_ip} has MAC: {src_mac}\nAsking for D IP: {dst_ip}\n\n"
        elif op == 2:
            proto_desc = "ARP Response (Is-at)"
            existing_entry = arp_table.get(src_ip)
            if existing_entry is None:
                update_arp_entry(arp_table, src_ip, src_mac)
                print(f"{timestamp1}: [NEW DEVICE] !!! {src_ip} ({get_hostname_by_ip(src_ip)}) is at {src_mac}")
            elif existing_entry["mac"] != src_mac:
                old_mac = existing_entry["mac"]
                print(f"[WARNING] !!! IP Cache Change for {src_ip} !!! POSSIBLE ARP SPOOFING !!!")
                print(f"OLD MAC: {old_mac}")
                print(f"NEW MAC: {src_mac}")
                update_arp_entry(arp_table, src_ip, src_mac)
            else:
                update_arp_entry(arp_table, src_ip, src_mac)
                print(f"{timestamp1}: [ARP] [Response] {src_ip} ({get_hostname_by_ip(src_ip)}) is at {src_mac}")
            log_msg = f"Timestamp: {timestamp2}\nProtocol Desc: {proto_desc}\nS IP: {src_ip} responds to D IP: {dst_ip}\nAt MAC: {src_mac}\n\n"
        else:
            proto_desc = "Unknown ARP"
            print(f"{timestamp1}: [ARP] Unknown ARP Op")
            log_msg = f"Timestamp: {timestamp2}\nProtocol Desc: {proto_desc}\nOp Code: {op}\n\n"
        with open("network_traffic_log.txt", "a") as f:
            f.write(log_msg)
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(filter = "arp", prn = packet_sniffer, store = False, count = 50)