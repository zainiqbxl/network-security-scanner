import socket
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
}

def scan_host(target, start_port=1, end_port=1024, timeout=0.15):
    results = []
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError("Could not resolve that hostname.")

    print(f"\nScanning {target} ({ip}) from port {start_port} to {end_port}...")
    started = datetime.now()

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                results.append((port, service))
                print(f"[OPEN] {port:<5} {service}")
        finally:
            sock.close()

    elapsed = datetime.now() - started
    return ip, results, elapsed

def save_report(target, ip, results, elapsed):
    with open("scan_report.txt", "w", encoding="utf-8") as f:
        f.write("NETWORK SECURITY SCAN REPORT\n")
        f.write("=" * 35 + "\n")
        f.write(f"Target: {target}\nIP: {ip}\n")
        f.write(f"Scan duration: {elapsed}\n\n")
        if results:
            for port, service in results:
                f.write(f"OPEN: Port {port} - {service}\n")
        else:
            f.write("No open ports found in the selected range.\n")
    print("\nReport saved as scan_report.txt")

if __name__ == "__main__":
    print("Network Security Scanner")
    print("Use only on systems you own or have permission to test.\n")
    target = input("Target (try localhost): ").strip() or "localhost"
    try:
        start = int(input("Start port [1]: ").strip() or "1")
        end = int(input("End port [1024]: ").strip() or "1024")
        if not (1 <= start <= end <= 65535):
            raise ValueError
        ip, results, elapsed = scan_host(target, start, end)
        print(f"\nFinished. Found {len(results)} open port(s).")
        save_report(target, ip, results, elapsed)
    except ValueError:
        print("Invalid target or port range.")
