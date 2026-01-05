import socket
import ipaddress

socket.setdefaulttimeout(0.5)

def host_alive(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, 80))
        s.close()
        return result == 0 or result == 111
    except:
        return False

def discover_hosts(network):
    alive_hosts = []
    for ip in ipaddress.IPv4Network(network):
        ip = str(ip)
        if host_alive(ip):
            print(f"[+] Host aktif: {ip}")
            alive_hosts.append(ip)
    return alive_hosts

def scan_ports(ip):
    open_ports = []
    print(f"[*] {ip} port taraması başladı...")
    for port in range(1, 65536):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"[+] Açık port: {port}")
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

def main():
    network = input("Network gir (örn: 192.168.1.0/24): ")
    hosts = discover_hosts(network)

    for host in hosts:
        ports = scan_ports(host)
        print(f"[✓] {host} açık portlar: {ports}")

if _name_ == "_main_":
    main()
