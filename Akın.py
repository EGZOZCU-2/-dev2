import argparse
import socket
import concurrent.futures
import ipaddress
import os
import subprocess
import time
import sys # sys kütüphanesi eklendi, etkileşimli çıkış için
from typing import List, Tuple, Dict, Any

# --- Yapılandırma ve Varsayılanlar ---
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 3306, 3389, 8080]
MAX_WORKERS = 150
PING_TIMEOUT = 3
SCAN_TIMEOUT = 1
BANNER_TIMEOUT = 1
RECV_SIZE = 2048

# --- Küçük Yardımcı Fonksiyonlar ---

def parse_ports(port_input: str) -> List[int]:
    """
    Port aralığı girişi için esneklik sağlayan fonsiyon.
    Kullanıcı '80,443,1000-1010' gibi karmaşık girdiler verebilir.
    """
    ports = set()
    parts = port_input.split(',')
    
    for part in parts:
        part = part.strip()
        if not part: continue
            
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if not (1 <= start <= 65535 and start <= end):
                    raise ValueError
                ports.update(range(start, end + 1)) 
            except ValueError:
                print(f"[!] Kardeşim, port aralığı formatın hatalı: {part}. Şunu dene: 1-1000")
                return []
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
                else:
                    print(f"[!] Port numarası 1 ile 65535 arasında olmalı: {port}")
                    return []
            except ValueError:
                print(f"[!] Port numarasını sayı olarak girmen gerekiyor: {part}")
                return []

    return sorted(list(ports)) 

# --- Ağ Keşfi (Canlı Hostları Bulma) ---

def ping_host(host: str) -> Tuple[str, bool]:
    """
    Hostun hayatta olup olmadığını kontrol eden klasik ping fonksiyonu.
    Windows ve Linux'taki komut farklılıklarını hallediyoruz.
    """
    param = "-n" if os.name == "nt" else "-c"
    command = ["ping", param, "1", host]
    
    try:
        startupinfo = None
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
        result = subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, # text=True eklendi
            timeout=PING_TIMEOUT,
            startupinfo=startupinfo
        )
        # Çıktıda TTL veya "1 received" kontrolü
        return host, (result.returncode == 0 and ("TTL=" in result.stdout or "1 received" in result.stdout or "0% packet loss" in result.stdout))
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return host, False

def list_hosts(network: str) -> List[str]:
    """
    Verilen CIDR bloğundaki (örn: 192.168.1.0/24) tüm IP'lere hızlıca ping atıp
    cevap verenleri 'aktif host' olarak listeye ekleyen fonksiyon.
    """
    try:
        net = ipaddress.ip_network(network, strict=False) 
    except ValueError:
        print(f"[!] Hatalı ağ formatı: {network}. Lütfen kontrol et.")
        return []
        
    hosts = [str(h) for h in net.hosts()]
    live: List[str] = []
    
    print(f"[*] Ping Tarama başladı: {network} bloğunda {len(hosts)} IP var.")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(ping_host, h) for h in hosts] 
        for f in concurrent.futures.as_completed(futures):
            host, status = f.result()
            if status:
                live.append(host)
                # Buraya anlık çıktı eklemedik, hepsi bitince listeleyeceğiz.
            
    return live

# --- Port Tarama ve Servis Tespiti ---

def scan_port(host: str, port: int) -> Tuple[int, bool]:
    """Basit TCP port taraması."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.connect((host, port))
            return port, True
    except (socket.timeout, socket.error, OSError):
        return port, False

def banner_grab(host: str, port: int) -> str:
    """Açık porttan hizmet bilgisini (Banner) yakalamaya çalışırız."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            s.connect((host, port))
            
            if port in [21, 25, 110, 143]:
                s.sendall(b"HELP\r\n")
            elif port == 80 or port == 443:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            
            data = s.recv(RECV_SIZE)
            return data.decode(errors="ignore").strip().split('\n')[0]
            
    except (socket.timeout, socket.error, OSError):
        return "Banner Alınamadı (Timeout/Hata)"

def scan_ports(host: str, ports: List[int]) -> Dict[str, Any]:
    """
    Port taramasını ve banner grabbing'i yöneten ana fonksiyon.
    """
    open_ports: List[int] = []
    banners: Dict[int, str] = {}
    
    print(f"[*] Port Tarama başladı: {host} üzerinde {len(ports)} port taranıyor.")

    # 1. Aşama: Port Tarama (Hızlı TCP Bağlantı Denemeleri)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(scan_port, host, p) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            port, status = f.result()
            if status:
                open_ports.append(port)
                
    # 2. Aşama: Banner Grabbing (Sadece Açık Portlar İçin Detay Toplama)
    if open_ports:
        print("[*] Açık portlar bulundu! Şimdi servis bilgilerini (Banner) çekiyoruz...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_banners = {executor.submit(banner_grab, host, p): p for p in open_ports}
            for future in concurrent.futures.as_completed(future_banners):
                port = future_banners[future]
                banner = future.result()
                banners[port] = banner
            
    return {"open_ports": open_ports, "banners": banners}

# --- Programın Ana Giriş Noktası ---

def main():
    """
    Kullanıcı arayüzünü yöneten, zamanı tutan ve sonuçları ekrana basan ana motor.
    """
    # Argüman zorunluluğunu kaldırıyoruz ve sadece tek bir "target" bekliyoruz.
    parser = argparse.ArgumentParser(
        prog="Akın",
        description="Kali Linux'a özel, hızlı ağ keşif ve port tarama aracı."
    )
    
    # nargs='?' ile target'ı isteğe bağlı yapıyoruz.
    parser.add_argument("target", nargs='?', help="Taranacak tek IP (Örn: 192.168.1.10) veya Ağ Bloğu (Örn: 192.168.1.0/24).")
    
    parser.add_argument("-p", "--ports", help="Özel port aralığı (Örn: 21,80,443,1000-2000). Yoksa varsayılan portları kullanırız.")
    
    args = parser.parse_args()

    # --- Etkileşimli Giriş ---
    if not args.target:
        print("\n" + "="*50)
        print("🎯 Akın Tarayıcı Başlatılıyor...")
        print("="*50)
        target = input("Lütfen taramak istediğiniz IP veya Network bloğunu girin: ")
        if not target.strip():
            print("[!] Geçerli bir hedef girmedin. Çıkılıyor.")
            sys.exit(1)
        args.target = target
    
    target = args.target
    start_time = time.time()

    # --- Hedef Türünü Otomatik Ayırt Etme ---
    is_network = False
    try:
        # Girdi bir CIDR bloğu mu?
        ipaddress.ip_network(target, strict=False) 
        # Eğer bir CIDR bloğu ise, IP host sayısına bakılarak ayırt edilir.
        if "/" in target and ipaddress.ip_network(target, strict=False).prefixlen < 32:
             is_network = True
        elif "/" not in target:
             # Eğer / yoksa ve sadece IP formatındaysa host olarak kabul et
             ipaddress.ip_address(target)
             is_network = False
        
    except ValueError:
        # Format hatası varsa
        print(f"[!] Hatalı IP veya Ağ formatı girdin: {target}")
        return

    # --- Çalışma Moduna Göre Yönlendir ---
    
    if is_network:
        # --- Ağ Tarama Modu ---
        try:
            live_hosts = list_hosts(target)
            
            print("\n" + "="*50)
            print(f"** 🌍 Akın Ağ Tarama Sonucu: {target} **")
            print("="*50)
            
            if live_hosts:
                print(f"🎉 *Aktif Host Sayısı:* {len(live_hosts)} tanesini buldum!")
                for h in live_hosts:
                    print(f"  - 🟢 {h}")
            else:
                print("❌ Üzgünüm, bu ağda aktif host yok gibi görünüyor.")
                
        except ValueError as e:
            print(f"[!] Hatalı ağ formatı: {e}")
        
    else:
        # --- Host Tarama Modu ---
        host = target
        
        ports_to_scan = []
        if args.ports:
            ports_to_scan = parse_ports(args.ports)
        else:
            ports_to_scan = DEFAULT_PORTS
        
        if not ports_to_scan:
            return
            
        scan_results = scan_ports(host, ports_to_scan)
        
        # Sonuçları Temizce Yazdır
        print("\n" + "="*50)
        print(f"** 🎯 Akın Host Tarama Sonuçları: {host} **")
        print("="*50)
        
        if scan_results["open_ports"]:
            print(f"✅ *Açık Portlar:* {len(scan_results['open_ports'])} kapı aralık!")
            for p in scan_results["open_ports"]:
                banner = scan_results["banners"].get(p, "Banner Alınamadı")
                service_name = socket.getservbyport(p, 'tcp') if 1 <= p <= 65535 else 'Bilinmiyor'
                print(f"  - *{p}/tcp* ({service_name})")
                print(f"    -> Servis Bilgisi: {banner.strip()}")
        else:
            print(f"❌ {len(ports_to_scan)} port taranmasına rağmen açık port bulamadık.")
    
    # --- Bitiş ---
    end_time = time.time()
    print("\n" + "="*50)
    print(f"⌛ Akın Tarama Tamamlandı: {end_time - start_time:.2f} saniyede bitirdik. Hızlıyız! 🏎")
    print("="*50)


# YAZIM HATASI DÜZELTİLDİ: name yerine _name_ kullanıldı.
if _name_ == "_main_":
    main()
