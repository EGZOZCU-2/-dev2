import argparse             # Kullanıcıdan komut satırı argümanlarını (IP, ağ bloğu vb.) almamızı sağlayan standart kütüphane.
import socket               # Ağ bağlantıları kurmak için olmazsa olmazımız.
import concurrent.futures   # İşte hızımızın sırrı! Aynı anda yüzlerce portu/IP'yi taramak için kullanıyoruz.
import ipaddress            # /24, /16 gibi ağ bloklarını kolayca çözmek için.
import os                   # İşletim sistemini tanımak (Windows/Linux) ve komut çalıştırmak için.
import subprocess           # Ping gibi dış komutları güvenli bir şekilde çalıştırma motoru.
import time                 # Taramanın ne kadar sürdüğünü görmek için zaman tutucu.
from typing import List, Tuple, Dict, Any # Kodun ne tür verilerle çalıştığını belirten temizlikçi (tip belirtimi).

# --- Yapılandırma ve Varsayılanlar ---

# Penetrasyon testlerinde en çok bakılan portlar. Varsayılan olarak bunları tarayacağız.
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 3306, 3389, 8080]
MAX_WORKERS = 150           # Thread sayısı. Ağdaki tıkanıklığı önlemek için çok fazla abartmamak lazım.
PING_TIMEOUT = 3            # Ping için 3 saniye yeterli. Daha fazlası taramayı yavaşlatır.
SCAN_TIMEOUT = 1            # Port bağlantı denemesi için 1 saniye ideal.
BANNER_TIMEOUT = 1          # Banner okuma için de 1 saniye veriyoruz.
RECV_SIZE = 2048            # Sunucudan gelen ilk veriyi (banner) okurken alacağımız maksimum boyut.

# --- Küçük Yardımcı Fonksiyonlar ---

def parse_ports(port_input: str) -> List[int]:
    """
    Port aralığı girişi için esneklik sağlayan fonsiyon. 
    Kullanıcı '80,443,1000-1010' gibi karmaşık girdiler verebilir, hepsini tek tek listeye çeviriyoruz.
    """
    ports = set()
    parts = port_input.split(',')
    
    for part in parts:
        part = part.strip()
        if not part: continue
            
        if '-' in part: # '1000-1010' formatını ele al
            try:
                start, end = map(int, part.split('-'))
                if not (1 <= start <= 65535 and start <= end):
                    raise ValueError # Geçersiz port aralığı
                ports.update(range(start, end + 1)) 
            except ValueError:
                print(f"[!] Kardeşim, port aralığı formatın hatalı: {part}. Şunu dene: 1-1000")
                return []
        else: # Tek port formatını ele al ('80')
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
    # OS kontrolü: Linux'ta '-c', Windows'ta '-n' kullanılır.
    param = "-n" if os.name == "nt" else "-c"
    command = ["ping", param, "1", host] # Sadece bir paket gönderiyoruz, hızlı olsun.
    
    try:
        # Ping komutunu çalıştır.
        startupinfo = None
        if os.name == "nt": # Windows'ta siyah komut penceresinin açılmasını engellemek için.
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
        result = subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            timeout=PING_TIMEOUT,
            startupinfo=startupinfo
        )
        # returncode 0 ise, ping başarılıdır, host aktif demektir.
        return host, (result.returncode == 0)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return host, False # Zaman aşımı, ağ hatası vb. durumlarda pasif kabul et.

def list_hosts(network: str) -> List[str]:
    """
    Verilen CIDR bloğundaki (örn: 192.168.1.0/24) tüm IP'lere hızlıca ping atıp
    cevap verenleri 'aktif host' olarak listeye ekleyen fonksiyon.
    """
    net = ipaddress.ip_network(network, strict=False) 
    hosts = [str(h) for h in net.hosts()] # Tüm host IP'lerini al.
    live: List[str] = []
    
    print(f"[*] Ping Tarama başladı: {network} bloğunda {len(hosts)} IP var.")

    # Tüm ping işlemlerini paralel yürütecek thread havuzu.
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(ping_host, h) for h in hosts] 
        for f in concurrent.futures.as_completed(futures): # Görevler tamamlandıkça sonuçları al
            host, status = f.result()
            if status:
                live.append(host) # Canlı olan hostu kaydet.
            
    return live

# --- Port Tarama ve Servis Tespiti ---

def scan_port(host: str, port: int) -> Tuple[int, bool]:
    """
    Basit TCP port taraması. Hedef porta bağlanmayı deneriz.
    Bağlantı başarılı olursa port açıktır, hata verirse kapalıdır.
    """
    try:
        # Yeni bir TCP soketi aç ve bağlantı zaman aşımını ayarla.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            s.connect((host, port)) # Bağlanmayı dene (Bu, portun açık olup olmadığını anlarız.)
            return port, True  # Port açık
    except (socket.timeout, socket.error, OSError):
        return port, False  # Port kapalı veya filtreli

def banner_grab(host: str, port: int) -> str:
    """
    Açık porttan hizmet bilgisini (Banner) yakalamaya çalışırız. 
    Bu bilgi bize servisin türünü ve sürümünü söyler.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            s.connect((host, port))
            
            # Bazı protokollere özel ilk isteği göndererek sunucuyu konuşturmaya çalışırız.
            if port in [21, 25, 110, 143]: # FTP, SMTP, POP3, IMAP gibi
                s.sendall(b"HELP\r\n")
            elif port == 80 or port == 443: # HTTP/HTTPS için
                # Sunucuya basit bir HTTP başlık (HEAD) isteği gönder.
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            
            data = s.recv(RECV_SIZE) # Gelen cevabı al.
            # Gelen bayt verisini temizle, ilk satırını al ve döndür.
            return data.decode(errors="ignore").strip().split('\n')[0] 
            
    except (socket.timeout, socket.error, OSError):
        return "Banner Alınamadı (Timeout/Hata)"

def scan_ports(host: str, ports: List[int]) -> Dict[str, Any]:
    """
    Port taramasını ve banner grabbing'i yöneten ana fonksiyon.
    Önce tüm portları paralel tarayıp açık portları buluruz, sonra sadece açık olanlardan banner toplarız.
    """
    open_ports: List[int] = []
    banners: Dict[int, str] = {}
    
    print(f"[*] Port Tarama başladı: {host} üzerinde {len(ports)} port taranıyor.")

    # 1. Aşama: Port Tarama (Hızlı TCP Bağlantı Denemeleri)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 
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
    parser = argparse.ArgumentParser(
        prog="Akın", # Uygulama adını Akın olarak güncelledik!
        description="Kali Linux'a özel, hızlı ağ keşif ve port tarama aracı. Güvenlik testlerinde kullan!"
    )
    
    # Ya ağ taraması (-n) ya da tek host taraması (-H) yapılmalı. 
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-n", "--network", help="Ağ bloğu tarama (Örn: 192.168.1.0/24)")
    target_group.add_argument("-H", "--host", help="Tek bir IP tarama (Örn: 192.168.1.10)")
    
    parser.add_argument("-p", "--ports", help="Özel port aralığı (Örn: 21,80,443,1000-2000). Yoksa varsayılan portları kullanırız.")
    
    args = parser.parse_args()

    start_time = time.time() # Zamanı başlat!

    # --- -n: Ağ Tarama Modu ---
    if args.network:
        try:
            live_hosts = list_hosts(args.network)
            
            print("\n" + "="*50)
            print(f"** 🌍 Akın Ağ Tarama Sonucu: {args.network} **")
            print("="*50)
            
            if live_hosts:
                print(f"🎉 **Aktif Host Sayısı:** {len(live_hosts)} tanesini buldum!")
                for h in live_hosts:
                    print(f"  - 🟢 {h}")
            else:
                print("❌ Üzgünüm, bu ağda aktif host yok gibi görünüyor.")
                
        except ValueError as e:
            print(f"[!] Hatalı ağ formatı girdin, kontrol et: {e}")
        
    # --- -H: Host Tarama Modu ---
    elif args.host:
        host = args.host
        
        try:
            ipaddress.ip_address(host) # IP'nin gerçekten IP formatında olup olmadığını kontrol et.
        except ValueError:
            print(f"[!] Bu geçerli bir IP adresi değil: {host}")
            return
            
        ports_to_scan = []
        if args.ports:
            ports_to_scan = parse_ports(args.ports) # Özel portlar varsa kullan.
        else:
            ports_to_scan = DEFAULT_PORTS # Yoksa standart portlarla devam et.
        
        if not ports_to_scan: # Port ayrıştırmada hata varsa dur.
            return
            
        # Port tarama ve Banner Grabbing'i tek bir çağrıda hallet!
        scan_results = scan_ports(host, ports_to_scan)
        
        # Sonuçları Temizce Yazdır
        print("\n" + "="*50)
            
        print(f"** 🎯 Akın Host Tarama Sonuçları: {host} **")
        print("="*50)
        
        if scan_results["open_ports"]:
            print(f"✅ **Açık Portlar:** {len(scan_results['open_ports'])} kapı aralık!")
            for p in scan_results["open_ports"]:
                banner = scan_results["banners"].get(p, "Banner Alınamadı")
                # Port numarasına göre servisin adını bulmaya çalış (21=ftp, 80=http gibi)
                service_name = socket.getservbyport(p, 'tcp') if 1 <= p <= 65535 else 'Bilinmiyor'
                print(f"  - **{p}/tcp** ({service_name})")
                print(f"    -> Servis Bilgisi: {banner}")
        else:
            print("❌ Tarama aralığında açık port bulamadık.")
    
    # --- Bitiş ---
    end_time = time.time()
    print("\n" + "="*50)
    print(f"⌛ Akın Tarama Tamamlandı: {end_time - start_time:.2f} saniyede bitirdik. Hızlıyız! 🏎️")
    print("="*50)


# Eğer bu dosya doğrudan çalıştırılıyorsa, main fonksiyonunu çağır.
if __name__ == "__main__":
    main()