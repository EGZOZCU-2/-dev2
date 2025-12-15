# --- Programın Ana Giriş Noktası ---

def main():
    """
    Kullanıcı arayüzünü yöneten, zamanı tutan ve sonuçları ekrana basan ana motor.
    Tek argüman geldiğinde bunun IP mi yoksa Network bloğu mu olduğunu otomatik ayırt eder.
    """
    parser = argparse.ArgumentParser(
        prog="Akın", # Uygulama adını Akın olarak güncelledik!
        description="Kali Linux'a özel, hızlı ağ keşif ve port tarama aracı. Güvenlik testlerinde kullan!"
    )
    
    # Argüman zorunluluğunu kaldırıyoruz. Sadece bir target (IP veya Network) bekliyoruz.
    # nargs='?' ile target'ı isteğe bağlı yapıyoruz.
    parser.add_argument("target", nargs='?', help="Taranacak tek IP (Örn: 192.168.1.10) veya Ağ Bloğu (Örn: 192.168.1.0/24).")
    
    parser.add_argument("-p", "--ports", help="Özel port aralığı (Örn: 21,80,443,1000-2000). Yoksa varsayılan portları kullanırız.")
    
    args = parser.parse_args()

    # Eğer hiç target girmemişse kullanıcıdan soruyoruz
    if not args.target:
        print("\n" + "="*50)
        print("Akın Tarayıcı Başlatılıyor...")
        print("="*50)
        target = input("🎯 Lütfen taramak istediğiniz IP veya Network bloğunu girin: ")
        if not target.strip():
            print("[!] Geçerli bir hedef girmedin. Çıkılıyor.")
            return
        args.target = target
    
    target = args.target
    start_time = time.time() # Zamanı başlat!

    # --- Hedef Türünü Otomatik Ayırt Etme ---

    is_network = False
    try:
        # Deneme: Girdi bir CIDR bloğu mu? (örn: 192.168.1.0/24)
        ipaddress.ip_network(target, strict=False) 
        is_network = True
    except ValueError:
        try:
            # Deneme: Girdi tek bir IP adresi mi? (örn: 192.168.1.10)
            ipaddress.ip_address(target)
            is_network = False # Tek host olarak kabul et
        except ValueError:
            print(f"[!] Hatalı IP veya Ağ formatı girdin: {target}")
            return

    # --- Ağ Tarama Modu ---
    if is_network:
        try:
            live_hosts = list_hosts(target)
            
            print("\n" + "="*50)
            print(f"** 🌍 Akın Ağ Tarama Sonucu: {target} **")
            print("="*50)
            
            if live_hosts:
                print(f"🎉 *Aktif Host Sayısı:* {len(live_hosts)} tanesini buldum!")
                
                # Ağ taramasında aktif hostları bulduktan sonra, port taraması yapmak istersek
                # Burada ek döngü ve kodlama gerekir. Şimdilik sadece aktif hostları listeliyoruz.
                for h in live_hosts:
                    print(f"  - 🟢 {h}")
            else:
                print("❌ Üzgünüm, bu ağda aktif host yok gibi görünüyor.")
                
        except ValueError as e:
            print(f"[!] Hatalı ağ formatı: {e}")
        
    # --- Host Tarama Modu ---
    else: # is_network False ise tek host tarıyoruz
        host = target
        
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
            print(f"✅ *Açık Portlar:* {len(scan_results['open_ports'])} kapı aralık!")
            for p in scan_results["open_ports"]:
                banner = scan_results["banners"].get(p, "Banner Alınamadı")
                # Port numarasına göre servisin adını bulmaya çalış
                service_name = socket.getservbyport(p, 'tcp') if 1 <= p <= 65535 else 'Bilinmiyor'
                print(f"  - *{p}/tcp* ({service_name})")
                print(f"    -> Servis Bilgisi: {banner}")
        else:
            print(f"❌ {len(ports_to_scan)} port taranmasına rağmen açık port bulamadık.")
    
    # --- Bitiş ---
    end_time = time.time()
    print("\n" + "="*50)
    print(f"⌛ Akın Tarama Tamamlandı: {end_time - start_time:.2f} saniyede bitirdik. Hızlıyız! 🏎")
    print("="*50)


# Eğer bu dosya doğrudan çalıştırılıyorsa, main fonksiyonunu çağır.
if _name_ == "_main_":
    main()
