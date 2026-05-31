import socket
import threading
import time
from datetime import datetime
from collections import OrderedDict

# Base de dados de serviços expandida
SERVICOS = {
    20: "FTP-Dados", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 119: "NNTP",
    123: "NTP", 135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD", 543: "Kerberos",
    544: "Kerberos", 546: "DHCPv6", 547: "DHCPv6", 554: "RTSP",
    587: "SMTP", 631: "IPP", 636: "LDAPS", 873: "Rsync", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1337: "Waste",
    1433: "MSSQL", 1434: "MSSQL-Mon", 1723: "PPTP", 1883: "MQTT",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL", 2086: "WHM",
    2087: "WHM-SSL", 2181: "ZooKeeper", 2222: "DirectAdmin", 2375: "Docker",
    2376: "Docker-SSL", 2379: "etcd", 2380: "etcd", 2480: "OrientDB",
    3000: "Grafana", 3128: "Squid", 3306: "MySQL", 3307: "MariaDB",
    3389: "RDP", 3690: "SVN", 4000: "RemoteAnything", 4040: "CouchDB",
    4243: "Docker", 4443: "AJP", 4489: "AppleWireless", 4567: "Galera",
    4664: "GoogleDesktop", 4848: "GlassFish", 5000: "UPnP", 5005: "JavaDebug",
    5006: "JavaDebug", 5007: "JavaDebug", 5222: "XMPP", 5269: "XMPP",
    5432: "PostgreSQL", 5555: "AndroidADB", 5631: "pcAnywhere",
    5632: "pcAnywhere", 5672: "AMQP", 5800: "VNC", 5900: "VNC",
    5901: "VNC", 5984: "CouchDB", 6000: "X11", 6379: "Redis", 7000: "Cassandra",
    7001: "WebLogic", 7077: "Spark", 7474: "Neo4j", 7475: "Neo4j",
    7547: "CWMP", 8000: "HTTP-Alt", 8008: "HTTP-Alt", 8009: "AJP",
    8010: "HTTP", 8080: "HTTP-Alt", 8081: "HTTP-Alt", 8086: "InfluxDB",
    8087: "HTTP", 8088: "Hadoop", 8089: "Splunk", 8090: "HTTP",
    8091: "Couchbase", 8092: "Couchbase", 8093: "Couchbase", 8094: "Couchbase",
    8095: "Couchbase", 8096: "Emby", 8097: "Emby", 8098: "Riak",
    8123: "HomeAssistant", 8140: "Puppet", 8161: "ActiveMQ", 8181: "Hazelcast",
    8282: "HTTP", 8333: "Bitcoin", 8443: "HTTPS-Alt", 8500: "Consul",
    8600: "Consul-DNS", 8883: "MQTT-SSL", 8888: "HTTP-Alt", 9000: "PHP-FPM",
    9001: "Tor", 9042: "Cassandra", 9090: "Prometheus", 9091: "Prometheus",
    9092: "Kafka", 9100: "NodeExporter", 9110: "Plex", 9160: "Cassandra",
    9200: "Elasticsearch", 9300: "Elasticsearch", 9418: "Git", 9999: "Distinct",
    10000: "Webmin", 11211: "Memcached", 15672: "RabbitMQ", 16010: "HBase",
    18080: "Spark", 20000: "DNP3", 20001: "DNP3", 25565: "Minecraft",
    27017: "MongoDB", 27018: "MongoDB", 27019: "MongoDB", 28015: "RethinkDB",
    31337: "BackOrifice", 35871: "GlusterFS", 37777: "Dahua", 40000: "NRPE",
    40404: "Sonexis", 43594: "RSPS", 44158: "Helium", 47808: "BACnet",
    49152: "WindowsRPC", 49153: "WindowsRPC", 49154: "WindowsRPC"
}

# Banner grabbing signatures
def banner_grabbing(host, porta, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, porta))
        
        # Probe específico por serviço
        probe = ""
        if porta == 22:  # SSH
            probe = ""
        elif porta in [80, 443, 8080, 8443]:  # HTTP/HTTPS
            probe = "HEAD / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
        elif porta == 21:  # FTP
            probe = ""
        elif porta == 25:  # SMTP
            probe = "EHLO test\r\n"
        elif porta == 110:  # POP3
            probe = "CAPA\r\n"
        elif porta == 143:  # IMAP
            probe = "A001 CAPABILITY\r\n"
        else:
            return None
        
        if probe:
            sock.send(probe.encode())
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:150]  # Limit output
        sock.close()
        return None
    except:
        return None

class Scanner:
    def __init__(self, host, start_port, end_port, max_threads=500, timeout=1.5):
        self.host = host
        self.start_port = start_port
        self.end_port = end_port
        self.max_threads = max_threads
        self.timeout = timeout
        self.open_ports = []
        self.filtered_ports = []
        self.lock = threading.Lock()
        self.total_ports = end_port - start_port + 1
        self.scanned = 0
        
    def scan_port(self, porta):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            start_time = time.time()
            result = sock.connect_ex((self.host, porta))
            elapsed = (time.time() - start_time) * 1000
            
            if result == 0:
                servico = SERVICOS.get(porta, "Unknown")
                banner = banner_grabbing(self.host, porta, self.timeout)
                
                with self.lock:
                    self.open_ports.append({
                        'port': porta,
                        'service': servico,
                        'banner': banner,
                        'rtt_ms': round(elapsed, 2)
                    })
            elif result == 10060:  # Timeout
                with self.lock:
                    self.filtered_ports.append(porta)
            
            sock.close()
        except Exception:
            pass
        
        with self.lock:
            self.scanned += 1
            if self.scanned % 100 == 0:
                progress = (self.scanned / self.total_ports) * 100
                print(f"  Progresso: {self.scanned}/{self.total_ports} ({progress:.1f}%)", end='\r')
    
    def run_scan(self):
        print(f"\n🔍 Scanner TCP SYN-like Mode")
        print(f"📡 Host: {self.host}")
        print(f"📊 Range: {self.start_port}-{self.end_port}")
        print(f"⚡ Threads: {self.max_threads}")
        print(f"⏱️  Timeout: {self.timeout}s")
        print(f"📅 Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        
        thread_pool = []
        for porta in range(self.start_port, self.end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(porta,))
            thread_pool.append(t)
            t.start()
            
            # Limit concurrent threads
            if len(thread_pool) >= self.max_threads:
                for t in thread_pool:
                    t.join()
                thread_pool = []
        
        # Wait remaining threads
        for t in thread_pool:
            t.join()
        
        print(f"\n\n📅 End: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        return self.open_ports

def detect_os_fingerprint(host):
    """Detecção básica de SO via TTL"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(2)
    except:
        return "Não detectável (RAW socket precisa de admin)"
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, 80))
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        sock.close()
        
        if ttl <= 64:
            return "Linux/Unix (TTL <= 64)"
        elif ttl <= 128:
            return "Windows (TTL <= 128)"
        else:
            return "Solaris/AIX (TTL ~255)"
    except:
        return "Indeterminado"

def print_report(open_ports, host, scan_time):
    print("\n" + "=" * 70)
    print("                     RELATÓRIO DE SCAN")
    print("=" * 70)
    
    os_fingerprint = detect_os_fingerprint(host)
    print(f"\n🖥️  Host: {host}")
    print(f"🔍 SO Provável: {os_fingerprint}")
    print(f"🎯 Portas Abertas: {len(open_ports)}")
    
    if open_ports:
        print("\n📋 LISTA DETALHADA:")
        print("-" * 70)
        print(f"{'PORTA':>8} {'ESTADO':<10} {'SERVIÇO':<20} {'RTT(ms)':<10} {'BANNER'}")
        print("-" * 70)
        
        for p in sorted(open_ports, key=lambda x: x['port']):
            banner_preview = p['banner'][:40] if p['banner'] else "N/A"
            print(f"{p['port']:>8} {'OPEN':<10} {p['service']:<20} {p['rtt_ms']:<10} {banner_preview}")
        
        print("\n📈 ESTATÍSTICAS:")
        total_services = len(set(p['service'] for p in open_ports))
        print(f"  • Serviços distintos: {total_services}")
        print(f"  • Menor RTT: {min(p['rtt_ms'] for p in open_ports)}ms")
        print(f"  • Maior RTT: {max(p['rtt_ms'] for p in open_ports)}ms")
        
        # Agrupamento por categoria
        web_ports = [p for p in open_ports if p['service'] in ['HTTP', 'HTTPS', 'HTTP-Alt']]
        db_ports = [p for p in open_ports if 'SQL' in p['service'] or p['service'] in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']]
        remote_ports = [p for p in open_ports if p['service'] in ['SSH', 'Telnet', 'RDP', 'VNC']]
        
        if web_ports:
            print(f"\n🌐 WEB: {', '.join(str(p['port']) for p in web_ports)}")
        if db_ports:
            print(f"💾 DATABASE: {', '.join(str(p['port']) for p in db_ports)}")
        if remote_ports:
            print(f"🖥️  REMOTE: {', '.join(str(p['port']) for p in remote_ports)}")
    
    else:
        print("\n🔒 Nenhuma porta aberta detectada")
    
    print("\n" + "=" * 70)
    print(f"⏱️  Tempo total: {scan_time:.2f} segundos")
    print("⚠️  Uso autorizado apenas em redes próprias")
    print("=" * 70)

def main():
    print("=" * 70)
    print("            SCANNER DE PORTAS PROFISSIONAL v3.0")
    print("           Stealth SYN-like Multi-threaded Scanner")
    print("=" * 70)
    print("\n⚠️  ATENÇÃO: Uso permitido APENAS em:")
    print("   • Próprias máquinas")
    print("   • Redes com permissão explícita")
    print("   • Ambientes de teste controlados")
    print("-" * 70)
    
    host = input("\n🎯 Host/IP (padrão: localhost): ").strip() or "localhost"
    
    try:
        ip = socket.gethostbyname(host)
        print(f"   Resolvido: {host} → {ip}")
    except:
        print("   ✗ Falha na resolução DNS")
    
    print("\n📌 MODOS DE SCAN:")
    print("   [1] Rápido (1-1024, top portas)")
    print("   [2] Completo (1-65535, padrão)")
    print("   [3] Personalizado")
    
    modo = input("\nEscolha: ").strip() or "2"
    
    if modo == "1":
        start, end = 1, 1024
    elif modo == "2":
        start, end = 1, 65535
    else:
        start = int(input("Porta inicial: ") or 1)
        end = int(input("Porta final: ") or 65535)
    
    threads = int(input("\n⚡ Threads (padrão 500): ") or 500)
    timeout = float(input("⏱️  Timeout segundos (padrão 1.5): ") or 1.5)
    
    # Validações
    if start < 1:
        start = 1
    if end > 65535:
        end = 65535
    if start > end:
        start, end = end, start
    
    total_ports = end - start + 1
    print(f"\n📊 Total de portas a escanear: {total_ports}")
    print(f"⚙️  Configurações: {threads} threads | {timeout}s timeout")
    input("\n▶️  Pressione ENTER para iniciar...")
    
    scanner = Scanner(host, start, end, threads, timeout)
    scan_start = time.time()
    open_ports = scanner.run_scan()
    scan_time = time.time() - scan_start
    
    print_report(open_ports, host, scan_time)
    
    # Export JSON
    if open_ports:
        import json
        export = input("\n💾 Exportar resultados para JSON? (s/N): ").lower()
        if export == 's':
            filename = f"scan_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump({
                    'host': host,
                    'ip': ip,
                    'timestamp': datetime.now().isoformat(),
                    'scan_time_seconds': scan_time,
                    'open_ports': open_ports
                }, f, indent=2)
            print(f"   ✓ Exportado para {filename}")

if __name__ == "__main__":
    main()