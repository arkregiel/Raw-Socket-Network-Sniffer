# Sniffer sieciowy z użyciem surowych gniazd (Linux)

Implementacja sniffera sieciowego bazującego na surowych gniazdach, który przechwytuje ramki i przedstawia część informacji (np. źródłowy i docelowy adres MAC, źródłowy i docelowy adres IPv4, źródłowy i docelowy port) w postaci czytelnej dla człowieka. Tego typu oprogramowanie pozwala zaobserwować zastosowanie teoretycznego modelu TCP/IP w praktyce

Z uwagi na wykorzystanie surowego gniazda, program należy uruchamiać z opcją `sudo`

```
$ sudo python main.py
```

```
sposób użycia:

	$ sudo python main.py -i <interface> [options]

opcje:

	-h --help			wyświetla tę pomoc
	-i --interface=<interface>	interfejs, z którym powiązać gniazdo
	-v --verbose			wyświetlanie danych na ekran
	-o --outputfile=<filename>	plik, do którego zapisać dane
	-d --dump			czy zrzucać surowe przechwycone dane do pliku

przykład:

$ sudo python main.py -i wlan0 --verbose -o captured.txt
```

Na chwilę obecną program obsługuje tylko protokoły:

- IPv4
- ARP
- ICMP
- UDP
- TCP
- DNS
- DHCP

## PacketSniffer

### Dissector.py

W tym pliku znajdują się następujące klasy, próbujące odwzorować strukturę nagłówka danego protokołu:

- `EthernetHeader`
- `IPHeader`
- `ARPHeader`
- `ICMPHeader`
- `TCPHeader`
- `UDPHeader`
- `DNSHeader`
- `DHCPHeader`

Jako parametr konstruktora każda z tych klas przyjmuje bufor rozpoczynający się nagłówkiem danego protokołu i tworzy jego strukturę, podobnie jak w języku C dzięki modułowi `ctypes`

```python
ip_header = Dissector.IPHeader(buf)
```

Struktura `ctypes` klasy `IPHeader` mapuje pierwsze 20 bajtów otrzymanego bufora na _przyjazny_ nagłówek IP (w pozostałych klasach jest analogicznie dla innych protokołów)

W tym samym pliku jest również funkcja `service_lookup`, która na podstawie podanych portów zgaduje, jaka usługa jest uruchomiona

```python
def service_lookup(src_port, dst_port=-1):
    """Zgaduje usługę za pomocą używanych numerów portów"""
    port_to_service_map = {
        20: 'FTP (data transfer)',
        21: 'FTP (command)',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        43: 'WHOIS',
        49: 'TACACS',
        53: 'DNS',
        80: 'HTTP',
        88: 'Kerberos',
        110: 'POP3',
        143: 'IMAP',
        161: 'SNMP',
        162: 'SNMP (trap)',
        443: 'HTTPS',
    }

    if src_port in port_to_service_map.keys():
        return port_to_service_map[src_port]
    elif dst_port in port_to_service_map.keys():
        return port_to_service_map[dst_port]
    else:
        return 'Unknown'
```

Z tej funkcji korzystają klasy `TCPHeader` oraz `UDPHeader`

### Sniffer.py

W tym pliku znajduje się klasa `Sniffer` odpowiedzialna za funkcjonalność narzędzia. Wykorzystuje klasy z modułu `Dissector.py` do przedstawiania przechwyconych danych w czytelnej dla człowieka formie

```python
sniffer = Sniffer("eth0", verbose=True, output_file='captured.txt', dump=False)
```

Konstruktor przujmuje argumenty:

- `interface` - NIC, z którego będą przechwytywane ramki (argument obowiązkowy)
- `verbose` - czy wypisywać wyniki na stdout (opcjonalne, domyślnie `True`)
- `output_file` - plik, do którego zapisać wyniki (opcjonalne, domyślnie `None`)
- `dump` - czy zrzucać surowe przechwycone dane (opcjonalne, domyślnie `True`)

W metodzie `__init__` jest tworzone _surowe gniazdo_, które następnie zostaje powiązane z podanym interfejsem

funkcja `socket` z modułu `socket` przyjmuje argumenty:

- rodzina `socket.AF_PACKET`
- typ `socket.SOCK_RAW`
- stała `ETH_P_ALL` (wszystkie protokoły)

Klasa `Sniffer` zawiera metody:

- `hexdump(self, buffer)`
    - Tworzy zrzut szesnastkowy z otrzymanej ramki
- `start_sniffing(self)`
    - rozpoczyna przechwytywanie pakietów
    - przełącza kartę sieciową w tryb mieszany (_promiscuous_)
    - przechwytuje ramki i przekazuje je do dalszej analizy
    - aby zatrzymać przechwytywanie należy nacisnąć _**Ctrl + C**_
- `promisc_mode(self, enable=True)`
    - jeśli parametr `enable` jest prawdą, przełącza kartę w tryb mieszany
    - jeśli `False`, wyłącza tryb mieszany
- `stop_sniffing(self)`
    - wyłącza tryb mieszany na interfejsie
- `dissect_eth(self, frame)`
    - z otrzymanej ramki tworzy obiekt `Dissector.EthernetHeader` i określa protokół warstwy wyższej
- `dissect_ip(self, ip_header, packet)`
    - z otrzymanego pakietu IP tworzy obiekt `Dissector.IPHeader` i określa protokół warstwy wyżej
    - w przypadku warstwy transportowej (TCP, UDP) określa usługę
- `dissect_app_layer(self, service, segment)`
    - na podstawie argumentu `service` określa protokół warstwy aplikacji i przetwarza jego dane
