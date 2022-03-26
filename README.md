# Sniffer sieciowy z użyciem surowych gniazd (Linux)

Implementacja sniffera sieciowego bazującego na surowych gniazdach, który przechwytuje ramki i przedstawia część informacji (np. źródłowy i docelowy adres MAC, źródłowy i docelowy adres IPv4, źródłowy i docelowy port) w postaci czytelnej dla człowieka

W pliku `Dissector.py` znajdują się klasy reprezentujące struktury nagłówków wybranych protokołów sieciowych, oraz funkcja `service_lookup`, która próbuje odgadnąć uruchomioną usługę na podstawie danych numerów portów

```python
service_lookup(src_port, dst_port)
```

W pliku `Sniffer.py` znajduje się klasa `Sniffer`, która opisuje zachowanie sniffera. Korzysta z klas w pliku `Dissector.py` do prezentowania danych z pakietów w postaci czytelnej dla człowieka

```python
sniffer = Sniffer("eth0", verbose=True, output_file='captured.txt')
```

Konstruktor przujmuje argumenty:

- `interface` - NIC, z którego będą przechwytywane ramki (argument obowiązkowy)
- `verbose` - czy wypisywać wyniki na stdout (opcjonalne)
- `output_file` - plik, do którego zapisać wyniki (opcjonalne)

Na chwilę obecną program obsługuje tylko protokoły:

- IPv4
- ARP
- ICMP
- UDP
- TCP