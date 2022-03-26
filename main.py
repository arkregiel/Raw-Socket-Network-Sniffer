import os

if os.name == 'nt':
        print('[!!] Ten sniffer działa pod linuxem, przepraszamy :(')
        quit()

from PacketSniffer.Sniffer import Sniffer


INTERFACE = 'wlan0'


if __name__ == '__main__':
    print('[+] Tworzenie Sniffera')
    sniffer = Sniffer(INTERFACE, verbose=True, output_file='captured.txt')

    print('[+] Rozpoczynanie przechwytywania')
    print("[+] Naciśnij Ctrl + C aby zatrzymać\n\n")
    sniffer.start_sniffing()
