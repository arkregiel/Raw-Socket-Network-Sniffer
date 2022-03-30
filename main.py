import os
import sys
import getopt

if os.name == 'nt':
    print('[!!] Ten sniffer działa pod linuxem, przepraszamy :(')
    quit()

from PacketSniffer.Sniffer import Sniffer


def usage():
    """Sposób użycia"""
    print("\nsposób użycia:\n")
    print(f"\t$ sudo python {sys.argv[0]} -i <interface> [options]\n")
    print("opcje:\n")
    print("\t-h --help\t\t\twyświetla tę pomoc")
    print("\t-i --interface=<interface>\tinterfejs, z którym powiązać gniazdo")
    print("\t-v --verbose\t\t\twyświetlanie danych na ekran")
    print("\t-o --outputfile=<filename>\tplik, do którego zapisać dane")
    print("\t-d --dump\t\t\tczy zrzucać surowe przechwycone dane do pliku")
    print("\nprzykład:\n")
    print(f"$ sudo python {sys.argv[0]} -i wlan0 --verbose -o captured.txt")
    print()
    quit()

def parse_argv():
    if not len(sys.argv[1:]):
        usage()

    interface = None
    verbose = False
    output_file = None
    dump = False

    try:
        opts = getopt.getopt(sys.argv[1:], "hi:vo:d",
                            ["help", "interface=", "verbose", "outputfile=", "dump"])[0]
    except getopt.GetoptError as e:
        print('[!!] ' + str(e))
        usage()

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-i', '--interface'):
            interface = a
        elif o in ('-v', '--verbose'):
            verbose = True
        elif o in ('-o', '--outputfile'):
            output_file = a
        elif o in ('-d', '--dump'):
            dump = True
        else:
            assert False, "Nieznana opcja"

    return interface, verbose, output_file, dump




if __name__ == '__main__':
    interface, verbose, output_file, dump = parse_argv()

    if not interface:
        usage()

    print('[+] Tworzenie Sniffera')
    sniffer = Sniffer(interface=interface, verbose=verbose, output_file=output_file, dump=dump)

    print('[+] Rozpoczynanie przechwytywania')
    print("[+] Naciśnij Ctrl + C aby zatrzymać\n\n")
    sniffer.start_sniffing()
