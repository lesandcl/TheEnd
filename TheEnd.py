#!/bin/python3
import scapy.all
import sys


def ayuda():
    print("""
    Para ejecutar este escript se requieren 3 elementos principalmente:
    1.- Archivo de captura en formato .pcapng
    2.- Primer número mágico
    3.- Segundo número mágico
    
    python <TheEnd.pcapng> <1> <2>
    
    """)


def main():
    scapy.all.load_contrib('ospf')
    scapy.all.load_contrib('eigrp')
    if len(sys.argv) == 1 or len(sys.argv) > 4:
        ayuda()
    if len(sys.argv) == 4:
        try:
            nombre_captura = sys.argv[1]
            primer_numero = int(sys.argv[2])
            segundo_numero = int(sys.argv[3])
        except:
            print("Error en el ingreso de parámetros.")
            ayuda()
            exit(1)
        try:
            lista_pdus = scapy.all.PcapReader(nombre_captura).read_all()
            pkt1 = lista_pdus[primer_numero]
            pkt2 = lista_pdus[segundo_numero]
            primera_mitad_flag = pkt2.tlvlist[0].value[-16:].decode()
            segunda_mitad_flag = ""
            lista_octetos = pkt1.neighbors[0].split('.')
            for octeto in lista_octetos:
                segunda_mitad_flag += chr(int(octeto))
            print(primera_mitad_flag + "f" + segunda_mitad_flag)
        except:
            print("Error en los números mágicos.")
            ayuda()

if __name__ == "__main__":
    main()