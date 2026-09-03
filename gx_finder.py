#!/usr/bin/env python3

import os
import socket
from datetime import datetime

START_PORT = 1
END_PORT = 1024
TIMEOUT = 0.5

RESULTS_DIR = "results"
REPORT_FILE = os.path.join(RESULTS_DIR, "scan.txt")


def prepare_directories():
    os.makedirs(RESULTS_DIR, exist_ok=True)


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((ip, port))
            return result == 0

    except socket.timeout:
        return False

    except socket.error:
        return False


def main():
    prepare_directories()

    print("=" * 50)
    print("        GxFinder - TCP Scanner")
    print("=" * 50)

    target = input("Objetivo (IP o dominio): ").strip()

    if not target:
        print("[!] Debes introducir un objetivo.")
        return

    ip = resolve_target(target)

    if ip is None:
        print("[!] No se pudo resolver el objetivo.")
        return

    print(f"[+] Objetivo : {target}")
    print(f"[+] IP       : {ip}")
    print(f"[+] Puertos  : {START_PORT}-{END_PORT}")
    print()

    start_time = datetime.now()

    open_ports = []

    for port in range(START_PORT, END_PORT + 1):
        if scan_port(ip, port):
            print(f"[+] Puerto abierto: {port}")
            open_ports.append(port)

    end_time = datetime.now()

    with open(REPORT_FILE, "w", encoding="utf-8") as report:
        report.write("GxFinder - Reporte de escaneo\n")
        report.write("=" * 40 + "\n")
        report.write(f"Objetivo: {target}\n")
        report.write(f"IP: {ip}\n")
        report.write(f"Inicio: {start_time}\n")
        report.write(f"Fin: {end_time}\n")
        report.write("\nPuertos abiertos:\n")

        if open_ports:
            for port in open_ports:
                report.write(f"- {port}\n")
        else:
            report.write("Ninguno encontrado.\n")

    print()
    print(f"[+] Escaneo terminado.")
    print(f"[+] Puertos abiertos: {len(open_ports)}")
    print(f"[+] Reporte guardado en: {REPORT_FILE}")


if __name__ == "__main__":
    main()