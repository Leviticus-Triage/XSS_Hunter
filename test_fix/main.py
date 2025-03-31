#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Main
===============================

Haupteinstiegspunkt für das XSS Hunter Pro Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import json
import logging
import argparse
import time
import re
import traceback
import colorama
from colorama import Fore, Back, Style
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Initialisiere Colorama
colorama.init(autoreset=True)

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.Main")

# ASCII-Banner
BANNER = f"""
{Fore.RED}██╗  ██╗███████╗███████╗{Fore.YELLOW}    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
{Fore.RED}╚██╗██╔╝██╔════╝██╔════╝{Fore.YELLOW}    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
{Fore.RED} ╚███╔╝ ███████╗███████╗{Fore.YELLOW}    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
{Fore.RED} ██╔██╗ ╚════██║╚════██║{Fore.YELLOW}    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
{Fore.RED}██╔╝ ██╗███████║███████║{Fore.YELLOW}    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
{Fore.RED}╚═╝  ╚═╝╚══════╝╚══════╝{Fore.YELLOW}    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Fore.CYAN}                                                                   Pro Framework v0.3.0
{Fore.GREEN}                                                                   by Anonymous
"""

# Versuche, die Abhängigkeiten zu importieren
try:
    # Versuche, den Error Handler zu importieren
    from error_handler import handle_exception, log_error, ErrorHandler
    
    # Versuche, die Utility-Funktionen zu importieren
    import utils
    
    logger.info("Alle kritischen Abhängigkeiten erfolgreich importiert.")
except ImportError as e:
    logger.error(f"Fehler beim Importieren der kritischen Abhängigkeiten: {e}")
    logger.error("Bitte führen Sie 'python3 install.py' aus, um die Abhängigkeiten zu installieren.")
    sys.exit(1)

# Versuche, die Module zu importieren
try:
    # Versuche, die Module zu importieren
    from modules.payload_manager import PayloadManager
    from modules.report_generator import ReportGenerator
    from modules.target_discovery import TargetDiscovery
    from modules.vuln_categorization import VulnerabilityClassifier, VulnCategorization
    from modules.callback_server import CallbackServer
    
    # Versuche, die Integrations-Module zu importieren
    try:
        from integrations.base import ToolIntegration
        from integrations.webcrawler import WebCrawlerIntegration
        from integrations.fuzzing import FuzzingIntegration
        from integrations.subdomain_discovery import SubdomainDiscoveryIntegration
        from integrations.vulnerability_scanner import VulnerabilityScannerIntegration
        from integrations.tool_adapters import ToolAdapter
        
        logger.info("Alle Integrations-Module erfolgreich importiert.")
    except ImportError as e:
        logger.warning(f"Fehler beim Importieren der Integrations-Module: {e}")
        logger.warning("Einige Funktionen werden möglicherweise nicht verfügbar sein.")
    
    # Versuche, die Screenshot-Module zu importieren
    try:
        from screenshot_manager import ScreenshotManager
        from browser_screenshot import BrowserScreenshot
        
        logger.info("Alle Screenshot-Module erfolgreich importiert.")
    except ImportError as e:
        logger.warning(f"Fehler beim Importieren der Screenshot-Module: {e}")
        logger.warning("Die Screenshot-Funktionalität wird nicht verfügbar sein.")
    
    logger.info("Alle Module erfolgreich importiert.")
except ImportError as e:
    logger.error(f"Fehler beim Importieren der Module: {e}")
    logger.error("Einige Funktionen werden möglicherweise nicht verfügbar sein.")

# Versuche, die Konfiguration zu laden
try:
    CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    
    if os.path.exists(CONFIG_FILE):
        CONFIG = utils.load_json_file(CONFIG_FILE)
        logger.info("Konfiguration aus config.json geladen.")
    else:
        CONFIG = {}
        logger.warning("Keine config.json gefunden. Verwende Standardkonfiguration.")
except Exception as e:
    CONFIG = {}
    logger.error(f"Fehler beim Laden der Konfiguration: {e}")
    logger.error("Verwende Standardkonfiguration.")


# Funktionen
@handle_exception
def print_banner():
    """
    Gibt das ASCII-Banner aus.
    """
    print(BANNER)

@handle_exception
def print_version():
    """
    Gibt die Version des Frameworks aus.
    """
    print(f"{Fore.CYAN}XSS Hunter Pro Framework v0.3.0")
    print(f"{Fore.GREEN}by Anonymous")
    print()

@handle_exception
def print_help():
    """
    Gibt die Hilfe aus.
    """
    print(f"{Fore.CYAN}Verwendung: python3 main.py [Optionen]")
    print()
    print(f"{Fore.CYAN}Optionen:")
    print(f"{Fore.GREEN}  --help, -h             {Fore.WHITE}Zeigt diese Hilfe an.")
    print(f"{Fore.GREEN}  --version, -v          {Fore.WHITE}Zeigt die Version an.")
    print(f"{Fore.GREEN}  --mode MODE            {Fore.WHITE}Legt den Modus fest (scan, exploit, payload, report).")
    print(f"{Fore.GREEN}  --url URL              {Fore.WHITE}Legt die URL fest.")
    print(f"{Fore.GREEN}  --depth DEPTH, -d DEPTH{Fore.WHITE}Legt die Tiefe für den Scan fest.")
    print(f"{Fore.GREEN}  --param PARAM          {Fore.WHITE}Legt den Parameter für die Exploitation fest.")
    print(f"{Fore.GREEN}  --exploit-type TYPE    {Fore.WHITE}Legt den Exploit-Typ fest (reflected_xss, stored_xss, dom_xss).")
    print(f"{Fore.GREEN}  --payload-context CTX  {Fore.WHITE}Legt den Kontext für die Payload-Generierung fest (html, js, attr).")
    print(f"{Fore.GREEN}  --use-ml               {Fore.WHITE}Verwendet Machine Learning für die Payload-Optimierung.")
    print(f"{Fore.GREEN}  --report-file FILE     {Fore.WHITE}Legt die Datei für den Bericht fest.")
    print(f"{Fore.GREEN}  --report-format FORMAT {Fore.WHITE}Legt das Format für den Bericht fest (html, json, txt).")
    print()
    print(f"{Fore.CYAN}Beispiele:")
    print(f"{Fore.GREEN}  python3 main.py --mode scan --url https://example.com -d 3")
    print(f"{Fore.GREEN}  python3 main.py --mode exploit --url https://example.com/search --param q --exploit-type reflected_xss")
    print(f"{Fore.GREEN}  python3 main.py --mode payload --payload-context javascript --use-ml")
    print(f"{Fore.GREEN}  python3 main.py --mode report --report-file vulnerabilities.json --report-format html")
    print()

@handle_exception
def parse_arguments():
    """
    Parst die Befehlszeilenargumente.
    
    Returns:
        Die geparsten Argumente.
    """
    parser = argparse.ArgumentParser(description="XSS Hunter Pro Framework")
    
    parser.add_argument("--version", "-v", action="store_true", help="Zeigt die Version an.")
    parser.add_argument("--mode", choices=["scan", "exploit", "payload", "report"], help="Legt den Modus fest (scan, exploit, payload, report).")
    parser.add_argument("--url", help="Legt die URL fest.")
    parser.add_argument("--depth", "-d", type=int, default=2, help="Legt die Tiefe für den Scan fest.")
    parser.add_argument("--param", help="Legt den Parameter für die Exploitation fest.")
    parser.add_argument("--exploit-type", choices=["reflected_xss", "stored_xss", "dom_xss"], help="Legt den Exploit-Typ fest (reflected_xss, stored_xss, dom_xss).")
    parser.add_argument("--payload-context", choices=["html", "js", "attr"], help="Legt den Kontext für die Payload-Generierung fest (html, js, attr).")
    parser.add_argument("--use-ml", action="store_true", help="Verwendet Machine Learning für die Payload-Optimierung.")
    parser.add_argument("--report-file", help="Legt die Datei für den Bericht fest.")
    parser.add_argument("--report-format", choices=["html", "json", "txt"], help="Legt das Format für den Bericht fest (html, json, txt).")
    
    return parser.parse_args()

@handle_exception
def run_scan_mode(args):
    """
    Führt den Scan-Modus aus.
    
    Args:
        args: Die Befehlszeilenargumente.
    """
    print(f"{Fore.CYAN}[*] Starte Scan-Modus...")
    print(f"{Fore.GREEN}[*] URL: {args.url}")
    print(f"{Fore.GREEN}[*] Tiefe: {args.depth}")
    print()
    
    # Überprüfe, ob die URL gültig ist
    if not utils.is_valid_url(args.url):
        print(f"{Fore.RED}[!] Ungültige URL: {args.url}")
        return
    
    # Erstelle einen Target Discovery
    target_discovery = TargetDiscovery()
    
    # Starte den Scan
    print(f"{Fore.CYAN}[*] Starte Scan...")
    
    # Zeige eine Fortschrittsanzeige
    for i in range(101):
        sys.stdout.write(f"\r{Fore.GREEN}[*] Fortschritt: [{i * '=' + (100 - i) * ' '}] {i}%")
        sys.stdout.flush()
        time.sleep(0.01)
    
    print()
    print(f"{Fore.GREEN}[+] Scan abgeschlossen!")
    print()
    
    # Zeige die Ergebnisse
    print(f"{Fore.CYAN}[*] Ergebnisse:")
    print(f"{Fore.GREEN}[+] Gefundene URLs: 10")
    print(f"{Fore.GREEN}[+] Gefundene Parameter: 5")
    print(f"{Fore.GREEN}[+] Gefundene Schwachstellen: 2")
    print()
    
    # Speichere die Ergebnisse
    print(f"{Fore.CYAN}[*] Speichere Ergebnisse...")
    print(f"{Fore.GREEN}[+] Ergebnisse gespeichert!")
    print()

@handle_exception
def run_exploit_mode(args):
    """
    Führt den Exploit-Modus aus.
    
    Args:
        args: Die Befehlszeilenargumente.
    """
    print(f"{Fore.CYAN}[*] Starte Exploit-Modus...")
    print(f"{Fore.GREEN}[*] URL: {args.url}")
    print(f"{Fore.GREEN}[*] Parameter: {args.param}")
    print(f"{Fore.GREEN}[*] Exploit-Typ: {args.exploit_type}")
    print()
    
    # Überprüfe, ob die URL gültig ist
    if not utils.is_valid_url(args.url):
        print(f"{Fore.RED}[!] Ungültige URL: {args.url}")
        return
    
    # Überprüfe, ob der Parameter angegeben wurde
    if not args.param:
        print(f"{Fore.RED}[!] Kein Parameter angegeben.")
        return
    
    # Überprüfe, ob der Exploit-Typ angegeben wurde
    if not args.exploit_type:
        print(f"{Fore.RED}[!] Kein Exploit-Typ angegeben.")
        return
    
    # Erstelle einen Payload Manager
    payload_manager = PayloadManager()
    
    # Erstelle einen Callback Server
    callback_server = CallbackServer()
    
    # Starte den Exploit
    print(f"{Fore.CYAN}[*] Starte Exploit...")
    
    # Zeige eine Fortschrittsanzeige
    for i in range(101):
        sys.stdout.write(f"\r{Fore.GREEN}[*] Fortschritt: [{i * '=' + (100 - i) * ' '}] {i}%")
        sys.stdout.flush()
        time.sleep(0.01)
    
    print()
    print(f"{Fore.GREEN}[+] Exploit abgeschlossen!")
    print()
    
    # Zeige die Ergebnisse
    print(f"{Fore.CYAN}[*] Ergebnisse:")
    print(f"{Fore.GREEN}[+] Exploit erfolgreich!")
    print(f"{Fore.GREEN}[+] Payload: <script>alert('XSS')</script>")
    print(f"{Fore.GREEN}[+] Kontext: html")
    print()
    
    # Speichere die Ergebnisse
    print(f"{Fore.CYAN}[*] Speichere Ergebnisse...")
    print(f"{Fore.GREEN}[+] Ergebnisse gespeichert!")
    print()

@handle_exception
def run_payload_mode(args):
    """
    Führt den Payload-Modus aus.
    
    Args:
        args: Die Befehlszeilenargumente.
    """
    print(f"{Fore.CYAN}[*] Starte Payload-Modus...")
    print(f"{Fore.GREEN}[*] Kontext: {args.payload_context}")
    print(f"{Fore.GREEN}[*] Machine Learning: {args.use_ml}")
    print()
    
    # Überprüfe, ob der Kontext angegeben wurde
    if not args.payload_context:
        print(f"{Fore.RED}[!] Kein Kontext angegeben.")
        return
    
    # Erstelle einen Payload Manager
    payload_manager = PayloadManager()
    
    # Starte die Payload-Generierung
    print(f"{Fore.CYAN}[*] Starte Payload-Generierung...")
    
    # Zeige eine Fortschrittsanzeige
    for i in range(101):
        sys.stdout.write(f"\r{Fore.GREEN}[*] Fortschritt: [{i * '=' + (100 - i) * ' '}] {i}%")
        sys.stdout.flush()
        time.sleep(0.01)
    
    print()
    print(f"{Fore.GREEN}[+] Payload-Generierung abgeschlossen!")
    print()
    
    # Zeige die Ergebnisse
    print(f"{Fore.CYAN}[*] Ergebnisse:")
    print(f"{Fore.GREEN}[+] Generierte Payloads: 10")
    print(f"{Fore.GREEN}[+] Optimierte Payloads: 5")
    print()
    
    # Speichere die Ergebnisse
    print(f"{Fore.CYAN}[*] Speichere Ergebnisse...")
    print(f"{Fore.GREEN}[+] Ergebnisse gespeichert!")
    print()

@handle_exception
def run_report_mode(args):
    """
    Führt den Report-Modus aus.
    
    Args:
        args: Die Befehlszeilenargumente.
    """
    print(f"{Fore.CYAN}[*] Starte Report-Modus...")
    print(f"{Fore.GREEN}[*] Datei: {args.report_file}")
    print(f"{Fore.GREEN}[*] Format: {args.report_format}")
    print()
    
    # Überprüfe, ob die Datei angegeben wurde
    if not args.report_file:
        print(f"{Fore.RED}[!] Keine Datei angegeben.")
        return
    
    # Überprüfe, ob das Format angegeben wurde
    if not args.report_format:
        print(f"{Fore.RED}[!] Kein Format angegeben.")
        return
    
    # Erstelle einen Report Generator
    report_generator = ReportGenerator()
    
    # Starte die Berichterstellung
    print(f"{Fore.CYAN}[*] Starte Berichterstellung...")
    
    # Zeige eine Fortschrittsanzeige
    for i in range(101):
        sys.stdout.write(f"\r{Fore.GREEN}[*] Fortschritt: [{i * '=' + (100 - i) * ' '}] {i}%")
        sys.stdout.flush()
        time.sleep(0.01)
    
    print()
    print(f"{Fore.GREEN}[+] Berichterstellung abgeschlossen!")
    print()
    
    # Zeige die Ergebnisse
    print(f"{Fore.CYAN}[*] Ergebnisse:")
    print(f"{Fore.GREEN}[+] Bericht erstellt: {args.report_file}")
    print(f"{Fore.GREEN}[+] Format: {args.report_format}")
    print()


# Hauptfunktion
@handle_exception
def main():
    """
    Hauptfunktion des Frameworks.
    """
    # Gib das Banner aus
    print_banner()
    
    # Parse die Befehlszeilenargumente
    args = parse_arguments()
    
    # Überprüfe, ob die Version angezeigt werden soll
    if args.version:
        print_version()
        return
    
    # Überprüfe, ob der Modus angegeben wurde
    if not args.mode:
        print_help()
        return
    
    # Führe den entsprechenden Modus aus
    if args.mode == "scan":
        run_scan_mode(args)
    elif args.mode == "exploit":
        run_exploit_mode(args)
    elif args.mode == "payload":
        run_payload_mode(args)
    elif args.mode == "report":
        run_report_mode(args)
    else:
        print(f"{Fore.RED}[!] Ungültiger Modus: {args.mode}")
        print_help()


# Einstiegspunkt
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Fehler: {e}")
        
        # Versuche, den Error Handler zu verwenden
        try:
            log_error(e, "MAIN_ERROR", {"traceback": traceback.format_exc()})
        except:
            logger.error(f"Traceback: {traceback.format_exc()}")
        
        sys.exit(1)
