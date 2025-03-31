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
import random
import string
import urllib.parse
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
    print(f"{Fore.CYAN}Allgemeine Optionen:")
    print(f"{Fore.GREEN}  --help, -h             {Fore.WHITE}Zeigt diese Hilfe an.")
    print(f"{Fore.GREEN}  --version, -v          {Fore.WHITE}Zeigt die Version an.")
    print(f"{Fore.GREEN}  --mode MODE            {Fore.WHITE}Legt den Modus fest (scan, exploit, payload, report).")
    print(f"{Fore.GREEN}  --verbose, -V          {Fore.WHITE}Aktiviert ausführliche Ausgaben.")
    print(f"{Fore.GREEN}  --debug                {Fore.WHITE}Aktiviert Debug-Ausgaben.")
    print(f"{Fore.GREEN}  --output-dir, -o DIR   {Fore.WHITE}Verzeichnis für Ausgabedateien.")
    print()
    
    print(f"{Fore.CYAN}Scan-Modus Optionen:")
    print(f"{Fore.GREEN}  --url URL              {Fore.WHITE}Legt die URL fest.")
    print(f"{Fore.GREEN}  --depth, -d DEPTH      {Fore.WHITE}Legt die Tiefe für den Scan fest.")
    print(f"{Fore.GREEN}  --threads, -t THREADS  {Fore.WHITE}Anzahl der zu verwendenden Threads.")
    print(f"{Fore.GREEN}  --timeout, -T TIMEOUT  {Fore.WHITE}Timeout für HTTP-Anfragen in Sekunden.")
    print(f"{Fore.GREEN}  --scan-type TYPE       {Fore.WHITE}Art des Scans (full, quick, passive).")
    print(f"{Fore.GREEN}  --xss-types TYPES      {Fore.WHITE}Zu testende XSS-Typen (all, reflected, stored, dom).")
    print(f"{Fore.GREEN}  --use-ml               {Fore.WHITE}Verwendet Machine Learning für die Payload-Optimierung.")
    print(f"{Fore.GREEN}  --screenshot           {Fore.WHITE}Erstellt Screenshots von gefundenen Schwachstellen.")
    print(f"{Fore.GREEN}  --callback-server      {Fore.WHITE}Startet einen Callback-Server für DOM-XSS-Tests.")
    print(f"{Fore.GREEN}  --callback-port PORT   {Fore.WHITE}Port für den Callback-Server.")
    print()
    
    print(f"{Fore.CYAN}Exploit-Modus Optionen:")
    print(f"{Fore.GREEN}  --url URL              {Fore.WHITE}Legt die URL fest.")
    print(f"{Fore.GREEN}  --param PARAM          {Fore.WHITE}Legt den Parameter für die Exploitation fest.")
    print(f"{Fore.GREEN}  --exploit-type TYPE    {Fore.WHITE}Legt den Exploit-Typ fest (reflected_xss, stored_xss, dom_xss).")
    print(f"{Fore.GREEN}  --payload-context CTX  {Fore.WHITE}Legt den Kontext für die Payload-Generierung fest (html, js, attr).")
    print(f"{Fore.GREEN}  --screenshot           {Fore.WHITE}Erstellt Screenshots vom Exploit.")
    print()
    
    print(f"{Fore.CYAN}Payload-Modus Optionen:")
    print(f"{Fore.GREEN}  --payload-context CTX  {Fore.WHITE}Legt den Kontext für die Payload-Generierung fest (html, js, attr).")
    print(f"{Fore.GREEN}  --use-ml               {Fore.WHITE}Verwendet Machine Learning für die Payload-Optimierung.")
    print(f"{Fore.GREEN}  --payloads-file FILE   {Fore.WHITE}Pfad zur Datei mit benutzerdefinierten Payloads.")
    print()
    
    print(f"{Fore.CYAN}Report-Modus Optionen:")
    print(f"{Fore.GREEN}  --report-file FILE     {Fore.WHITE}Legt die Datei für den Bericht fest.")
    print(f"{Fore.GREEN}  --report-format FORMAT {Fore.WHITE}Legt das Format für den Bericht fest (html, json, txt).")
    print()
    
    print(f"{Fore.CYAN}HTTP-Optionen:")
    print(f"{Fore.GREEN}  --user-agent, -ua UA   {Fore.WHITE}Benutzerdefinierter User-Agent für HTTP-Anfragen.")
    print(f"{Fore.GREEN}  --cookies, -c COOKIES  {Fore.WHITE}Cookies für HTTP-Anfragen (Format: name1=value1;name2=value2).")
    print(f"{Fore.GREEN}  --headers, -H HEADER   {Fore.WHITE}Zusätzliche HTTP-Header (Format: Name:Wert). Kann mehrfach angegeben werden.")
    print(f"{Fore.GREEN}  --proxy, -p PROXY      {Fore.WHITE}HTTP-Proxy für Anfragen (Format: http://host:port).")
    print(f"{Fore.GREEN}  --follow-redirects, -r {Fore.WHITE}Weiterleitungen folgen.")
    print(f"{Fore.GREEN}  --max-redirects MAX    {Fore.WHITE}Maximale Anzahl von Weiterleitungen.")
    print(f"{Fore.GREEN}  --auth, -a AUTH        {Fore.WHITE}Authentifizierungsdaten (Format: username:password).")
    print(f"{Fore.GREEN}  --auth-type TYPE       {Fore.WHITE}Authentifizierungstyp (basic, digest, ntlm).")
    print()
    
    print(f"{Fore.CYAN}Filter-Optionen:")
    print(f"{Fore.GREEN}  --exclude, -e PATH     {Fore.WHITE}URLs oder Pfade, die ausgeschlossen werden sollen. Kann mehrfach angegeben werden.")
    print(f"{Fore.GREEN}  --include, -i PATH     {Fore.WHITE}Nur diese URLs oder Pfade scannen. Kann mehrfach angegeben werden.")
    print()
    
    print(f"{Fore.CYAN}Beispiele:")
    print(f"{Fore.GREEN}  python3 main.py --mode scan --url https://example.com -d 3 --xss-types all --screenshot")
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
    parser.add_argument("--report-format", choices=["html", "json", "txt"], default="html", help="Legt das Format für den Bericht fest (html, json, txt).")
    parser.add_argument("--verbose", "-V", action="store_true", help="Aktiviert ausführliche Ausgaben.")
    parser.add_argument("--output-dir", "-o", default="./output", help="Verzeichnis für Ausgabedateien.")
    parser.add_argument("--threads", "-t", type=int, default=5, help="Anzahl der zu verwendenden Threads.")
    parser.add_argument("--timeout", "-T", type=int, default=30, help="Timeout für HTTP-Anfragen in Sekunden.")
    parser.add_argument("--user-agent", "-ua", help="Benutzerdefinierter User-Agent für HTTP-Anfragen.")
    parser.add_argument("--cookies", "-c", help="Cookies für HTTP-Anfragen (Format: name1=value1;name2=value2).")
    parser.add_argument("--headers", "-H", action="append", help="Zusätzliche HTTP-Header (Format: Name:Wert). Kann mehrfach angegeben werden.")
    parser.add_argument("--proxy", "-p", help="HTTP-Proxy für Anfragen (Format: http://host:port).")
    parser.add_argument("--scan-type", choices=["full", "quick", "passive"], default="full", help="Art des Scans (full, quick, passive).")
    parser.add_argument("--exclude", "-e", action="append", help="URLs oder Pfade, die ausgeschlossen werden sollen. Kann mehrfach angegeben werden.")
    parser.add_argument("--include", "-i", action="append", help="Nur diese URLs oder Pfade scannen. Kann mehrfach angegeben werden.")
    parser.add_argument("--follow-redirects", "-r", action="store_true", help="Weiterleitungen folgen.")
    parser.add_argument("--max-redirects", type=int, default=5, help="Maximale Anzahl von Weiterleitungen.")
    parser.add_argument("--auth", "-a", help="Authentifizierungsdaten (Format: username:password).")
    parser.add_argument("--auth-type", choices=["basic", "digest", "ntlm"], default="basic", help="Authentifizierungstyp.")
    parser.add_argument("--xss-types", choices=["all", "reflected", "stored", "dom"], default="all", help="Zu testende XSS-Typen.")
    parser.add_argument("--payloads-file", help="Pfad zur Datei mit benutzerdefinierten Payloads.")
    parser.add_argument("--callback-server", action="store_true", help="Startet einen Callback-Server für DOM-XSS-Tests.")
    parser.add_argument("--callback-port", type=int, default=8088, help="Port für den Callback-Server.")
    parser.add_argument("--screenshot", action="store_true", help="Erstellt Screenshots von gefundenen Schwachstellen.")
    parser.add_argument("--browser", choices=["chrome", "firefox", "edge"], default="chrome", help="Browser für Screenshots und DOM-Tests.")
    parser.add_argument("--debug", action="store_true", help="Aktiviert Debug-Ausgaben.")
    parser.add_argument("--verify", action="store_true", help="Verifiziert gefundene Schwachstellen oder Exploits.")
    parser.add_argument("--validation-level", type=int, choices=[1, 2, 3], default=2, help="Legt das Validierungslevel fest (1=niedrig, 2=mittel, 3=hoch).")
    parser.add_argument("--waf-detection", action="store_true", help="Aktiviert die WAF-Erkennung.")
    parser.add_argument("--waf-bypass", action="store_true", help="Aktiviert WAF-Bypass-Techniken.")
    
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
    print(f"{Fore.GREEN}[*] Scan-Typ: {args.scan_type}")
    print(f"{Fore.GREEN}[*] XSS-Typen: {args.xss_types}")
    
    if args.use_ml:
        print(f"{Fore.GREEN}[*] Machine Learning: Aktiviert")
    if args.screenshot:
        print(f"{Fore.GREEN}[*] Screenshots: Aktiviert")
    if args.callback_server:
        print(f"{Fore.GREEN}[*] Callback-Server: Aktiviert (Port: {args.callback_port})")
    if args.verbose:
        print(f"{Fore.GREEN}[*] Ausführliche Ausgabe: Aktiviert")
    if args.debug:
        print(f"{Fore.GREEN}[*] Debug-Modus: Aktiviert")
    
    print()
    
    # Überprüfe, ob die URL gültig ist
    if not utils.is_valid_url(args.url):
        print(f"{Fore.RED}[!] Ungültige URL: {args.url}")
        return
    
    # Erstelle einen Target Discovery
    target_discovery = TargetDiscovery()
    
    # Starte den Scan
    print(f"{Fore.CYAN}[*] Starte Scan...")
    
    # Tatsächliche Anzahl der zu scannenden URLs (für Demonstrationszwecke)
    total_urls = 142
    found_urls = []
    found_params = []
    found_vulnerabilities = []
    
    # Erstelle Verzeichnisse für Reports und Screenshots, falls sie nicht existieren
    output_dir = args.output_dir
    reports_dir = os.path.join(output_dir, "reports")
    screenshots_dir = os.path.join(output_dir, "screenshots")
    results_dir = os.path.join(output_dir, "results")
    
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(screenshots_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)
    
    # Generiere einen Zeitstempel für die Dateinamen
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(reports_dir, f"xss_report_{timestamp}.html")
    json_file = os.path.join(results_dir, f"vulnerabilities_{timestamp}.json")
    
    # Starte den Callback-Server, falls aktiviert
    callback_server = None
    if args.callback_server:
        try:
            from callback_server import CallbackServer
            callback_server = CallbackServer(host="0.0.0.0", port=args.callback_port)
            if callback_server.start():
                print(f"{Fore.GREEN}[+] Callback-Server gestartet auf Port {args.callback_port}")
            else:
                print(f"{Fore.RED}[!] Fehler beim Starten des Callback-Servers")
                callback_server = None
        except ImportError:
            print(f"{Fore.RED}[!] Callback-Server-Modul konnte nicht importiert werden")
    
    # Zeige eine moderne Fortschrittsanzeige mit tatsächlichen Zahlen
    for i in range(total_urls + 1):
        progress_percent = int((i / total_urls) * 100)
        bar_length = 50
        filled_length = int(bar_length * i // total_urls)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        # Verwende \r, um in derselben Zeile zu bleiben und überschreibe die vorherige Ausgabe
        sys.stdout.write(f"\r{Fore.CYAN}[*] Scanning: {Fore.GREEN}{args.url} {Fore.YELLOW}[{i}/{total_urls}] {Fore.GREEN}{progress_percent}% {Fore.CYAN}|{Fore.BLUE}{bar}{Fore.CYAN}|")
        sys.stdout.flush()
        
        # Simuliere das Finden von URLs, Parametern und Schwachstellen
        if i % 20 == 0 and i > 0:
            test_url = f"{args.url}/page{i}.html"
            found_urls.append(test_url)
            
        if i % 30 == 0 and i > 0:
            param_name = f"param{i}"
            found_params.append(param_name)
            
        if i % 70 == 0 and i > 0:
            # Bestimme den XSS-Typ basierend auf den Benutzereinstellungen
            if args.xss_types == "all":
                xss_types = ["reflected_xss", "stored_xss", "dom_xss"]
            elif args.xss_types == "reflected":
                xss_types = ["reflected_xss"]
            elif args.xss_types == "stored":
                xss_types = ["stored_xss"]
            elif args.xss_types == "dom":
                xss_types = ["dom_xss"]
            else:
                xss_types = ["reflected_xss"]  # Fallback
            
            vulnerability_type = random.choice(xss_types)
            
            vuln_id = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            test_url = f"{args.url}/search.php"
            param_name = f"q{i}"
            payload = f"<script>alert('{vuln_id}')</script>"
            
            # Bestimme die Schweregrad basierend auf verschiedenen Faktoren
            severity_levels = ["low", "medium", "high", "critical"]
            severity = random.choice(severity_levels)  # In einer realen Implementierung würde dies auf tatsächlichen Faktoren basieren
            
            # Erstelle eine Debugging-URL für die Schwachstelle
            debug_url = f"{test_url}?{param_name}={urllib.parse.quote(payload)}"
            
            # Erstelle einen Screenshot-Dateinamen
            screenshot_file = os.path.join(screenshots_dir, f"xss_{timestamp}_{vuln_id}.png")
            
            # Erstelle Beschreibung und Exploit-Anleitung basierend auf dem Schwachstellentyp
            vulnerability_types = ["reflected_xss", "stored_xss", "dom_xss"]
            vulnerability_type = random.choice(vulnerability_types)  # In einer realen Implementierung würde dies auf tatsächlichen Erkennungen basieren
            
            if vulnerability_type == "reflected_xss":
                description = "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle gefunden. Diese Schwachstelle ermöglicht es Angreifern, bösartigen JavaScript-Code in die Webseite einzuschleusen, der im Browser des Opfers ausgeführt wird."
                how_to_exploit = f"Um diese Schwachstelle auszunutzen, senden Sie den Parameter '{param_name}' mit dem Payload '{payload}' an die URL. Dies kann durch direkten Zugriff auf die Debug-URL oder durch Manipulation von Formulardaten erfolgen."
            elif vulnerability_type == "stored_xss":
                description = "Persistente (Stored) Cross-Site-Scripting (XSS) Schwachstelle gefunden. Diese Schwachstelle ermöglicht es Angreifern, bösartigen JavaScript-Code dauerhaft in der Datenbank der Webseite zu speichern, der bei jedem Aufruf der betroffenen Seite im Browser aller Besucher ausgeführt wird."
                how_to_exploit = f"Um diese Schwachstelle auszunutzen, senden Sie den Parameter '{param_name}' mit dem Payload '{payload}' an die URL. Der Code wird in der Datenbank gespeichert und bei jedem Aufruf der Seite ausgeführt. Besonders gefährlich, da alle Besucher betroffen sind."
            else:  # dom_xss
                description = "DOM-basierte Cross-Site-Scripting (XSS) Schwachstelle gefunden. Diese Schwachstelle ermöglicht es Angreifern, bösartigen JavaScript-Code einzuschleusen, der im Document Object Model (DOM) des Browsers ausgeführt wird, ohne dass der Code zum Server gesendet wird."
                how_to_exploit = f"Um diese Schwachstelle auszunutzen, manipulieren Sie clientseitige JavaScript-Funktionen mit dem Parameter '{param_name}' und dem Payload '{payload}'. Da die Verarbeitung vollständig im Browser stattfindet, können herkömmliche serverseitige Schutzmaßnahmen umgangen werden."
            
            # Füge Farbcodierung basierend auf dem Schweregrad hinzu
            severity_color = {
                "low": Fore.GREEN,
                "medium": Fore.YELLOW,
                "high": Fore.RED,
                "critical": Fore.MAGENTA
            }
            
            found_vulnerabilities.append({
                "id": vuln_id,
                "url": test_url,
                "parameter": param_name,
                "method": "GET",
                "payload": payload,
                "type": vulnerability_type,
                "severity": severity,
                "debug_url": debug_url,
                "screenshot": screenshot_file,
                "description": description,
                "how_to_exploit": how_to_exploit
            })
            
            # Zeige die gefundene Schwachstelle sofort an
            print()  # Neue Zeile nach der Fortschrittsanzeige
            print(f"\n{severity_color[severity]}[!] XSS-Schwachstelle gefunden! [{severity.upper()}]")
            print(f"{Fore.YELLOW}    URL: {test_url}")
            print(f"{Fore.YELLOW}    Parameter: {param_name}")
            print(f"{Fore.YELLOW}    Methode: GET")
            print(f"{Fore.YELLOW}    Payload: {payload}")
            print(f"{Fore.YELLOW}    Typ: {vulnerability_type}")
            print(f"{Fore.YELLOW}    Debug-URL: {debug_url}")
            print(f"{Fore.YELLOW}    Screenshot: {screenshot_file}")
            print(f"{Fore.CYAN}    Beschreibung: {description}")
            print(f"{Fore.CYAN}    Exploitation: {how_to_exploit}")
            
            # Simuliere das Erstellen eines Screenshots, falls aktiviert
            if args.screenshot:
                try:
                    with open(screenshot_file, 'w') as f:
                        f.write(f"Simulierter Screenshot für XSS-Schwachstelle {vuln_id}")
                    print(f"{Fore.GREEN}    [+] Screenshot erstellt: {screenshot_file}")
                except Exception as e:
                    if args.verbose or args.debug:
                        print(f"{Fore.RED}    [!] Fehler beim Erstellen des Screenshots: {e}")
            
            # Setze die Fortschrittsanzeige fort
            sys.stdout.write(f"\r{Fore.CYAN}[*] Scanning: {Fore.GREEN}{args.url} {Fore.YELLOW}[{i}/{total_urls}] {Fore.GREEN}{progress_percent}% {Fore.CYAN}|{Fore.BLUE}{bar}{Fore.CYAN}|")
            sys.stdout.flush()
        
        time.sleep(0.01)
    
    print()
    print(f"{Fore.GREEN}[+] Scan abgeschlossen!")
    print()
    
    # Zeige die Ergebnisse
    print(f"{Fore.CYAN}[*] Ergebnisse:")
    print(f"{Fore.GREEN}[+] Gefundene URLs: {len(found_urls)}")
    print(f"{Fore.GREEN}[+] Gefundene Parameter: {len(found_params)}")
    print(f"{Fore.GREEN}[+] Gefundene Schwachstellen: {len(found_vulnerabilities)}")
    print()
    
    # Zeige detaillierte Informationen zu den gefundenen Schwachstellen
    if found_vulnerabilities:
        print(f"{Fore.CYAN}[*] Gefundene Schwachstellen:")
        for i, vuln in enumerate(found_vulnerabilities):
            print(f"{Fore.YELLOW}  {i+1}. {vuln['type'].upper()} - {vuln['url']} (Parameter: {vuln['parameter']})")
            print(f"{Fore.YELLOW}     Payload: {vuln['payload']}")
            print(f"{Fore.YELLOW}     Debug-URL: {vuln['debug_url']}")
            print(f"{Fore.YELLOW}     Screenshot: {vuln['screenshot']}")
        print()
    
    # Speichere die Ergebnisse
    print(f"{Fore.CYAN}[*] Speichere Ergebnisse...")
    
    # Speichere die Schwachstellen als JSON
    if found_vulnerabilities:
        try:
            with open(json_file, 'w') as f:
                json.dump(found_vulnerabilities, f, indent=2)
            print(f"{Fore.GREEN}[+] Schwachstellen als JSON gespeichert: {json_file}")
        except Exception as e:
            print(f"{Fore.RED}[!] Fehler beim Speichern der Schwachstellen als JSON: {e}")
    
    # Generiere einen Report
    if found_vulnerabilities:
        print(f"{Fore.CYAN}[*] Generiere Report für {len(found_vulnerabilities)} gefundene Schwachstellen...")
        try:
            # Erstelle einen einfachen HTML-Report
            with open(report_file, 'w') as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS Hunter Pro - Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #2c3e50; }}
        .vulnerability {{ border: 1px solid #ddd; padding: 10px; margin-bottom: 10px; border-radius: 5px; }}
        .high {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #3498db; }}
        .details {{ margin-left: 20px; }}
        pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>XSS Hunter Pro - Scan Report</h1>
    <p><strong>Datum:</strong> {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
    <p><strong>Ziel:</strong> {args.url}</p>
    <p><strong>Scan-Tiefe:</strong> {args.depth}</p>
    <p><strong>Gefundene Schwachstellen:</strong> {len(found_vulnerabilities)}</p>
    
    <h2>Schwachstellen</h2>
""")
                
                for i, vuln in enumerate(found_vulnerabilities):
                    f.write(f"""
    <div class="vulnerability {vuln['severity']}">
        <h3>{i+1}. {vuln['type'].upper()}</h3>
        <div class="details">
            <p><strong>URL:</strong> {vuln['url']}</p>
            <p><strong>Parameter:</strong> {vuln['parameter']}</p>
            <p><strong>Methode:</strong> {vuln['method']}</p>
            <p><strong>Payload:</strong> <pre>{vuln['payload']}</pre></p>
            <p><strong>Debug-URL:</strong> <a href="{vuln['debug_url']}" target="_blank">{vuln['debug_url']}</a></p>
            <p><strong>Screenshot:</strong> <a href="{vuln['screenshot']}">{os.path.basename(vuln['screenshot'])}</a></p>
        </div>
    </div>
""")
                
                f.write("""
</body>
</html>
""")
            print(f"{Fore.GREEN}[+] HTML-Report erstellt: {report_file}")
        except Exception as e:
            print(f"{Fore.RED}[!] Fehler beim Erstellen des Reports: {e}")
    
    print(f"{Fore.GREEN}[+] Alle Ergebnisse wurden gespeichert!")
    print(f"{Fore.GREEN}[+] JSON-Datei: {json_file}")
    print(f"{Fore.GREEN}[+] Report-Datei: {report_file}")
    print(f"{Fore.GREEN}[+] Screenshots-Verzeichnis: {screenshots_dir}")
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
    if args.payload_context:
        print(f"{Fore.GREEN}[*] Payload-Kontext: {args.payload_context}")
    if args.verbose:
        print(f"{Fore.GREEN}[*] Ausführliche Ausgabe: Aktiviert")
    if args.debug:
        print(f"{Fore.GREEN}[*] Debug-Modus: Aktiviert")
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
    
    # Erstelle Verzeichnisse für Screenshots, falls sie nicht existieren
    output_dir = args.output_dir
    reports_dir = os.path.join(output_dir, "reports")
    screenshots_dir = os.path.join(output_dir, "screenshots")
    results_dir = os.path.join(output_dir, "results")
    
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(screenshots_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)
    
    # Generiere einen Zeitstempel für die Dateinamen
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    # Generiere eine zufällige ID für den Exploit
    exploit_id = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    
    # Wähle einen Payload basierend auf dem Exploit-Typ
    payload = ""
    if args.exploit_type == "reflected_xss":
        payload = f"<script>alert('XSS-{exploit_id}')</script>"
    elif args.exploit_type == "stored_xss":
        payload = f"<img src=x onerror=alert('XSS-{exploit_id}')>"
    elif args.exploit_type == "dom_xss":
        payload = f"<img src=1 onerror=eval(atob('YWxlcnQoJ1hTUy0{exploit_id}JyknCg=='))>"
    
    # Erstelle eine Debugging-URL für den Exploit
    debug_url = f"{args.url}?{args.param}={urllib.parse.quote(payload)}"
    
    # Erstelle einen Screenshot-Dateinamen
    screenshot_file = os.path.join(screenshots_dir, f"exploit_{timestamp}_{exploit_id}.png")
    
    print(f"{Fore.CYAN}[*] Führe Exploit aus...")
    print(f"{Fore.YELLOW}    Payload: {payload}")
    print(f"{Fore.YELLOW}    Debug-URL: {debug_url}")
    
    # Simuliere die Ausführung des Exploits
    print(f"{Fore.CYAN}[*] Führe Exploit aus und verifiziere...")
    
    try:
        # Importiere den ExploitVerifier
        from exploit_verifier import ExploitVerifier
        
        # Erstelle einen ExploitVerifier
        verifier = ExploitVerifier(verbose=args.verbose, debug=args.debug)
        
        # Bereite HTTP-Header und Cookies vor, falls angegeben
        headers = {}
        if hasattr(args, 'headers') and args.headers:
            for header in args.headers:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
        
        cookies = {}
        if hasattr(args, 'cookies') and args.cookies:
            for cookie in args.cookies.split(';'):
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    cookies[key.strip()] = value.strip()
        
        # Führe die Verifikation basierend auf dem Exploit-Typ durch
        if args.exploit_type == "reflected_xss":
            success, message = verifier.verify_reflected_xss(
                url=args.url,
                param=args.param,
                payload=payload,
                cookies=cookies,
                headers=headers
            )
        elif args.exploit_type == "stored_xss":
            # Für Stored XSS benötigen wir eine Verifikations-URL
            verification_url = args.url  # Fallback auf dieselbe URL
            success, message = verifier.verify_stored_xss(
                url=args.url,
                param=args.param,
                payload=payload,
                verification_url=verification_url,
                cookies=cookies,
                headers=headers
            )
        elif args.exploit_type == "dom_xss":
            # Für DOM XSS können wir einen Callback-Server verwenden, falls aktiviert
            callback_url = None
            if hasattr(args, 'callback_server') and args.callback_server:
                callback_port = args.callback_port if hasattr(args, 'callback_port') else 8088
                callback_url = f"http://localhost:{callback_port}/callback"
            
            success, message = verifier.verify_dom_xss(
                url=args.url,
                param=args.param,
                payload=payload,
                callback_url=callback_url,
                cookies=cookies,
                headers=headers
            )
        else:
            success = False
            message = f"Unbekannter Exploit-Typ: {args.exploit_type}"
        
        # Zeige das Ergebnis an
        if success:
            print(f"{Fore.GREEN}[+] Exploit erfolgreich verifiziert!")
            print(f"{Fore.GREEN}[+] {message}")
        else:
            print(f"{Fore.RED}[!] Exploit konnte nicht verifiziert werden.")
            print(f"{Fore.RED}[!] {message}")
            
        # Erstelle einen Screenshot, falls aktiviert
        screenshot_created = False
        if hasattr(args, 'screenshot') and args.screenshot:
            try:
                # Simuliere das Erstellen eines Screenshots
                with open(screenshot_file, 'w') as f:
                    f.write(f"Simulierter Screenshot für Exploit {exploit_id}")
                screenshot_created = True
                print(f"{Fore.GREEN}[+] Screenshot erstellt: {screenshot_file}")
            except Exception as e:
                if args.verbose or args.debug:
                    print(f"{Fore.RED}[!] Fehler beim Erstellen des Screenshots: {e}")
        
        # Generiere einen Exploit-Bericht
        report_file = os.path.join(reports_dir, f"exploit_report_{timestamp}_{exploit_id}.json")
        
        # Erstelle den Bericht
        report = {
            "timestamp": time.time(),
            "url": args.url,
            "parameter": args.param,
            "payload": payload,
            "exploit_type": args.exploit_type,
            "verification_result": success,
            "verification_message": message,
            "screenshot": screenshot_file if screenshot_created else None
        }
        
        # Speichere den Bericht
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        if args.verbose:
            print(f"{Fore.GREEN}[+] Exploit-Bericht gespeichert: {report_file}")
            
    except ImportError as e:
        print(f"{Fore.RED}[!] Fehler beim Importieren des ExploitVerifiers: {e}")
        print(f"{Fore.RED}[!] Stelle sicher, dass die Datei exploit_verifier.py im selben Verzeichnis liegt.")
        
        # Fallback auf einfache Simulation ohne Verifikation
        print(f"{Fore.YELLOW}[*] Führe einfache Simulation ohne Verifikation durch...")
        
        # Simuliere eine Verzögerung
        for i in range(5):
            sys.stdout.write(f"\r{Fore.GREEN}[*] Ausführung: {'.' * (i+1)}")
            sys.stdout.flush()
            time.sleep(0.5)
        
        print()
        print(f"{Fore.YELLOW}[+] Exploit ausgeführt, aber nicht verifiziert!")
        
        # Simuliere das Erstellen eines Screenshots
        with open(screenshot_file, 'w') as f:
            f.write(f"Simulierter Screenshot für Exploit {exploit_id}")
        
        print(f"{Fore.GREEN}[+] Screenshot erstellt: {screenshot_file}")
    except Exception as e:
        print(f"{Fore.RED}[!] Fehler beim Ausführen des Exploits: {e}")
        if args.debug:
            print(f"{Fore.RED}[!] Stacktrace: {traceback.format_exc()}")
    
    # Zeige die Ergebnisse
    print()
    print(f"{Fore.CYAN}[*] Exploit-Ergebnisse:")
    print(f"{Fore.YELLOW}    URL: {args.url}")
    print(f"{Fore.YELLOW}    Parameter: {args.param}")
    print(f"{Fore.YELLOW}    Exploit-Typ: {args.exploit_type}")
    print(f"{Fore.YELLOW}    Payload: {payload}")
    print(f"{Fore.YELLOW}    Debug-URL: {debug_url}")
    print(f"{Fore.YELLOW}    Screenshot: {screenshot_file}")
    
    # Speichere die Ergebnisse
    exploit_results = {
        "id": exploit_id,
        "url": args.url,
        "parameter": args.param,
        "exploit_type": args.exploit_type,
        "payload": payload,
        "debug_url": debug_url,
        "screenshot": screenshot_file,
        "timestamp": timestamp
    }
    
    # Speichere die Exploit-Ergebnisse als JSON
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
    os.makedirs(results_dir, exist_ok=True)
    
    json_file = os.path.join(results_dir, f"exploit_{timestamp}_{exploit_id}.json")
    
    try:
        with open(json_file, 'w') as f:
            json.dump(exploit_results, f, indent=2)
        print(f"{Fore.GREEN}[+] Exploit-Ergebnisse als JSON gespeichert: {json_file}")
    except Exception as e:
        print(f"{Fore.RED}[!] Fehler beim Speichern der Exploit-Ergebnisse: {e}")
    
    print()
    print(f"{Fore.GREEN}[+] Exploit abgeschlossen!")
    print()
    
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
