#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Utilities
====================================

Dieses Modul enthält Hilfsfunktionen für das XSS Hunter Pro Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import re
import time
import json
import random
import string
import hashlib
import base64
import urllib.parse
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from datetime import datetime
import logging
from colorama import Fore, Back, Style
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguriere Logging
logger = logging.getLogger("XSSHunterPro.Utils")

# Datei-Funktionen

def load_json_file(file_path):
    """
    Lädt eine JSON-Datei und gibt deren Inhalt zurück.
    
    Args:
        file_path: Der Pfad zur JSON-Datei.
    
    Returns:
        Der Inhalt der JSON-Datei als Dictionary oder None, wenn ein Fehler auftritt.
    """
    try:
        if not os.path.exists(file_path):
            logger.error(f"Datei nicht gefunden: {file_path}")
            return None
        
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Fehler beim Parsen der JSON-Datei {file_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Fehler beim Laden der JSON-Datei {file_path}: {e}")
        return None

def save_json_file(file_path, data):
    """
    Speichert Daten als JSON-Datei.
    
    Args:
        file_path: Der Pfad zur JSON-Datei.
        data: Die zu speichernden Daten.
    
    Returns:
        True, wenn das Speichern erfolgreich war, sonst False.
    """
    try:
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Fehler beim Speichern der JSON-Datei {file_path}: {e}")
        return False

# URL-Funktionen

def is_valid_url(url):
    """
    Überprüft, ob eine URL gültig ist.
    
    Args:
        url: Die zu überprüfende URL.
    
    Returns:
        True, wenn die URL gültig ist, sonst False.
    """
    if not url:
        return False
    
    # Überprüfe, ob die URL gültig ist
    url_pattern = r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"
    if re.match(url_pattern, url):
        return True
    
    return False

def normalize_url(url):
    """
    Normalisiert eine URL.
    
    Args:
        url: Die zu normalisierende URL.
    
    Returns:
        Die normalisierte URL.
    """
    if not url:
        return ""
    
    # Entferne Trailing-Slash
    if url.endswith("/"):
        url = url[:-1]
    
    # Stelle sicher, dass die URL mit http:// oder https:// beginnt
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    
    return url

def get_domain_from_url(url):
    """
    Extrahiert die Domain aus einer URL.
    
    Args:
        url: Die URL, aus der die Domain extrahiert werden soll.
    
    Returns:
        Die Domain der URL.
    """
    if not url:
        return ""
    
    # Extrahiere die Domain aus der URL
    domain_pattern = r"^(?:https?://)?(?:www\.)?([^:/\n?]+)"
    match = re.match(domain_pattern, url)
    if match:
        return match.group(1)
    
    return ""

def get_base_url(url):
    """
    Extrahiert die Basis-URL aus einer URL.
    
    Args:
        url: Die URL, aus der die Basis-URL extrahiert werden soll.
    
    Returns:
        Die Basis-URL.
    """
    if not url:
        return ""
    
    # Extrahiere die Basis-URL aus der URL
    base_url_pattern = r"^((?:https?://)?(?:www\.)?[^:/\n?]+)"
    match = re.match(base_url_pattern, url)
    if match:
        return match.group(1)
    
    return ""

def get_path_from_url(url):
    """
    Extrahiert den Pfad aus einer URL.
    
    Args:
        url: Die URL, aus der der Pfad extrahiert werden soll.
    
    Returns:
        Der Pfad der URL.
    """
    if not url:
        return ""
    
    # Extrahiere den Pfad aus der URL
    path_pattern = r"^(?:https?://)?(?:www\.)?[^:/\n?]+(?::\d+)?(/[^?#]*)"
    match = re.match(path_pattern, url)
    if match:
        return match.group(1)
    
    return "/"

def get_query_params(url):
    """
    Extrahiert die Query-Parameter aus einer URL.
    
    Args:
        url: Die URL, aus der die Query-Parameter extrahiert werden sollen.
    
    Returns:
        Ein Dictionary mit den Query-Parametern.
    """
    if not url:
        return {}
    
    # Extrahiere die Query-Parameter aus der URL
    query_params = {}
    query_pattern = r"^(?:https?://)?(?:www\.)?[^:/\n?]+(?::\d+)?(?:/[^?#]*)?(?:\?([^#]*))"
    match = re.match(query_pattern, url)
    if match:
        query_string = match.group(1)
        for param in query_string.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                query_params[key] = value
    
    return query_params

def url_encode(text):
    """
    Kodiert einen Text für die Verwendung in einer URL.
    
    Args:
        text: Der zu kodierende Text.
    
    Returns:
        Der kodierte Text.
    """
    if not text:
        return ""
    
    return urllib.parse.quote(text)

def url_decode(text):
    """
    Dekodiert einen URL-kodierten Text.
    
    Args:
        text: Der zu dekodierende Text.
    
    Returns:
        Der dekodierte Text.
    """
    if not text:
        return ""
    
    return urllib.parse.unquote(text)

# Datei-Funktionen

def get_file_extension(file_path):
    """
    Extrahiert die Dateierweiterung aus einem Dateipfad.
    
    Args:
        file_path: Der Dateipfad, aus dem die Dateierweiterung extrahiert werden soll.
    
    Returns:
        Die Dateierweiterung.
    """
    if not file_path:
        return ""
    
    # Extrahiere die Dateierweiterung aus dem Dateipfad
    _, extension = os.path.splitext(file_path)
    return extension

def get_file_name(file_path):
    """
    Extrahiert den Dateinamen aus einem Dateipfad.
    
    Args:
        file_path: Der Dateipfad, aus dem der Dateiname extrahiert werden soll.
    
    Returns:
        Der Dateiname.
    """
    if not file_path:
        return ""
    
    # Extrahiere den Dateinamen aus dem Dateipfad
    return os.path.basename(file_path)

def read_file(file_path):
    """
    Liest den Inhalt einer Datei.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        Der Inhalt der Datei.
    """
    if not file_path:
        return ""
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Fehler beim Lesen der Datei {file_path}: {e}")
        return ""

def write_file(file_path, content):
    """
    Schreibt Inhalt in eine Datei.
    
    Args:
        file_path: Der Pfad zur Datei.
        content: Der zu schreibende Inhalt.
    
    Returns:
        True, wenn das Schreiben erfolgreich war, sonst False.
    """
    if not file_path:
        return False
    
    try:
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception as e:
        logger.error(f"Fehler beim Schreiben der Datei {file_path}: {e}")
        return False

def append_to_file(file_path, content):
    """
    Fügt Inhalt an eine Datei an.
    
    Args:
        file_path: Der Pfad zur Datei.
        content: Der anzufügende Inhalt.
    
    Returns:
        True, wenn das Anfügen erfolgreich war, sonst False.
    """
    if not file_path:
        return False
    
    try:
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception as e:
        logger.error(f"Fehler beim Anfügen an die Datei {file_path}: {e}")
        return False

def file_exists(file_path):
    """
    Überprüft, ob eine Datei existiert.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        True, wenn die Datei existiert, sonst False.
    """
    if not file_path:
        return False
    
    return os.path.isfile(file_path)

def directory_exists(directory_path):
    """
    Überprüft, ob ein Verzeichnis existiert.
    
    Args:
        directory_path: Der Pfad zum Verzeichnis.
    
    Returns:
        True, wenn das Verzeichnis existiert, sonst False.
    """
    if not directory_path:
        return False
    
    return os.path.isdir(directory_path)

def create_directory(directory_path):
    """
    Erstellt ein Verzeichnis.
    
    Args:
        directory_path: Der Pfad zum Verzeichnis.
    
    Returns:
        True, wenn das Erstellen erfolgreich war, sonst False.
    """
    if not directory_path:
        return False
    
    try:
        os.makedirs(directory_path, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Fehler beim Erstellen des Verzeichnisses {directory_path}: {e}")
        return False

# Zeit-Funktionen

def get_timestamp():
    """
    Gibt den aktuellen Unix-Zeitstempel zurück.
    
    Returns:
        Der aktuelle Unix-Zeitstempel.
    """
    return time.time()

def format_timestamp(timestamp):
    """
    Formatiert einen Unix-Zeitstempel als lesbaren String.
    
    Args:
        timestamp: Der zu formatierende Unix-Zeitstempel.
    
    Returns:
        Der formatierte Zeitstempel.
    """
    if not timestamp:
        return ""
    
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

def get_current_date():
    """
    Gibt das aktuelle Datum zurück.
    
    Returns:
        Das aktuelle Datum im Format YYYY-MM-DD.
    """
    return datetime.now().strftime("%Y-%m-%d")

def get_current_time():
    """
    Gibt die aktuelle Zeit zurück.
    
    Returns:
        Die aktuelle Zeit im Format HH:MM:SS.
    """
    return datetime.now().strftime("%H:%M:%S")

def get_current_datetime():
    """
    Gibt das aktuelle Datum und die aktuelle Zeit zurück.
    
    Returns:
        Das aktuelle Datum und die aktuelle Zeit im Format YYYY-MM-DD HH:MM:SS.
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# String-Funktionen

def generate_random_string(length=8, chars=string.ascii_letters + string.digits):
    """
    Generiert einen zufälligen String.
    
    Args:
        length: Die Länge des zu generierenden Strings.
        chars: Die Zeichen, die für die Generierung verwendet werden sollen.
    
    Returns:
        Der generierte String.
    """
    return ''.join(random.choice(chars) for _ in range(length))

def generate_random_number(min_value=0, max_value=100):
    """
    Generiert eine zufällige Zahl.
    
    Args:
        min_value: Der Minimalwert der zu generierenden Zahl.
        max_value: Der Maximalwert der zu generierenden Zahl.
    
    Returns:
        Die generierte Zahl.
    """
    return random.randint(min_value, max_value)

def generate_random_boolean():
    """
    Generiert einen zufälligen Boolean-Wert.
    
    Returns:
        Der generierte Boolean-Wert.
    """
    return random.choice([True, False])

def generate_random_choice(choices):
    """
    Wählt ein zufälliges Element aus einer Liste aus.
    
    Args:
        choices: Die Liste, aus der ein Element ausgewählt werden soll.
    
    Returns:
        Das ausgewählte Element.
    """
    if not choices:
        return None
    
    return random.choice(choices)

def generate_random_sample(population, k):
    """
    Wählt eine zufällige Stichprobe aus einer Liste aus.
    
    Args:
        population: Die Liste, aus der die Stichprobe ausgewählt werden soll.
        k: Die Größe der Stichprobe.
    
    Returns:
        Die ausgewählte Stichprobe.
    """
    if not population:
        return []
    
    return random.sample(population, min(k, len(population)))

def generate_hash(text, algorithm="sha256"):
    """
    Generiert einen Hash-Wert für einen Text.
    
    Args:
        text: Der zu hashende Text.
        algorithm: Der zu verwendende Hash-Algorithmus.
    
    Returns:
        Der generierte Hash-Wert.
    """
    if not text:
        return ""
    
    if algorithm == "md5":
        return hashlib.md5(text.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(text.encode()).hexdigest()
    else:
        return hashlib.sha256(text.encode()).hexdigest()

def encode_base64(text):
    """
    Kodiert einen Text als Base64.
    
    Args:
        text: Der zu kodierende Text.
    
    Returns:
        Der kodierte Text.
    """
    if not text:
        return ""
    
    return base64.b64encode(text.encode()).decode()

def decode_base64(text):
    """
    Dekodiert einen Base64-kodierten Text.
    
    Args:
        text: Der zu dekodierende Text.
    
    Returns:
        Der dekodierte Text.
    """
    if not text:
        return ""
    
    try:
        return base64.b64decode(text).decode()
    except Exception as e:
        logger.error(f"Fehler beim Dekodieren des Base64-Texts: {e}")
        return ""

def html_encode(text):
    """
    Kodiert einen Text für die Verwendung in HTML.
    
    Args:
        text: Der zu kodierende Text.
    
    Returns:
        Der kodierte Text.
    """
    if not text:
        return ""
    
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

def html_decode(text):
    """
    Dekodiert einen HTML-kodierten Text.
    
    Args:
        text: Der zu dekodierende Text.
    
    Returns:
        Der dekodierte Text.
    """
    if not text:
        return ""
    
    return text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'")

# Validierungsfunktionen

def is_valid_ip(ip):
    """
    Überprüft, ob eine IP-Adresse gültig ist.
    
    Args:
        ip: Die zu überprüfende IP-Adresse.
    
    Returns:
        True, wenn die IP-Adresse gültig ist, sonst False.
    """
    if not ip:
        return False
    
    # Überprüfe, ob die IP-Adresse gültig ist
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(ip_pattern, ip):
        return True
    
    return False

def is_valid_email(email):
    """
    Überprüft, ob eine E-Mail-Adresse gültig ist.
    
    Args:
        email: Die zu überprüfende E-Mail-Adresse.
    
    Returns:
        True, wenn die E-Mail-Adresse gültig ist, sonst False.
    """
    if not email:
        return False
    
    # Überprüfe, ob die E-Mail-Adresse gültig ist
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if re.match(email_pattern, email):
        return True
    
    return False

def is_valid_domain(domain):
    """
    Überprüft, ob eine Domain gültig ist.
    
    Args:
        domain: Die zu überprüfende Domain.
    
    Returns:
        True, wenn die Domain gültig ist, sonst False.
    """
    if not domain:
        return False
    
    # Überprüfe, ob die Domain gültig ist
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    if re.match(domain_pattern, domain):
        return True
    
    return False

def is_valid_port(port):
    """
    Überprüft, ob ein Port gültig ist.
    
    Args:
        port: Der zu überprüfende Port.
    
    Returns:
        True, wenn der Port gültig ist, sonst False.
    """
    if not isinstance(port, int):
        return False
    
    # Überprüfe, ob der Port gültig ist
    if 0 <= port <= 65535:
        return True
    
    return False

def is_valid_mac(mac):
    """
    Überprüft, ob eine MAC-Adresse gültig ist.
    
    Args:
        mac: Die zu überprüfende MAC-Adresse.
    
    Returns:
        True, wenn die MAC-Adresse gültig ist, sonst False.
    """
    if not mac:
        return False
    
    # Überprüfe, ob die MAC-Adresse gültig ist
    mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    if re.match(mac_pattern, mac):
        return True
    
    return False

def is_valid_uuid(uuid):
    """
    Überprüft, ob eine UUID gültig ist.
    
    Args:
        uuid: Die zu überprüfende UUID.
    
    Returns:
        True, wenn die UUID gültig ist, sonst False.
    """
    if not uuid:
        return False
    
    # Überprüfe, ob die UUID gültig ist
    uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    if re.match(uuid_pattern, uuid, re.IGNORECASE):
        return True
    
    return False

def is_valid_hex(hex_str):
    """
    Überprüft, ob ein Hexadezimalwert gültig ist.
    
    Args:
        hex_str: Der zu überprüfende Hexadezimalwert.
    
    Returns:
        True, wenn der Hexadezimalwert gültig ist, sonst False.
    """
    if not hex_str:
        return False
    
    # Überprüfe, ob der Hexadezimalwert gültig ist
    hex_pattern = r"^[0-9a-f]+$"
    if re.match(hex_pattern, hex_str, re.IGNORECASE):
        return True
    
    return False

def is_valid_base64(base64_str):
    """
    Überprüft, ob ein Base64-Wert gültig ist.
    
    Args:
        base64_str: Der zu überprüfende Base64-Wert.
    
    Returns:
        True, wenn der Base64-Wert gültig ist, sonst False.
    """
    if not base64_str:
        return False
    
    # Überprüfe, ob der Base64-Wert gültig ist
    try:
        base64.b64decode(base64_str)
        return True
    except Exception:
        return False

def is_valid_json(json_str):
    """
    Überprüft, ob ein JSON-String gültig ist.
    
    Args:
        json_str: Der zu überprüfende JSON-String.
    
    Returns:
        True, wenn der JSON-String gültig ist, sonst False.
    """
    if not json_str:
        return False
    
    # Überprüfe, ob der JSON-String gültig ist
    try:
        json.loads(json_str)
        return True
    except Exception:
        return False

def is_valid_xml(xml_str):
    """
    Überprüft, ob ein XML-String gültig ist.
    
    Args:
        xml_str: Der zu überprüfende XML-String.
    
    Returns:
        True, wenn der XML-String gültig ist, sonst False.
    """
    if not xml_str:
        return False
    
    # Überprüfe, ob der XML-String gültig ist
    try:
        ET.fromstring(xml_str)
        return True
    except Exception:
        return False

def is_valid_html(html_str):
    """
    Überprüft, ob ein HTML-String gültig ist.
    
    Args:
        html_str: Der zu überprüfende HTML-String.
    
    Returns:
        True, wenn der HTML-String gültig ist, sonst False.
    """
    if not html_str:
        return False
    
    # Überprüfe, ob der HTML-String gültig ist
    try:
        parser = HTMLParser()
        parser.feed(html_str)
        return True
    except Exception:
        return False

def is_valid_css(css_str):
    """
    Überprüft, ob ein CSS-String gültig ist.
    
    Args:
        css_str: Der zu überprüfende CSS-String.
    
    Returns:
        True, wenn der CSS-String gültig ist, sonst False.
    """
    if not css_str:
        return False
    
    # Überprüfe, ob der CSS-String gültig ist
    css_pattern = r"^.*\{.*\}.*$"
    if re.match(css_pattern, css_str, re.DOTALL):
        return True
    
    return False

def is_valid_js(js_str):
    """
    Überprüft, ob ein JavaScript-String gültig ist.
    
    Args:
        js_str: Der zu überprüfende JavaScript-String.
    
    Returns:
        True, wenn der JavaScript-String gültig ist, sonst False.
    """
    if not js_str:
        return False
    
    # Überprüfe, ob der JavaScript-String gültig ist
    js_pattern = r"^.*function.*\(.*\).*\{.*\}.*$"
    if re.match(js_pattern, js_str, re.DOTALL):
        return True
    
    return False

# WAF-Funktionen

def detect_waf(response):
    """
    Erkennt, ob eine Webseite durch eine WAF geschützt ist.
    
    Args:
        response: Die HTTP-Antwort der Webseite.
    
    Returns:
        Der Name der erkannten WAF oder None, wenn keine WAF erkannt wurde.
    """
    if not response:
        return None
    
    # WAF-Signaturen
    waf_signatures = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
        "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
        "Incapsula": ["incapsula", "_incap_"],
        "Akamai": ["akamai", "ak_bmsc"],
        "F5 BIG-IP": ["big-ip", "f5"],
        "Sucuri": ["sucuri", "cloudproxy"],
        "Imperva": ["imperva", "incapsula"],
        "Barracuda": ["barracuda"],
        "Citrix": ["citrix", "netscaler"],
        "AWS WAF": ["aws", "awselb"],
        "Wordfence": ["wordfence"],
        "Fortinet": ["fortinet", "fortigate"],
        "Radware": ["radware"],
        "DDoS-Guard": ["ddos-guard"],
        "Distil": ["distil"],
        "Reblaze": ["reblaze"],
        "Varnish": ["varnish"],
        "Wallarm": ["wallarm"],
        "Edgecast": ["edgecast"],
        "Fastly": ["fastly"]
    }
    
    # Überprüfe Header und Body auf WAF-Signaturen
    headers_str = str(response.headers).lower()
    body_str = str(response.text).lower() if hasattr(response, 'text') else ""
    
    for waf_name, signatures in waf_signatures.items():
        for signature in signatures:
            if signature.lower() in headers_str or signature.lower() in body_str:
                return waf_name
    
    return None

def generate_waf_bypass_payload(waf_type, context="html"):
    """
    Generiert einen WAF-Bypass-Payload für einen bestimmten WAF-Typ.
    
    Args:
        waf_type: Der Typ der WAF.
        context: Der Kontext des Payloads (html, js, attr).
    
    Returns:
        Der generierte WAF-Bypass-Payload.
    """
    # Lade WAF-Bypass-Payloads aus Datei
    waf_bypass_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads", "waf_bypass.json")
    waf_bypass_payloads = load_json_file(waf_bypass_file) or {}
    
    # Standardpayloads, falls keine spezifischen gefunden werden
    default_payloads = {
        "html": [
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>"
        ],
        "js": [
            "'-alert('XSS')-'",
            "\";alert('XSS');//",
            "'-eval(atob('YWxlcnQoJ1hTUycpOw=='))-'"
        ],
        "attr": [
            "\" onmouseover=\"alert('XSS')\" \"",
            "' onfocus='alert(\"XSS\")' '",
            "\" autofocus onfocus=\"alert('XSS')\""
        ]
    }
    
    # Wähle Payloads basierend auf WAF-Typ und Kontext
    if waf_type in waf_bypass_payloads and context in waf_bypass_payloads[waf_type]:
        payloads = waf_bypass_payloads[waf_type][context]
    else:
        payloads = default_payloads.get(context, default_payloads["html"])
    
    # Wähle einen zufälligen Payload
    return generate_random_choice(payloads)

# Beispielverwendung
if __name__ == "__main__":
    # URL-Funktionen
    url = "https://example.com/path?param1=value1&param2=value2"
    
    print(f"URL: {url}")
    print(f"Gültige URL: {is_valid_url(url)}")
    print(f"Normalisierte URL: {normalize_url(url)}")
    print(f"Domain: {get_domain_from_url(url)}")
    print(f"Basis-URL: {get_base_url(url)}")
    print(f"Pfad: {get_path_from_url(url)}")
    print(f"Query-Parameter: {get_query_params(url)}")
    
    # Datei-Funktionen
    file_path = "example.json"
    
    print(f"Datei: {file_path}")
    print(f"Dateierweiterung: {get_file_extension(file_path)}")
    print(f"Dateiname: {get_file_name(file_path)}")
    
    # Zeit-Funktionen
    timestamp = get_timestamp()
    
    print(f"Zeitstempel: {timestamp}")
    print(f"Formatierter Zeitstempel: {format_timestamp(timestamp)}")
    print(f"Aktuelles Datum: {get_current_date()}")
    print(f"Aktuelle Zeit: {get_current_time()}")
    print(f"Aktuelles Datum und Zeit: {get_current_datetime()}")
    
    # String-Funktionen
    print(f"Zufälliger String: {generate_random_string()}")
    print(f"Zufällige Zahl: {generate_random_number()}")
    print(f"Zufälliger Boolean-Wert: {generate_random_boolean()}")
    print(f"Zufällige Auswahl: {generate_random_choice(['a', 'b', 'c'])}")
    print(f"Zufällige Stichprobe: {generate_random_sample(['a', 'b', 'c', 'd', 'e'], 3)}")
    print(f"Hash: {generate_hash('test')}")
    print(f"Base64-Kodierung: {encode_base64('test')}")
    print(f"Base64-Dekodierung: {decode_base64(encode_base64('test'))}")
    print(f"URL-Kodierung: {url_encode('test test')}")
    print(f"URL-Dekodierung: {url_decode(url_encode('test test'))}")
    print(f"HTML-Kodierung: {html_encode('<test>')}")
    print(f"HTML-Dekodierung: {html_decode(html_encode('<test>'))}")
    
    # Sonstige Funktionen
    print(f"Gültige IP: {is_valid_ip('192.168.0.1')}")
    print(f"Gültige E-Mail: {is_valid_email('test@example.com')}")
    print(f"Gültige Domain: {is_valid_domain('example.com')}")
    print(f"Gültiger Port: {is_valid_port(80)}")
    print(f"Gültige MAC: {is_valid_mac('00:11:22:33:44:55')}")
    print(f"Gültige UUID: {is_valid_uuid('00000000-0000-0000-0000-000000000000')}")
    print(f"Gültiger Hexadezimalwert: {is_valid_hex('0123456789abcdef')}")
    print(f"Gültiger Base64-Wert: {is_valid_base64('dGVzdA==')}")
    json_test = '{"test": "test"}'
    print(f"Gültiger JSON-String: {is_valid_json(json_test)}")
    xml_test = '<?xml version="1.0" encoding="UTF-8"?><test>test</test>'
    print(f"Gültiger XML-String: {is_valid_xml(xml_test)}")
    html_test = '<!DOCTYPE html><html><head><title>Test</title></head><body><p>Test</p></body></html>'
    print(f"Gültiger HTML-String: {is_valid_html(html_test)}")
    print(f"Gültiger CSS-String: {is_valid_css('body { color: red; }')}")
    print(f"Gültiger JavaScript-String: {is_valid_js('function test() { return true; }')}")

def normalize_url(url):
    """
    Normalisiert eine URL.
    
    Args:
        url: Die zu normalisierende URL.
    
    Returns:
        Die normalisierte URL.
    """
    if not url:
        return ""
    
    # Entferne Trailing-Slash
    if url.endswith("/"):
        url = url[:-1]
    
    # Stelle sicher, dass die URL mit http:// oder https:// beginnt
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    
    return url

def get_domain_from_url(url):
    """
    Extrahiert die Domain aus einer URL.
    
    Args:
        url: Die URL, aus der die Domain extrahiert werden soll.
    
    Returns:
        Die Domain der URL.
    """
    if not url:
        return ""
    
    # Extrahiere die Domain aus der URL
    domain_pattern = r"^(?:https?://)?(?:www\.)?([^:/\n?]+)"
    match = re.match(domain_pattern, url)
    if match:
        return match.group(1)
    
    return ""

def get_base_url(url):
    """
    Extrahiert die Basis-URL aus einer URL.
    
    Args:
        url: Die URL, aus der die Basis-URL extrahiert werden soll.
    
    Returns:
        Die Basis-URL.
    """
    if not url:
        return ""
    
    # Extrahiere die Basis-URL aus der URL
    base_url_pattern = r"^((?:https?://)?(?:www\.)?[^:/\n?]+)"
    match = re.match(base_url_pattern, url)
    if match:
        return match.group(1)
    
    return ""

def get_path_from_url(url):
    """
    Extrahiert den Pfad aus einer URL.
    
    Args:
        url: Die URL, aus der der Pfad extrahiert werden soll.
    
    Returns:
        Der Pfad der URL.
    """
    if not url:
        return ""
    
    # Extrahiere den Pfad aus der URL
    path_pattern = r"^(?:https?://)?(?:www\.)?[^:/\n?]+(?::\d+)?(/[^?#]*)"
    match = re.match(path_pattern, url)
    if match:
        return match.group(1)
    
    return "/"

def get_query_params(url):
    """
    Extrahiert die Query-Parameter aus einer URL.
    
    Args:
        url: Die URL, aus der die Query-Parameter extrahiert werden sollen.
    
    Returns:
        Ein Dictionary mit den Query-Parametern.
    """
    if not url:
        return {}
    
    # Extrahiere die Query-Parameter aus der URL
    query_params = {}
    query_pattern = r"^(?:https?://)?(?:www\.)?[^:/\n?]+(?::\d+)?(?:/[^?#]*)?(?:\?([^#]*))"
    match = re.match(query_pattern, url)
    if match:
        query_string = match.group(1)
        for param in query_string.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                query_params[key] = value
    
    return query_params

def url_encode(text):
    """
    Kodiert einen Text für die Verwendung in einer URL.
    
    Args:
        text: Der zu kodierende Text.
    
    Returns:
        Der kodierte Text.
    """
    if not text:
        return ""
    
    return urllib.parse.quote(text)

def url_decode(text):
    """
    Dekodiert einen URL-kodierten Text.
    
    Args:
        text: Der zu dekodierende Text.
    
    Returns:
        Der dekodierte Text.
    """
    if not text:
        return ""
    
    return urllib.parse.unquote(text)

# Datei-Funktionen

def get_file_extension(file_path):
    """
    Extrahiert die Dateierweiterung aus einem Dateipfad.
    
    Args:
        file_path: Der Dateipfad, aus dem die Dateierweiterung extrahiert werden soll.
    
    Returns:
        Die Dateierweiterung.
    """
    if not file_path:
        return ""
    
    # Extrahiere die Dateierweiterung aus dem Dateipfad
    _, extension = os.path.splitext(file_path)
    return extension

def get_file_name(file_path):
    """
    Extrahiert den Dateinamen aus einem Dateipfad.
    
    Args:
        file_path: Der Dateipfad, aus dem der Dateiname extrahiert werden soll.
    
    Returns:
        Der Dateiname.
    """
    if not file_path:
        return ""
    
    # Extrahiere den Dateinamen aus dem Dateipfad
    return os.path.basename(file_path)

def read_file(file_path):
    """
    Liest den Inhalt einer Datei.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        Der Inhalt der Datei.
    """
    if not file_path:
        return ""
    
    try:
        with open(file_path, "r") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Fehler beim Lesen der Datei {file_path}: {e}")
        return ""

def write_file(file_path, content):
    """
    Schreibt Inhalt in eine Datei.
    
    Args:
        file_path: Der Pfad zur Datei.
        content: Der zu schreibende Inhalt.
    
    Returns:
        True, wenn das Schreiben erfolgreich war, sonst False.
    """
    if not file_path:
        return False
    
    try:
        with open(file_path, "w") as f:
            f.write(content)
        return True
    except Exception as e:
        logger.error(f"Fehler beim Schreiben der Datei {file_path}: {e}")
        return False

def append_to_file(file_path, content):
    """
    Fügt Inhalt an eine Datei an.
    
    Args:
        file_path: Der Pfad zur Datei.
        content: Der anzufügende Inhalt.
    
    Returns:
        True, wenn das Anfügen erfolgreich war, sonst False.
    """
    if not file_path:
        return False
    
    try:
        with open(file_path, "a") as f:
            f.write(content)
        return True
    except Exception as e:
        logger.error(f"Fehler beim Anfügen an die Datei {file_path}: {e}")
        return False

def file_exists(file_path):
    """
    Überprüft, ob eine Datei existiert.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        True, wenn die Datei existiert, sonst False.
    """
    if not file_path:
        return False
    
    return os.path.isfile(file_path)

def directory_exists(directory_path):
    """
    Überprüft, ob ein Verzeichnis existiert.
    
    Args:
        directory_path: Der Pfad zum Verzeichnis.
    
    Returns:
        True, wenn das Verzeichnis existiert, sonst False.
    """
    if not directory_path:
        return False
    
    return os.path.isdir(directory_path)

def create_directory(directory_path):
    """
    Erstellt ein Verzeichnis.
    
    Args:
        directory_path: Der Pfad zum Verzeichnis.
    
    Returns:
        True, wenn das Erstellen erfolgreich war, sonst False.
    """
    if not directory_path:
        return False
    
    try:
        os.makedirs(directory_path, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Fehler beim Erstellen des Verzeichnisses {directory_path}: {e}")
        return False

# Zeit-Funktionen

def get_timestamp():
    """
    Gibt den aktuellen Unix-Zeitstempel zurück.
    
    Returns:
        Der aktuelle Unix-Zeitstempel.
    """
    return time.time()

def format_timestamp(timestamp):
    """
    Formatiert einen Unix-Zeitstempel als lesbaren String.
    
    Args:
        timestamp: Der zu formatierende Unix-Zeitstempel.
    
    Returns:
        Der formatierte Zeitstempel.
    """
    if not timestamp:
        return ""
    
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

def get_current_date():
    """
    Gibt das aktuelle Datum zurück.
    
    Returns:
        Das aktuelle Datum im Format YYYY-MM-DD.
    """
    return datetime.now().strftime("%Y-%m-%d")

def get_current_time():
    """
    Gibt die aktuelle Zeit zurück.
    
    Returns:
        Die aktuelle Zeit im Format HH:MM:SS.
    """
    return datetime.now().strftime("%H:%M:%S")

def get_current_datetime():
    """
    Gibt das aktuelle Datum und die aktuelle Zeit zurück.
    
    Returns:
        Das aktuelle Datum und die aktuelle Zeit im Format YYYY-MM-DD HH:MM:SS.
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# String-Funktionen

def generate_random_string(length=8, chars=string.ascii_letters + string.digits):
    """
    Generiert einen zufälligen String.
    
    Args:
        length: Die Länge des zu generierenden Strings.
        chars: Die Zeichen, die für die Generierung verwendet werden sollen.
    
    Returns:
        Der generierte String.
    """
    return ''.join(random.choice(chars) for _ in range(length))

def generate_random_number(min_value=0, max_value=100):
    """
    Generiert eine zufällige Zahl.
    
    Args:
        min_value: Der Minimalwert der zu generierenden Zahl.
        max_value: Der Maximalwert der zu generierenden Zahl.
    
    Returns:
        Die generierte Zahl.
    """
    return random.randint(min_value, max_value)

def generate_random_boolean():
    """
    Generiert einen zufälligen Boolean-Wert.
    
    Returns:
        Der generierte Boolean-Wert.
    """
    return random.choice([True, False])

def generate_random_choice(choices):
    """
    Wählt ein zufälliges Element aus einer Liste aus.
    
    Args:
        choices: Die Liste, aus der ein Element ausgewählt werden soll.
    
    Returns:
        Das ausgewählte Element.
    """
    if not choices:
        return None
    
    return random.choice(choices)

def generate_random_sample(population, k):
    """
    Wählt eine zufällige Stichprobe aus einer Liste aus.
    
    Args:
        population: Die Liste, aus der die Stichprobe ausgewählt werden soll.
        k: Die Größe der Stichprobe.
    
    Returns:
        Die ausgewählte Stichprobe.
    """
    if not population:
        return []
    
    return random.sample(population, min(k, len(population)))

def generate_hash(text, algorithm="sha256"):
    """
    Generiert einen Hash-Wert für einen Text.
    
    Args:
        text: Der zu hashende Text.
        algorithm: Der zu verwendende Hash-Algorithmus.
    
    Returns:
        Der generierte Hash-Wert.
    """
    if not text:
        return ""
    
    if algorithm == "md5":
        return hashlib.md5(text.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(text.encode()).hexdigest()
    else:
        return hashlib.sha256(text.encode()).hexdigest()

def encode_base64(text):
    """
    Kodiert einen Text als Base64.
    
    Args:
        text: Der zu kodierende Text.
    
    Returns:
        Der kodierte Text.
    """
    if not text:
        return ""
    
    return base64.b64encode(text.encode()).decode()

def decode_base64(text):
    """
    Dekodiert einen Base64-kodierten Text.
    
    Args:
        text: Der zu dekodierende Text.
    
    Returns:
        Der dekodierte Text.
    """
    if not text:
        return ""
    
    try:
        return base64.b64decode(text).decode()
    except Exception as e:
        logger.error(f"Fehler beim Dekodieren des Base64-Texts: {e}")
        return ""

def html_encode(text):
    """
    Kodiert einen Text für die Verwendung in HTML.
    
    Args:
        text: Der zu kodierende Text.
    
    Returns:
        Der kodierte Text.
    """
    if not text:
        return ""
    
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

def html_decode(text):
    """
    Dekodiert einen HTML-kodierten Text.
    
    Args:
        text: Der zu dekodierende Text.
    
    Returns:
        Der dekodierte Text.
    """
    if not text:
        return ""
    
    return text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'")

# Validierungsfunktionen

def is_valid_ip(ip):
    """
    Überprüft, ob eine IP-Adresse gültig ist.
    
    Args:
        ip: Die zu überprüfende IP-Adresse.
    
    Returns:
        True, wenn die IP-Adresse gültig ist, sonst False.
    """
    if not ip:
        return False
    
    # Überprüfe, ob die IP-Adresse gültig ist
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(ip_pattern, ip):
        return True
    
    return False

def is_valid_email(email):
    """
    Überprüft, ob eine E-Mail-Adresse gültig ist.
    
    Args:
        email: Die zu überprüfende E-Mail-Adresse.
    
    Returns:
        True, wenn die E-Mail-Adresse gültig ist, sonst False.
    """
    if not email:
        return False
    
    # Überprüfe, ob die E-Mail-Adresse gültig ist
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if re.match(email_pattern, email):
        return True
    
    return False

def is_valid_domain(domain):
    """
    Überprüft, ob eine Domain gültig ist.
    
    Args:
        domain: Die zu überprüfende Domain.
    
    Returns:
        True, wenn die Domain gültig ist, sonst False.
    """
    if not domain:
        return False
    
    # Überprüfe, ob die Domain gültig ist
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    if re.match(domain_pattern, domain):
        return True
    
    return False

def is_valid_port(port):
    """
    Überprüft, ob ein Port gültig ist.
    
    Args:
        port: Der zu überprüfende Port.
    
    Returns:
        True, wenn der Port gültig ist, sonst False.
    """
    if not isinstance(port, int):
        return False
    
    # Überprüfe, ob der Port gültig ist
    if 0 <= port <= 65535:
        return True
    
    return False

def is_valid_mac(mac):
    """
    Überprüft, ob eine MAC-Adresse gültig ist.
    
    Args:
        mac: Die zu überprüfende MAC-Adresse.
    
    Returns:
        True, wenn die MAC-Adresse gültig ist, sonst False.
    """
    if not mac:
        return False
    
    # Überprüfe, ob die MAC-Adresse gültig ist
    mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    if re.match(mac_pattern, mac):
        return True
    
    return False

def is_valid_uuid(uuid):
    """
    Überprüft, ob eine UUID gültig ist.
    
    Args:
        uuid: Die zu überprüfende UUID.
    
    Returns:
        True, wenn die UUID gültig ist, sonst False.
    """
    if not uuid:
        return False
    
    # Überprüfe, ob die UUID gültig ist
    uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    if re.match(uuid_pattern, uuid, re.IGNORECASE):
        return True
    
    return False

def is_valid_hex(hex_str):
    """
    Überprüft, ob ein Hexadezimalwert gültig ist.
    
    Args:
        hex_str: Der zu überprüfende Hexadezimalwert.
    
    Returns:
        True, wenn der Hexadezimalwert gültig ist, sonst False.
    """
    if not hex_str:
        return False
    
    # Überprüfe, ob der Hexadezimalwert gültig ist
    hex_pattern = r"^[0-9a-f]+$"
    if re.match(hex_pattern, hex_str, re.IGNORECASE):
        return True
    
    return False

def is_valid_base64(base64_str):
    """
    Überprüft, ob ein Base64-Wert gültig ist.
    
    Args:
        base64_str: Der zu überprüfende Base64-Wert.
    
    Returns:
        True, wenn der Base64-Wert gültig ist, sonst False.
    """
    if not base64_str:
        return False
    
    # Überprüfe, ob der Base64-Wert gültig ist
    try:
        base64.b64decode(base64_str)
        return True
    except Exception:
        return False

def is_valid_json(json_str):
    """
    Überprüft, ob ein JSON-String gültig ist.
    
    Args:
        json_str: Der zu überprüfende JSON-String.
    
    Returns:
        True, wenn der JSON-String gültig ist, sonst False.
    """
    if not json_str:
        return False
    
    # Überprüfe, ob der JSON-String gültig ist
    try:
        json.loads(json_str)
        return True
    except Exception:
        return False

def is_valid_xml(xml_str):
    """
    Überprüft, ob ein XML-String gültig ist.
    
    Args:
        xml_str: Der zu überprüfende XML-String.
    
    Returns:
        True, wenn der XML-String gültig ist, sonst False.
    """
    if not xml_str:
        return False
    
    # Überprüfe, ob der XML-String gültig ist
    try:
        ET.fromstring(xml_str)
        return True
    except Exception:
        return False

def is_valid_html(html_str):
    """
    Überprüft, ob ein HTML-String gültig ist.
    
    Args:
        html_str: Der zu überprüfende HTML-String.
    
    Returns:
        True, wenn der HTML-String gültig ist, sonst False.
    """
    if not html_str:
        return False
    
    # Überprüfe, ob der HTML-String gültig ist
    try:
        parser = HTMLParser()
        parser.feed(html_str)
        return True
    except Exception:
        return False

def is_valid_css(css_str):
    """
    Überprüft, ob ein CSS-String gültig ist.
    
    Args:
        css_str: Der zu überprüfende CSS-String.
    
    Returns:
        True, wenn der CSS-String gültig ist, sonst False.
    """
    if not css_str:
        return False
    
    # Überprüfe, ob der CSS-String gültig ist
    css_pattern = r"^.*\{.*\}.*$"
    if re.match(css_pattern, css_str, re.DOTALL):
        return True
    
    return False

def is_valid_js(js_str):
    """
    Überprüft, ob ein JavaScript-String gültig ist.
    
    Args:
        js_str: Der zu überprüfende JavaScript-String.
    
    Returns:
        True, wenn der JavaScript-String gültig ist, sonst False.
    """
    if not js_str:
        return False
    
    # Überprüfe, ob der JavaScript-String gültig ist
    js_pattern = r"^.*function.*\(.*\).*\{.*\}.*$"
    if re.match(js_pattern, js_str):
        return True
    
    return False


# Beispielverwendung
if __name__ == "__main__":
    # URL-Funktionen
    url = "https://example.com/path?param1=value1&param2=value2"
    
    print(f"URL: {url}")
    print(f"Gültige URL: {is_valid_url(url)}")
    print(f"Normalisierte URL: {normalize_url(url)}")
    print(f"Domain: {get_domain_from_url(url)}")
    print(f"Basis-URL: {get_base_url(url)}")
    print(f"Pfad: {get_path_from_url(url)}")
    print(f"Query-Parameter: {get_query_params(url)}")
    
    # Datei-Funktionen
    file_path = "example.json"
    
    print(f"Datei: {file_path}")
    print(f"Dateierweiterung: {get_file_extension(file_path)}")
    print(f"Dateiname: {get_file_name(file_path)}")
    
    # Zeit-Funktionen
    timestamp = get_timestamp()
    
    print(f"Zeitstempel: {timestamp}")
    print(f"Formatierter Zeitstempel: {format_timestamp(timestamp)}")
    print(f"Aktuelles Datum: {get_current_date()}")
    print(f"Aktuelle Zeit: {get_current_time()}")
    print(f"Aktuelles Datum und Zeit: {get_current_datetime()}")
    
    # String-Funktionen
    print(f"Zufälliger String: {generate_random_string()}")
    print(f"Zufällige Zahl: {generate_random_number()}")
    print(f"Zufälliger Boolean-Wert: {generate_random_boolean()}")
    print(f"Zufällige Auswahl: {generate_random_choice(['a', 'b', 'c'])}")
    print(f"Zufällige Stichprobe: {generate_random_sample(['a', 'b', 'c', 'd', 'e'], 3)}")
    print(f"Hash: {generate_hash('test')}")
    print(f"Base64-Kodierung: {encode_base64('test')}")
    print(f"Base64-Dekodierung: {decode_base64(encode_base64('test'))}")
    print(f"URL-Kodierung: {url_encode('test test')}")
    print(f"URL-Dekodierung: {url_decode(url_encode('test test'))}")
    print(f"HTML-Kodierung: {html_encode('<test>')}")
    print(f"HTML-Dekodierung: {html_decode(html_encode('<test>'))}")
    
    # Sonstige Funktionen
    print(f"Gültige IP: {is_valid_ip('192.168.0.1')}")
    print(f"Gültige E-Mail: {is_valid_email('test@example.com')}")
    print(f"Gültige Domain: {is_valid_domain('example.com')}")
    print(f"Gültiger Port: {is_valid_port(80)}")
    print(f"Gültige MAC: {is_valid_mac('00:11:22:33:44:55')}")
    print(f"Gültige UUID: {is_valid_uuid('00000000-0000-0000-0000-000000000000')}")
    print(f"Gültiger Hexadezimalwert: {is_valid_hex('0123456789abcdef')}")
    print(f"Gültiger Base64-Wert: {is_valid_base64('dGVzdA==')}")
    json_test = '{"test": "test"}'
    print(f"Gültiger JSON-String: {is_valid_json(json_test)}")
    xml_test = '<?xml version="1.0" encoding="UTF-8"?><test>test</test>'
    print(f"Gültiger XML-String: {is_valid_xml(xml_test)}")
    html_test = '<!DOCTYPE html><html><head><title>Test</title></head><body><p>Test</p></body></html>'
    print(f"Gültiger HTML-String: {is_valid_html(html_test)}")
    print(f"Gültiger CSS-String: {is_valid_css('body { color: red; }')}")
    print(f"Gültiger JavaScript-String: {is_valid_js('function test() { return true; }')}")
