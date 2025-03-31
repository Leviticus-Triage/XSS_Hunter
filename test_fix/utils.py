#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Utilities
====================================

Dieses Modul enthält Hilfsfunktionen für das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import json
import logging
import time
import re
import random
import string
import hashlib
import base64
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.Utils")

# Versuche, den Error Handler zu importieren
try:
    from error_handler import handle_exception, log_error
except ImportError:
    logger.warning("Error Handler konnte nicht importiert werden. Verwende einfache Fehlerbehandlung.")
    
    # Einfache Fehlerbehandlung
    def handle_exception(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Fehler: {e}")
                return None
        return wrapper
    
    def log_error(error, error_type="UNKNOWN_ERROR", details=None):
        logger.error(f"{error_type}: {error}")
        if details:
            logger.error(f"Details: {details}")


# URL-Funktionen
@handle_exception
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
    
    # Überprüfe, ob die URL mit http:// oder https:// beginnt
    if not url.startswith(("http://", "https://")):
        return False
    
    # Überprüfe, ob die URL eine gültige Domain enthält
    domain_pattern = r"^(?:https?:\/\/)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\/.*)?$"
    if not re.match(domain_pattern, url):
        return False
    
    return True

@handle_exception
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
    
    # Füge http:// hinzu, wenn kein Schema vorhanden ist
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    # Entferne Trailing Slash
    if url.endswith("/"):
        url = url[:-1]
    
    return url

@handle_exception
def get_domain_from_url(url):
    """
    Extrahiert die Domain aus einer URL.
    
    Args:
        url: Die URL, aus der die Domain extrahiert werden soll.
    
    Returns:
        Die extrahierte Domain.
    """
    if not url:
        return ""
    
    # Normalisiere die URL
    url = normalize_url(url)
    
    # Extrahiere die Domain
    domain_pattern = r"^(?:https?:\/\/)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\/.*)?$"
    match = re.match(domain_pattern, url)
    
    if match:
        domain = match.group(1)
        return domain
    
    return ""

@handle_exception
def get_base_url(url):
    """
    Extrahiert die Basis-URL aus einer URL.
    
    Args:
        url: Die URL, aus der die Basis-URL extrahiert werden soll.
    
    Returns:
        Die extrahierte Basis-URL.
    """
    if not url:
        return ""
    
    # Normalisiere die URL
    url = normalize_url(url)
    
    # Extrahiere die Basis-URL
    base_url_pattern = r"^((?:https?:\/\/)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})(?:\/.*)?$"
    match = re.match(base_url_pattern, url)
    
    if match:
        base_url = match.group(1)
        return base_url
    
    return ""

@handle_exception
def get_path_from_url(url):
    """
    Extrahiert den Pfad aus einer URL.
    
    Args:
        url: Die URL, aus der der Pfad extrahiert werden soll.
    
    Returns:
        Der extrahierte Pfad.
    """
    if not url:
        return ""
    
    # Normalisiere die URL
    url = normalize_url(url)
    
    # Extrahiere den Pfad
    path_pattern = r"^(?:https?:\/\/)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(\/.*)?$"
    match = re.match(path_pattern, url)
    
    if match:
        path = match.group(1)
        return path or "/"
    
    return "/"

@handle_exception
def get_query_params(url):
    """
    Extrahiert die Query-Parameter aus einer URL.
    
    Args:
        url: Die URL, aus der die Query-Parameter extrahiert werden sollen.
    
    Returns:
        Die extrahierten Query-Parameter.
    """
    if not url:
        return {}
    
    # Normalisiere die URL
    url = normalize_url(url)
    
    # Extrahiere die Query-Parameter
    query_params = {}
    
    if "?" in url:
        query_string = url.split("?")[1]
        
        if "&" in query_string:
            params = query_string.split("&")
            
            for param in params:
                if "=" in param:
                    key, value = param.split("=", 1)
                    query_params[key] = value
                else:
                    query_params[param] = ""
        else:
            if "=" in query_string:
                key, value = query_string.split("=", 1)
                query_params[key] = value
            else:
                query_params[query_string] = ""
    
    return query_params

@handle_exception
def build_url(base_url, path="", query_params=None):
    """
    Erstellt eine URL aus einer Basis-URL, einem Pfad und Query-Parametern.
    
    Args:
        base_url: Die Basis-URL.
        path: Der Pfad.
        query_params: Die Query-Parameter.
    
    Returns:
        Die erstellte URL.
    """
    if not base_url:
        return ""
    
    # Normalisiere die Basis-URL
    base_url = normalize_url(base_url)
    
    # Füge den Pfad hinzu
    if path:
        if not path.startswith("/"):
            path = "/" + path
        
        url = base_url + path
    else:
        url = base_url
    
    # Füge die Query-Parameter hinzu
    if query_params:
        url += "?"
        
        for key, value in query_params.items():
            url += f"{key}={value}&"
        
        # Entferne das letzte &
        url = url[:-1]
    
    return url


# Datei-Funktionen
@handle_exception
def load_json_file(file_path):
    """
    Lädt eine JSON-Datei.
    
    Args:
        file_path: Der Pfad zur JSON-Datei.
    
    Returns:
        Der Inhalt der JSON-Datei.
    """
    if not file_path or not os.path.exists(file_path):
        logger.error(f"Datei nicht gefunden: {file_path}")
        return {}
    
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        
        logger.info(f"JSON-Datei geladen: {file_path}")
        
        return data
    except Exception as e:
        logger.error(f"Fehler beim Laden der JSON-Datei: {e}")
        return {}

@handle_exception
def save_json_file(data, file_path):
    """
    Speichert Daten in einer JSON-Datei.
    
    Args:
        data: Die zu speichernden Daten.
        file_path: Der Pfad zur JSON-Datei.
    
    Returns:
        True, wenn die Daten erfolgreich gespeichert wurden, sonst False.
    """
    if not file_path:
        logger.error("Kein Dateipfad angegeben.")
        return False
    
    try:
        # Erstelle das Verzeichnis, falls es nicht existiert
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"JSON-Datei gespeichert: {file_path}")
        
        return True
    except Exception as e:
        logger.error(f"Fehler beim Speichern der JSON-Datei: {e}")
        return False

@handle_exception
def load_text_file(file_path):
    """
    Lädt eine Textdatei.
    
    Args:
        file_path: Der Pfad zur Textdatei.
    
    Returns:
        Der Inhalt der Textdatei.
    """
    if not file_path or not os.path.exists(file_path):
        logger.error(f"Datei nicht gefunden: {file_path}")
        return ""
    
    try:
        with open(file_path, "r") as f:
            data = f.read()
        
        logger.info(f"Textdatei geladen: {file_path}")
        
        return data
    except Exception as e:
        logger.error(f"Fehler beim Laden der Textdatei: {e}")
        return ""

@handle_exception
def save_text_file(data, file_path):
    """
    Speichert Daten in einer Textdatei.
    
    Args:
        data: Die zu speichernden Daten.
        file_path: Der Pfad zur Textdatei.
    
    Returns:
        True, wenn die Daten erfolgreich gespeichert wurden, sonst False.
    """
    if not file_path:
        logger.error("Kein Dateipfad angegeben.")
        return False
    
    try:
        # Erstelle das Verzeichnis, falls es nicht existiert
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, "w") as f:
            f.write(data)
        
        logger.info(f"Textdatei gespeichert: {file_path}")
        
        return True
    except Exception as e:
        logger.error(f"Fehler beim Speichern der Textdatei: {e}")
        return False

@handle_exception
def get_file_extension(file_path):
    """
    Gibt die Dateierweiterung eines Dateipfads zurück.
    
    Args:
        file_path: Der Dateipfad.
    
    Returns:
        Die Dateierweiterung.
    """
    if not file_path:
        return ""
    
    return os.path.splitext(file_path)[1]

@handle_exception
def get_file_name(file_path):
    """
    Gibt den Dateinamen eines Dateipfads zurück.
    
    Args:
        file_path: Der Dateipfad.
    
    Returns:
        Der Dateiname.
    """
    if not file_path:
        return ""
    
    return os.path.basename(file_path)

@handle_exception
def get_file_size(file_path):
    """
    Gibt die Dateigröße eines Dateipfads zurück.
    
    Args:
        file_path: Der Dateipfad.
    
    Returns:
        Die Dateigröße.
    """
    if not file_path or not os.path.exists(file_path):
        return 0
    
    return os.path.getsize(file_path)

@handle_exception
def get_file_creation_time(file_path):
    """
    Gibt die Erstellungszeit eines Dateipfads zurück.
    
    Args:
        file_path: Der Dateipfad.
    
    Returns:
        Die Erstellungszeit.
    """
    if not file_path or not os.path.exists(file_path):
        return 0
    
    return os.path.getctime(file_path)

@handle_exception
def get_file_modification_time(file_path):
    """
    Gibt die Änderungszeit eines Dateipfads zurück.
    
    Args:
        file_path: Der Dateipfad.
    
    Returns:
        Die Änderungszeit.
    """
    if not file_path or not os.path.exists(file_path):
        return 0
    
    return os.path.getmtime(file_path)


# Zeit-Funktionen
@handle_exception
def get_timestamp():
    """
    Gibt den aktuellen Zeitstempel zurück.
    
    Returns:
        Der aktuelle Zeitstempel.
    """
    return int(time.time())

@handle_exception
def format_timestamp(timestamp, format="%Y-%m-%d %H:%M:%S"):
    """
    Formatiert einen Zeitstempel.
    
    Args:
        timestamp: Der zu formatierende Zeitstempel.
        format: Das Format für den Zeitstempel.
    
    Returns:
        Der formatierte Zeitstempel.
    """
    if not timestamp:
        return ""
    
    return time.strftime(format, time.localtime(timestamp))

@handle_exception
def get_current_date():
    """
    Gibt das aktuelle Datum zurück.
    
    Returns:
        Das aktuelle Datum.
    """
    return time.strftime("%Y-%m-%d", time.localtime())

@handle_exception
def get_current_time():
    """
    Gibt die aktuelle Zeit zurück.
    
    Returns:
        Die aktuelle Zeit.
    """
    return time.strftime("%H:%M:%S", time.localtime())

@handle_exception
def get_current_datetime():
    """
    Gibt das aktuelle Datum und die aktuelle Zeit zurück.
    
    Returns:
        Das aktuelle Datum und die aktuelle Zeit.
    """
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


# String-Funktionen
@handle_exception
def generate_random_string(length=10):
    """
    Generiert einen zufälligen String.
    
    Args:
        length: Die Länge des zu generierenden Strings.
    
    Returns:
        Der generierte String.
    """
    if not length or length <= 0:
        return ""
    
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

@handle_exception
def generate_random_number(min_value=0, max_value=100):
    """
    Generiert eine zufällige Zahl.
    
    Args:
        min_value: Der Minimalwert für die zu generierende Zahl.
        max_value: Der Maximalwert für die zu generierende Zahl.
    
    Returns:
        Die generierte Zahl.
    """
    if min_value > max_value:
        min_value, max_value = max_value, min_value
    
    return random.randint(min_value, max_value)

@handle_exception
def generate_random_boolean():
    """
    Generiert einen zufälligen Boolean-Wert.
    
    Returns:
        Der generierte Boolean-Wert.
    """
    return random.choice([True, False])

@handle_exception
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

@handle_exception
def generate_random_sample(choices, k=1):
    """
    Wählt mehrere zufällige Elemente aus einer Liste aus.
    
    Args:
        choices: Die Liste, aus der Elemente ausgewählt werden sollen.
        k: Die Anzahl der auszuwählenden Elemente.
    
    Returns:
        Die ausgewählten Elemente.
    """
    if not choices:
        return []
    
    if k <= 0:
        return []
    
    if k > len(choices):
        k = len(choices)
    
    return random.sample(choices, k)

@handle_exception
def generate_hash(data, algorithm="sha256"):
    """
    Generiert einen Hash für die angegebenen Daten.
    
    Args:
        data: Die Daten, für die ein Hash generiert werden soll.
        algorithm: Der zu verwendende Hash-Algorithmus.
    
    Returns:
        Der generierte Hash.
    """
    if not data:
        return ""
    
    if isinstance(data, str):
        data = data.encode()
    
    if algorithm == "md5":
        return hashlib.md5(data).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data).hexdigest()
    else:
        return hashlib.sha256(data).hexdigest()

@handle_exception
def encode_base64(data):
    """
    Kodiert Daten in Base64.
    
    Args:
        data: Die zu kodierenden Daten.
    
    Returns:
        Die kodierten Daten.
    """
    if not data:
        return ""
    
    if isinstance(data, str):
        data = data.encode()
    
    return base64.b64encode(data).decode()

@handle_exception
def decode_base64(data):
    """
    Dekodiert Base64-kodierte Daten.
    
    Args:
        data: Die zu dekodierenden Daten.
    
    Returns:
        Die dekodierten Daten.
    """
    if not data:
        return ""
    
    if isinstance(data, str):
        data = data.encode()
    
    return base64.b64decode(data).decode()

@handle_exception
def url_encode(data):
    """
    Kodiert Daten für die Verwendung in URLs.
    
    Args:
        data: Die zu kodierenden Daten.
    
    Returns:
        Die kodierten Daten.
    """
    if not data:
        return ""
    
    return urllib.parse.quote(data)

@handle_exception
def url_decode(data):
    """
    Dekodiert URL-kodierte Daten.
    
    Args:
        data: Die zu dekodierenden Daten.
    
    Returns:
        Die dekodierten Daten.
    """
    if not data:
        return ""
    
    return urllib.parse.unquote(data)

@handle_exception
def html_encode(data):
    """
    Kodiert Daten für die Verwendung in HTML.
    
    Args:
        data: Die zu kodierenden Daten.
    
    Returns:
        Die kodierten Daten.
    """
    if not data:
        return ""
    
    return data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

@handle_exception
def html_decode(data):
    """
    Dekodiert HTML-kodierte Daten.
    
    Args:
        data: Die zu dekodierenden Daten.
    
    Returns:
        Die dekodierten Daten.
    """
    if not data:
        return ""
    
    return data.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'")


# Sonstige Funktionen
@handle_exception
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
    
    # Überprüfe, ob die IP-Adresse eine IPv4-Adresse ist
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(ipv4_pattern, ip):
        return True
    
    # Überprüfe, ob die IP-Adresse eine IPv6-Adresse ist
    ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    if re.match(ipv6_pattern, ip):
        return True
    
    return False

@handle_exception
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

@handle_exception
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
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(domain_pattern, domain):
        return True
    
    return False

@handle_exception
def is_valid_port(port):
    """
    Überprüft, ob ein Port gültig ist.
    
    Args:
        port: Der zu überprüfende Port.
    
    Returns:
        True, wenn der Port gültig ist, sonst False.
    """
    if not port:
        return False
    
    try:
        port = int(port)
        return 0 <= port <= 65535
    except:
        return False

@handle_exception
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

@handle_exception
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
    if re.match(uuid_pattern, uuid):
        return True
    
    return False

@handle_exception
def is_valid_hex(hex):
    """
    Überprüft, ob ein Hexadezimalwert gültig ist.
    
    Args:
        hex: Der zu überprüfende Hexadezimalwert.
    
    Returns:
        True, wenn der Hexadezimalwert gültig ist, sonst False.
    """
    if not hex:
        return False
    
    # Überprüfe, ob der Hexadezimalwert gültig ist
    hex_pattern = r"^[0-9a-fA-F]+$"
    if re.match(hex_pattern, hex):
        return True
    
    return False

@handle_exception
def is_valid_base64(base64):
    """
    Überprüft, ob ein Base64-Wert gültig ist.
    
    Args:
        base64: Der zu überprüfende Base64-Wert.
    
    Returns:
        True, wenn der Base64-Wert gültig ist, sonst False.
    """
    if not base64:
        return False
    
    # Überprüfe, ob der Base64-Wert gültig ist
    base64_pattern = r"^[A-Za-z0-9+/]+={0,2}$"
    if re.match(base64_pattern, base64):
        return True
    
    return False

@handle_exception
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
    
    try:
        json.loads(json_str)
        return True
    except:
        return False

@handle_exception
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
    xml_pattern = r"^<\?xml.*\?>.*$"
    if re.match(xml_pattern, xml_str):
        return True
    
    return False

@handle_exception
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
    html_pattern = r"^<!DOCTYPE html>.*$"
    if re.match(html_pattern, html_str):
        return True
    
    return False

@handle_exception
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
    if re.match(css_pattern, css_str):
        return True
    
    return False

@handle_exception
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
    print(f"Gültiger JSON-String: {is_valid_json('{"test": "test"}')}")
    print(f"Gültiger XML-String: {is_valid_xml('<?xml version="1.0" encoding="UTF-8"?><test>test</test>')}")
    print(f"Gültiger HTML-String: {is_valid_html('<!DOCTYPE html><html><head><title>Test</title></head><body><p>Test</p></body></html>')}")
    print(f"Gültiger CSS-String: {is_valid_css('body { color: red; }')}")
    print(f"Gültiger JavaScript-String: {is_valid_js('function test() { return true; }')}")
