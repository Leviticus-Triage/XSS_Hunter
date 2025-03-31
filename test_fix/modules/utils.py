#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Utils Module
=============================================

Dieses Modul stellt Hilfsfunktionen für das XSS Hunter Framework bereit.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import re
import json
import logging
import urllib.parse
import socket
import time
import random
import string
import hashlib
import base64
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


@handle_exception
def is_valid_url(url: str) -> bool:
    """
    Überprüft, ob eine URL gültig ist.
    
    Args:
        url: Die zu überprüfende URL.
    
    Returns:
        True, wenn die URL gültig ist, sonst False.
    """
    # Einfache Überprüfung auf gültige URL-Syntax
    if not url:
        return False
    
    # Überprüfe, ob die URL mit http:// oder https:// beginnt
    if not url.startswith(("http://", "https://")):
        return False
    
    # Überprüfe die URL-Syntax mit regulärem Ausdruck
    url_pattern = re.compile(
        r'^(?:http|https)://'  # http:// oder https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # Domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # Port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(url_pattern.match(url))


@handle_exception
def is_valid_param(param: str) -> bool:
    """
    Überprüft, ob ein Parameter gültig ist.
    
    Args:
        param: Der zu überprüfende Parameter.
    
    Returns:
        True, wenn der Parameter gültig ist, sonst False.
    """
    # Einfache Überprüfung auf gültigen Parameternamen
    if not param:
        return False
    
    # Überprüfe, ob der Parameter nur alphanumerische Zeichen, Unterstriche und Bindestriche enthält
    param_pattern = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
    
    return bool(param_pattern.match(param))


@handle_exception
def is_valid_method(method: str) -> bool:
    """
    Überprüft, ob eine HTTP-Methode gültig ist.
    
    Args:
        method: Die zu überprüfende HTTP-Methode.
    
    Returns:
        True, wenn die Methode gültig ist, sonst False.
    """
    # Überprüfe, ob die Methode in der Liste der gültigen Methoden enthalten ist
    valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
    
    return method.upper() in valid_methods


@handle_exception
def is_valid_context(context: str) -> bool:
    """
    Überprüft, ob ein Kontext gültig ist.
    
    Args:
        context: Der zu überprüfende Kontext.
    
    Returns:
        True, wenn der Kontext gültig ist, sonst False.
    """
    # Überprüfe, ob der Kontext in der Liste der gültigen Kontexte enthalten ist
    valid_contexts = ["html", "javascript", "url", "dom", "attribute", "css"]
    
    return context.lower() in valid_contexts


@handle_exception
def is_valid_exploit_type(exploit_type: str) -> bool:
    """
    Überprüft, ob ein Exploit-Typ gültig ist.
    
    Args:
        exploit_type: Der zu überprüfende Exploit-Typ.
    
    Returns:
        True, wenn der Exploit-Typ gültig ist, sonst False.
    """
    # Überprüfe, ob der Exploit-Typ in der Liste der gültigen Exploit-Typen enthalten ist
    valid_exploit_types = ["reflected_xss", "stored_xss", "dom_xss", "xss_data_theft", "keylogger", "cookie_stealer"]
    
    return exploit_type.lower() in valid_exploit_types


@handle_exception
def is_valid_format(format: str) -> bool:
    """
    Überprüft, ob ein Format gültig ist.
    
    Args:
        format: Das zu überprüfende Format.
    
    Returns:
        True, wenn das Format gültig ist, sonst False.
    """
    # Überprüfe, ob das Format in der Liste der gültigen Formate enthalten ist
    valid_formats = ["json", "html", "markdown", "md", "txt", "xml", "csv"]
    
    return format.lower() in valid_formats


@handle_exception
def extract_params_from_url(url: str) -> List[str]:
    """
    Extrahiert Parameter aus einer URL.
    
    Args:
        url: Die URL, aus der Parameter extrahiert werden sollen.
    
    Returns:
        Eine Liste der Parameter.
    """
    # Parse die URL
    parsed_url = urllib.parse.urlparse(url)
    
    # Parse die Query-Parameter
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    # Extrahiere die Parameternamen
    params = list(query_params.keys())
    
    return params


@handle_exception
def extract_forms_from_html(html: str) -> List[Dict[str, Any]]:
    """
    Extrahiert Formulare aus HTML.
    
    Args:
        html: Der HTML-Code, aus dem Formulare extrahiert werden sollen.
    
    Returns:
        Eine Liste der Formulare.
    """
    forms = []
    
    try:
        # Versuche, BeautifulSoup zu importieren
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            # Versuche, den Dependency Wrapper zu verwenden
            try:
                from lib.dependency_wrapper import BeautifulSoup
            except ImportError:
                logger.error("BeautifulSoup konnte nicht importiert werden.")
                return forms
        
        # Parse das HTML
        soup = BeautifulSoup(html, "html.parser")
        
        # Finde alle Formulare
        form_tags = soup.find_all("form")
        
        for form_tag in form_tags:
            form = {
                "action": form_tag.get("action", ""),
                "method": form_tag.get("method", "GET").upper(),
                "inputs": []
            }
            
            # Finde alle Eingabefelder
            input_tags = form_tag.find_all(["input", "textarea", "select"])
            
            for input_tag in input_tags:
                input_type = input_tag.get("type", "text").lower()
                
                # Überspringe Submit-Buttons und versteckte Felder
                if input_type in ["submit", "button", "image", "reset"]:
                    continue
                
                input_name = input_tag.get("name", "")
                
                if input_name:
                    form["inputs"].append({
                        "name": input_name,
                        "type": input_type,
                        "value": input_tag.get("value", "")
                    })
            
            forms.append(form)
    except Exception as e:
        log_error(e, "HTML_PARSING_ERROR", {"html_length": len(html)})
    
    return forms


@handle_exception
def extract_links_from_html(html: str, base_url: str) -> List[str]:
    """
    Extrahiert Links aus HTML.
    
    Args:
        html: Der HTML-Code, aus dem Links extrahiert werden sollen.
        base_url: Die Basis-URL für relative Links.
    
    Returns:
        Eine Liste der Links.
    """
    links = []
    
    try:
        # Versuche, BeautifulSoup zu importieren
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            # Versuche, den Dependency Wrapper zu verwenden
            try:
                from lib.dependency_wrapper import BeautifulSoup
            except ImportError:
                logger.error("BeautifulSoup konnte nicht importiert werden.")
                return links
        
        # Parse das HTML
        soup = BeautifulSoup(html, "html.parser")
        
        # Finde alle Links
        a_tags = soup.find_all("a")
        
        for a_tag in a_tags:
            href = a_tag.get("href", "")
            
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                # Konvertiere relative URLs in absolute URLs
                if not href.startswith(("http://", "https://")):
                    href = urllib.parse.urljoin(base_url, href)
                
                # Füge den Link zur Liste hinzu, wenn er gültig ist
                if is_valid_url(href):
                    links.append(href)
    except Exception as e:
        log_error(e, "HTML_PARSING_ERROR", {"html_length": len(html), "base_url": base_url})
    
    return links


@handle_exception
def normalize_url(url: str) -> str:
    """
    Normalisiert eine URL.
    
    Args:
        url: Die zu normalisierende URL.
    
    Returns:
        Die normalisierte URL.
    """
    # Parse die URL
    parsed_url = urllib.parse.urlparse(url)
    
    # Normalisiere den Pfad
    path = parsed_url.path
    
    if not path:
        path = "/"
    
    # Entferne doppelte Schrägstriche
    while "//" in path:
        path = path.replace("//", "/")
    
    # Entferne den Anker
    fragment = ""
    
    # Erstelle die normalisierte URL
    normalized_url = urllib.parse.urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        path,
        parsed_url.params,
        parsed_url.query,
        fragment
    ))
    
    return normalized_url


@handle_exception
def is_same_origin(url1: str, url2: str) -> bool:
    """
    Überprüft, ob zwei URLs denselben Ursprung haben.
    
    Args:
        url1: Die erste URL.
        url2: Die zweite URL.
    
    Returns:
        True, wenn die URLs denselben Ursprung haben, sonst False.
    """
    # Parse die URLs
    parsed_url1 = urllib.parse.urlparse(url1)
    parsed_url2 = urllib.parse.urlparse(url2)
    
    # Vergleiche Scheme und Netloc
    return (parsed_url1.scheme == parsed_url2.scheme and
            parsed_url1.netloc == parsed_url2.netloc)


@handle_exception
def generate_random_string(length: int = 8) -> str:
    """
    Generiert eine zufällige Zeichenkette.
    
    Args:
        length: Die Länge der Zeichenkette.
    
    Returns:
        Die generierte Zeichenkette.
    """
    # Generiere eine zufällige Zeichenkette aus Buchstaben und Zahlen
    characters = string.ascii_letters + string.digits
    
    return ''.join(random.choice(characters) for _ in range(length))


@handle_exception
def generate_payload_marker() -> str:
    """
    Generiert einen Payload-Marker.
    
    Returns:
        Der generierte Payload-Marker.
    """
    # Generiere einen zufälligen Marker
    random_string = generate_random_string(8)
    
    return f"XSS-HUNTER-MARKER-{random_string}"


@handle_exception
def encode_payload(payload: str, encoding: str = "url") -> str:
    """
    Kodiert einen Payload.
    
    Args:
        payload: Der zu kodierende Payload.
        encoding: Die zu verwendende Kodierung.
    
    Returns:
        Der kodierte Payload.
    """
    if encoding == "url":
        # URL-Kodierung
        return urllib.parse.quote(payload)
    elif encoding == "html":
        # HTML-Kodierung
        return payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
    elif encoding == "js":
        # JavaScript-Kodierung
        return payload.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    elif encoding == "base64":
        # Base64-Kodierung
        return base64.b64encode(payload.encode()).decode()
    else:
        # Keine Kodierung
        return payload


@handle_exception
def decode_payload(payload: str, encoding: str = "url") -> str:
    """
    Dekodiert einen Payload.
    
    Args:
        payload: Der zu dekodierende Payload.
        encoding: Die verwendete Kodierung.
    
    Returns:
        Der dekodierte Payload.
    """
    if encoding == "url":
        # URL-Dekodierung
        return urllib.parse.unquote(payload)
    elif encoding == "html":
        # HTML-Dekodierung
        return payload.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#x27;", "'")
    elif encoding == "js":
        # JavaScript-Dekodierung
        return payload.replace("\\n", "\n").replace("\\r", "\r").replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
    elif encoding == "base64":
        # Base64-Dekodierung
        return base64.b64decode(payload.encode()).decode()
    else:
        # Keine Dekodierung
        return payload


@handle_exception
def check_internet_connection() -> bool:
    """
    Überprüft, ob eine Internetverbindung besteht.
    
    Returns:
        True, wenn eine Internetverbindung besteht, sonst False.
    """
    try:
        # Versuche, eine Verbindung zu einem bekannten Server herzustellen
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False


@handle_exception
def load_json_file(file_path: str) -> Dict[str, Any]:
    """
    Lädt eine JSON-Datei.
    
    Args:
        file_path: Der Pfad zur JSON-Datei.
    
    Returns:
        Der Inhalt der JSON-Datei.
    """
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        log_error(e, "JSON_PARSING_ERROR", {"file_path": file_path})
        return {}
    except FileNotFoundError as e:
        log_error(e, "FILE_NOT_FOUND_ERROR", {"file_path": file_path})
        return {}
    except Exception as e:
        log_error(e, "FILE_READING_ERROR", {"file_path": file_path})
        return {}


@handle_exception
def save_json_file(data: Dict[str, Any], file_path: str) -> bool:
    """
    Speichert Daten in einer JSON-Datei.
    
    Args:
        data: Die zu speichernden Daten.
        file_path: Der Pfad zur JSON-Datei.
    
    Returns:
        True, wenn die Daten erfolgreich gespeichert wurden, sonst False.
    """
    try:
        # Erstelle das Verzeichnis, falls es nicht existiert
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)
        
        return True
    except Exception as e:
        log_error(e, "FILE_WRITING_ERROR", {"file_path": file_path})
        return False


@handle_exception
def calculate_hash(data: str, algorithm: str = "sha256") -> str:
    """
    Berechnet den Hash eines Strings.
    
    Args:
        data: Der String, für den der Hash berechnet werden soll.
        algorithm: Der zu verwendende Hash-Algorithmus.
    
    Returns:
        Der berechnete Hash.
    """
    if algorithm == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data.encode()).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(data.encode()).hexdigest()
    else:
        return hashlib.sha256(data.encode()).hexdigest()


@handle_exception
def get_domain_from_url(url: str) -> str:
    """
    Extrahiert die Domain aus einer URL.
    
    Args:
        url: Die URL, aus der die Domain extrahiert werden soll.
    
    Returns:
        Die extrahierte Domain.
    """
    # Parse die URL
    parsed_url = urllib.parse.urlparse(url)
    
    # Extrahiere die Domain
    domain = parsed_url.netloc
    
    # Entferne den Port, falls vorhanden
    if ":" in domain:
        domain = domain.split(":")[0]
    
    return domain


@handle_exception
def get_base_url(url: str) -> str:
    """
    Extrahiert die Basis-URL aus einer URL.
    
    Args:
        url: Die URL, aus der die Basis-URL extrahiert werden soll.
    
    Returns:
        Die extrahierte Basis-URL.
    """
    # Parse die URL
    parsed_url = urllib.parse.urlparse(url)
    
    # Erstelle die Basis-URL
    base_url = urllib.parse.urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        "",
        "",
        "",
        ""
    ))
    
    return base_url


@handle_exception
def is_ip_address(host: str) -> bool:
    """
    Überprüft, ob ein Host eine IP-Adresse ist.
    
    Args:
        host: Der zu überprüfende Host.
    
    Returns:
        True, wenn der Host eine IP-Adresse ist, sonst False.
    """
    # Überprüfe, ob der Host eine IPv4-Adresse ist
    ipv4_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    
    if ipv4_pattern.match(host):
        # Überprüfe, ob die Zahlen im gültigen Bereich liegen
        try:
            parts = host.split(".")
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    # Überprüfe, ob der Host eine IPv6-Adresse ist
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (socket.error, AttributeError):
        return False


@handle_exception
def is_local_host(host: str) -> bool:
    """
    Überprüft, ob ein Host ein lokaler Host ist.
    
    Args:
        host: Der zu überprüfende Host.
    
    Returns:
        True, wenn der Host ein lokaler Host ist, sonst False.
    """
    # Überprüfe, ob der Host localhost ist
    if host.lower() == "localhost":
        return True
    
    # Überprüfe, ob der Host eine lokale IP-Adresse ist
    if is_ip_address(host):
        # Überprüfe, ob die IP-Adresse eine lokale IP-Adresse ist
        if host.startswith(("127.", "0.", "::1")):
            return True
        
        # Überprüfe, ob die IP-Adresse eine private IP-Adresse ist
        if (host.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                            "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                            "172.30.", "172.31.", "192.168.")) or
            host.startswith(("fd", "fc"))):
            return True
    
    return False


@handle_exception
def is_valid_port(port: int) -> bool:
    """
    Überprüft, ob ein Port gültig ist.
    
    Args:
        port: Der zu überprüfende Port.
    
    Returns:
        True, wenn der Port gültig ist, sonst False.
    """
    return 0 < port < 65536


@handle_exception
def is_valid_ip(ip: str) -> bool:
    """
    Überprüft, ob eine IP-Adresse gültig ist.
    
    Args:
        ip: Die zu überprüfende IP-Adresse.
    
    Returns:
        True, wenn die IP-Adresse gültig ist, sonst False.
    """
    return is_ip_address(ip)


@handle_exception
def get_timestamp() -> int:
    """
    Gibt den aktuellen Zeitstempel zurück.
    
    Returns:
        Der aktuelle Zeitstempel.
    """
    return int(time.time())


@handle_exception
def format_timestamp(timestamp: int, format: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Formatiert einen Zeitstempel.
    
    Args:
        timestamp: Der zu formatierende Zeitstempel.
        format: Das zu verwendende Format.
    
    Returns:
        Der formatierte Zeitstempel.
    """
    return time.strftime(format, time.localtime(timestamp))


@handle_exception
def get_file_extension(file_path: str) -> str:
    """
    Gibt die Dateierweiterung einer Datei zurück.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        Die Dateierweiterung.
    """
    return os.path.splitext(file_path)[1].lower()


@handle_exception
def is_valid_file_extension(file_path: str, allowed_extensions: List[str]) -> bool:
    """
    Überprüft, ob eine Datei eine gültige Dateierweiterung hat.
    
    Args:
        file_path: Der Pfad zur Datei.
        allowed_extensions: Die erlaubten Dateierweiterungen.
    
    Returns:
        True, wenn die Datei eine gültige Dateierweiterung hat, sonst False.
    """
    extension = get_file_extension(file_path)
    
    return extension in allowed_extensions


@handle_exception
def is_valid_file_size(file_path: str, max_size: int) -> bool:
    """
    Überprüft, ob eine Datei eine gültige Größe hat.
    
    Args:
        file_path: Der Pfad zur Datei.
        max_size: Die maximale Größe in Bytes.
    
    Returns:
        True, wenn die Datei eine gültige Größe hat, sonst False.
    """
    return os.path.getsize(file_path) <= max_size


@handle_exception
def is_valid_file(file_path: str, allowed_extensions: List[str], max_size: int) -> bool:
    """
    Überprüft, ob eine Datei gültig ist.
    
    Args:
        file_path: Der Pfad zur Datei.
        allowed_extensions: Die erlaubten Dateierweiterungen.
        max_size: Die maximale Größe in Bytes.
    
    Returns:
        True, wenn die Datei gültig ist, sonst False.
    """
    return (os.path.isfile(file_path) and
            is_valid_file_extension(file_path, allowed_extensions) and
            is_valid_file_size(file_path, max_size))


@handle_exception
def sanitize_filename(filename: str) -> str:
    """
    Bereinigt einen Dateinamen.
    
    Args:
        filename: Der zu bereinigende Dateiname.
    
    Returns:
        Der bereinigte Dateiname.
    """
    # Entferne ungültige Zeichen
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    
    sanitized = ''.join(c for c in filename if c in valid_chars)
    
    # Entferne Leerzeichen am Anfang und Ende
    sanitized = sanitized.strip()
    
    # Ersetze mehrere aufeinanderfolgende Leerzeichen durch ein einzelnes
    sanitized = re.sub(r'\s+', ' ', sanitized)
    
    # Ersetze Leerzeichen durch Unterstriche
    sanitized = sanitized.replace(' ', '_')
    
    # Stelle sicher, dass der Dateiname nicht leer ist
    if not sanitized:
        sanitized = "unnamed"
    
    return sanitized


@handle_exception
def get_mime_type(file_path: str) -> str:
    """
    Gibt den MIME-Typ einer Datei zurück.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        Der MIME-Typ.
    """
    import mimetypes
    
    # Initialisiere die MIME-Typen
    mimetypes.init()
    
    # Bestimme den MIME-Typ
    mime_type, _ = mimetypes.guess_type(file_path)
    
    # Verwende einen Standard-MIME-Typ, wenn keiner gefunden wurde
    if mime_type is None:
        mime_type = "application/octet-stream"
    
    return mime_type


@handle_exception
def is_binary_file(file_path: str) -> bool:
    """
    Überprüft, ob eine Datei eine Binärdatei ist.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        True, wenn die Datei eine Binärdatei ist, sonst False.
    """
    # Überprüfe den MIME-Typ
    mime_type = get_mime_type(file_path)
    
    # Überprüfe, ob der MIME-Typ auf eine Binärdatei hinweist
    return not mime_type.startswith(("text/", "application/json", "application/xml"))


@handle_exception
def read_file(file_path: str, binary: bool = False) -> Union[str, bytes]:
    """
    Liest eine Datei.
    
    Args:
        file_path: Der Pfad zur Datei.
        binary: Ob die Datei im Binärmodus gelesen werden soll.
    
    Returns:
        Der Inhalt der Datei.
    """
    try:
        mode = "rb" if binary else "r"
        
        with open(file_path, mode) as f:
            return f.read()
    except Exception as e:
        log_error(e, "FILE_READING_ERROR", {"file_path": file_path, "binary": binary})
        return b"" if binary else ""


@handle_exception
def write_file(file_path: str, content: Union[str, bytes], binary: bool = False) -> bool:
    """
    Schreibt in eine Datei.
    
    Args:
        file_path: Der Pfad zur Datei.
        content: Der zu schreibende Inhalt.
        binary: Ob die Datei im Binärmodus geschrieben werden soll.
    
    Returns:
        True, wenn der Inhalt erfolgreich geschrieben wurde, sonst False.
    """
    try:
        # Erstelle das Verzeichnis, falls es nicht existiert
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        mode = "wb" if binary else "w"
        
        with open(file_path, mode) as f:
            f.write(content)
        
        return True
    except Exception as e:
        log_error(e, "FILE_WRITING_ERROR", {"file_path": file_path, "binary": binary})
        return False


@handle_exception
def append_to_file(file_path: str, content: Union[str, bytes], binary: bool = False) -> bool:
    """
    Hängt Inhalt an eine Datei an.
    
    Args:
        file_path: Der Pfad zur Datei.
        content: Der anzuhängende Inhalt.
        binary: Ob die Datei im Binärmodus geschrieben werden soll.
    
    Returns:
        True, wenn der Inhalt erfolgreich angehängt wurde, sonst False.
    """
    try:
        # Erstelle das Verzeichnis, falls es nicht existiert
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        mode = "ab" if binary else "a"
        
        with open(file_path, mode) as f:
            f.write(content)
        
        return True
    except Exception as e:
        log_error(e, "FILE_WRITING_ERROR", {"file_path": file_path, "binary": binary})
        return False


@handle_exception
def delete_file(file_path: str) -> bool:
    """
    Löscht eine Datei.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        True, wenn die Datei erfolgreich gelöscht wurde, sonst False.
    """
    try:
        if os.path.isfile(file_path):
            os.remove(file_path)
            return True
        else:
            return False
    except Exception as e:
        log_error(e, "FILE_DELETION_ERROR", {"file_path": file_path})
        return False


@handle_exception
def create_directory(directory_path: str) -> bool:
    """
    Erstellt ein Verzeichnis.
    
    Args:
        directory_path: Der Pfad zum Verzeichnis.
    
    Returns:
        True, wenn das Verzeichnis erfolgreich erstellt wurde, sonst False.
    """
    try:
        os.makedirs(directory_path, exist_ok=True)
        return True
    except Exception as e:
        log_error(e, "DIRECTORY_CREATION_ERROR", {"directory_path": directory_path})
        return False


@handle_exception
def delete_directory(directory_path: str, recursive: bool = False) -> bool:
    """
    Löscht ein Verzeichnis.
    
    Args:
        directory_path: Der Pfad zum Verzeichnis.
        recursive: Ob das Verzeichnis rekursiv gelöscht werden soll.
    
    Returns:
        True, wenn das Verzeichnis erfolgreich gelöscht wurde, sonst False.
    """
    try:
        if os.path.isdir(directory_path):
            if recursive:
                import shutil
                shutil.rmtree(directory_path)
            else:
                os.rmdir(directory_path)
            return True
        else:
            return False
    except Exception as e:
        log_error(e, "DIRECTORY_DELETION_ERROR", {"directory_path": directory_path, "recursive": recursive})
        return False


@handle_exception
def list_files(directory_path: str, pattern: str = "*") -> List[str]:
    """
    Listet Dateien in einem Verzeichnis auf.
    
    Args:
        directory_path: Der Pfad zum Verzeichnis.
        pattern: Das Muster für die Dateinamen.
    
    Returns:
        Eine Liste der Dateien.
    """
    try:
        import glob
        
        # Erstelle den Pfad mit dem Muster
        path_pattern = os.path.join(directory_path, pattern)
        
        # Finde alle Dateien, die dem Muster entsprechen
        files = glob.glob(path_pattern)
        
        # Filtere Verzeichnisse heraus
        files = [f for f in files if os.path.isfile(f)]
        
        return files
    except Exception as e:
        log_error(e, "FILE_LISTING_ERROR", {"directory_path": directory_path, "pattern": pattern})
        return []


@handle_exception
def list_directories(directory_path: str, pattern: str = "*") -> List[str]:
    """
    Listet Verzeichnisse in einem Verzeichnis auf.
    
    Args:
        directory_path: Der Pfad zum Verzeichnis.
        pattern: Das Muster für die Verzeichnisnamen.
    
    Returns:
        Eine Liste der Verzeichnisse.
    """
    try:
        import glob
        
        # Erstelle den Pfad mit dem Muster
        path_pattern = os.path.join(directory_path, pattern)
        
        # Finde alle Dateien und Verzeichnisse, die dem Muster entsprechen
        items = glob.glob(path_pattern)
        
        # Filtere Dateien heraus
        directories = [d for d in items if os.path.isdir(d)]
        
        return directories
    except Exception as e:
        log_error(e, "DIRECTORY_LISTING_ERROR", {"directory_path": directory_path, "pattern": pattern})
        return []


@handle_exception
def get_file_size(file_path: str) -> int:
    """
    Gibt die Größe einer Datei zurück.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        Die Größe der Datei in Bytes.
    """
    try:
        return os.path.getsize(file_path)
    except Exception as e:
        log_error(e, "FILE_SIZE_ERROR", {"file_path": file_path})
        return 0


@handle_exception
def get_file_modification_time(file_path: str) -> int:
    """
    Gibt die letzte Änderungszeit einer Datei zurück.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        Die letzte Änderungszeit der Datei als Zeitstempel.
    """
    try:
        return int(os.path.getmtime(file_path))
    except Exception as e:
        log_error(e, "FILE_MODIFICATION_TIME_ERROR", {"file_path": file_path})
        return 0


@handle_exception
def get_file_creation_time(file_path: str) -> int:
    """
    Gibt die Erstellungszeit einer Datei zurück.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        Die Erstellungszeit der Datei als Zeitstempel.
    """
    try:
        return int(os.path.getctime(file_path))
    except Exception as e:
        log_error(e, "FILE_CREATION_TIME_ERROR", {"file_path": file_path})
        return 0


@handle_exception
def get_file_access_time(file_path: str) -> int:
    """
    Gibt die letzte Zugriffszeit einer Datei zurück.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        Die letzte Zugriffszeit der Datei als Zeitstempel.
    """
    try:
        return int(os.path.getatime(file_path))
    except Exception as e:
        log_error(e, "FILE_ACCESS_TIME_ERROR", {"file_path": file_path})
        return 0


@handle_exception
def format_file_size(size: int) -> str:
    """
    Formatiert eine Dateigröße.
    
    Args:
        size: Die zu formatierende Größe in Bytes.
    
    Returns:
        Die formatierte Größe.
    """
    # Definiere die Einheiten
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    
    # Bestimme die Einheit
    unit_index = 0
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    # Formatiere die Größe
    if unit_index == 0:
        return f"{size} {units[unit_index]}"
    else:
        return f"{size:.2f} {units[unit_index]}"


@handle_exception
def is_valid_email(email: str) -> bool:
    """
    Überprüft, ob eine E-Mail-Adresse gültig ist.
    
    Args:
        email: Die zu überprüfende E-Mail-Adresse.
    
    Returns:
        True, wenn die E-Mail-Adresse gültig ist, sonst False.
    """
    # Überprüfe die E-Mail-Adresse mit einem regulären Ausdruck
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    return bool(email_pattern.match(email))


@handle_exception
def is_valid_phone_number(phone: str) -> bool:
    """
    Überprüft, ob eine Telefonnummer gültig ist.
    
    Args:
        phone: Die zu überprüfende Telefonnummer.
    
    Returns:
        True, wenn die Telefonnummer gültig ist, sonst False.
    """
    # Entferne Leerzeichen, Bindestriche und Klammern
    phone = re.sub(r'[\s\-()]', '', phone)
    
    # Überprüfe, ob die Telefonnummer nur Ziffern und das Pluszeichen enthält
    if not re.match(r'^\+?\d+$', phone):
        return False
    
    # Überprüfe die Länge der Telefonnummer
    return 7 <= len(phone) <= 15


@handle_exception
def is_valid_credit_card(card_number: str) -> bool:
    """
    Überprüft, ob eine Kreditkartennummer gültig ist.
    
    Args:
        card_number: Die zu überprüfende Kreditkartennummer.
    
    Returns:
        True, wenn die Kreditkartennummer gültig ist, sonst False.
    """
    # Entferne Leerzeichen und Bindestriche
    card_number = re.sub(r'[\s\-]', '', card_number)
    
    # Überprüfe, ob die Kreditkartennummer nur Ziffern enthält
    if not card_number.isdigit():
        return False
    
    # Überprüfe die Länge der Kreditkartennummer
    if not 13 <= len(card_number) <= 19:
        return False
    
    # Implementiere den Luhn-Algorithmus
    digits = [int(d) for d in card_number]
    checksum = 0
    
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        
        checksum += digit
    
    return checksum % 10 == 0


@handle_exception
def is_valid_ssn(ssn: str) -> bool:
    """
    Überprüft, ob eine Sozialversicherungsnummer (SSN) gültig ist.
    
    Args:
        ssn: Die zu überprüfende SSN.
    
    Returns:
        True, wenn die SSN gültig ist, sonst False.
    """
    # Entferne Bindestriche
    ssn = ssn.replace('-', '')
    
    # Überprüfe, ob die SSN nur Ziffern enthält
    if not ssn.isdigit():
        return False
    
    # Überprüfe die Länge der SSN
    if len(ssn) != 9:
        return False
    
    # Überprüfe, ob die SSN nicht aus nur einer Ziffer besteht
    if len(set(ssn)) == 1:
        return False
    
    # Überprüfe, ob die SSN nicht mit 000, 666 oder 900-999 beginnt
    if ssn.startswith(('000', '666')) or 900 <= int(ssn[:3]) <= 999:
        return False
    
    # Überprüfe, ob der mittlere Teil nicht 00 ist
    if ssn[3:5] == '00':
        return False
    
    # Überprüfe, ob der letzte Teil nicht 0000 ist
    if ssn[5:] == '0000':
        return False
    
    return True


@handle_exception
def mask_sensitive_data(data: str, data_type: str) -> str:
    """
    Maskiert sensible Daten.
    
    Args:
        data: Die zu maskierenden Daten.
        data_type: Der Typ der Daten.
    
    Returns:
        Die maskierten Daten.
    """
    if data_type == "credit_card":
        # Entferne Leerzeichen und Bindestriche
        data = re.sub(r'[\s\-]', '', data)
        
        # Maskiere alle Ziffern außer den letzten vier
        return '*' * (len(data) - 4) + data[-4:]
    elif data_type == "ssn":
        # Entferne Bindestriche
        data = data.replace('-', '')
        
        # Maskiere alle Ziffern außer den letzten vier
        return '*' * (len(data) - 4) + data[-4:]
    elif data_type == "email":
        # Finde den Benutzernamen und die Domain
        match = re.match(r'^([^@]+)@(.+)$', data)
        
        if match:
            username, domain = match.groups()
            
            # Maskiere den Benutzernamen
            if len(username) <= 2:
                masked_username = username[0] + '*' * (len(username) - 1)
            else:
                masked_username = username[0] + '*' * (len(username) - 2) + username[-1]
            
            return f"{masked_username}@{domain}"
        else:
            return data
    elif data_type == "phone":
        # Entferne Leerzeichen, Bindestriche und Klammern
        data = re.sub(r'[\s\-()]', '', data)
        
        # Maskiere alle Ziffern außer den letzten vier
        return '*' * (len(data) - 4) + data[-4:]
    else:
        return data


@handle_exception
def detect_sensitive_data(text: str) -> Dict[str, List[str]]:
    """
    Erkennt sensible Daten in einem Text.
    
    Args:
        text: Der zu durchsuchende Text.
    
    Returns:
        Ein Dictionary mit den erkannten sensiblen Daten.
    """
    sensitive_data = {
        "credit_cards": [],
        "ssns": [],
        "emails": [],
        "phone_numbers": []
    }
    
    # Suche nach Kreditkartennummern
    credit_card_pattern = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
    
    for match in credit_card_pattern.finditer(text):
        card_number = match.group()
        card_number = re.sub(r'[\s\-]', '', card_number)
        
        if is_valid_credit_card(card_number):
            sensitive_data["credit_cards"].append(card_number)
    
    # Suche nach SSNs
    ssn_pattern = re.compile(r'\b\d{3}[ -]?\d{2}[ -]?\d{4}\b')
    
    for match in ssn_pattern.finditer(text):
        ssn = match.group()
        ssn = ssn.replace(' ', '').replace('-', '')
        
        if is_valid_ssn(ssn):
            sensitive_data["ssns"].append(ssn)
    
    # Suche nach E-Mail-Adressen
    email_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
    
    for match in email_pattern.finditer(text):
        email = match.group()
        
        if is_valid_email(email):
            sensitive_data["emails"].append(email)
    
    # Suche nach Telefonnummern
    phone_pattern = re.compile(r'\b(?:\+\d{1,3}[ -]?)?(?:\(\d{1,4}\)|\d{1,4})[ -]?\d{1,4}[ -]?\d{1,4}[ -]?\d{1,4}\b')
    
    for match in phone_pattern.finditer(text):
        phone = match.group()
        
        if is_valid_phone_number(phone):
            sensitive_data["phone_numbers"].append(phone)
    
    return sensitive_data


@handle_exception
def mask_sensitive_data_in_text(text: str) -> str:
    """
    Maskiert sensible Daten in einem Text.
    
    Args:
        text: Der zu maskierende Text.
    
    Returns:
        Der maskierte Text.
    """
    # Erkenne sensible Daten
    sensitive_data = detect_sensitive_data(text)
    
    # Maskiere Kreditkartennummern
    for card_number in sensitive_data["credit_cards"]:
        masked_card = mask_sensitive_data(card_number, "credit_card")
        text = text.replace(card_number, masked_card)
    
    # Maskiere SSNs
    for ssn in sensitive_data["ssns"]:
        masked_ssn = mask_sensitive_data(ssn, "ssn")
        text = text.replace(ssn, masked_ssn)
    
    # Maskiere E-Mail-Adressen
    for email in sensitive_data["emails"]:
        masked_email = mask_sensitive_data(email, "email")
        text = text.replace(email, masked_email)
    
    # Maskiere Telefonnummern
    for phone in sensitive_data["phone_numbers"]:
        masked_phone = mask_sensitive_data(phone, "phone")
        text = text.replace(phone, masked_phone)
    
    return text
