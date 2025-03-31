#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - XSS Validator
========================================

Dieses Modul enthält Funktionen zur Validierung von XSS-Schwachstellen.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import re
import json
import logging
import random
import string
import time
import urllib.parse
import requests
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from bs4 import BeautifulSoup
from colorama import Fore, Style

# Füge das Hauptverzeichnis zum Pfad hinzu, um Module zu importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils import url_encode, url_decode, is_valid_url, normalize_url, get_domain_from_url
    from utils import get_severity_color, get_severity_level, create_directory
except ImportError:
    # Einfache Implementierungen, falls die Module nicht importiert werden können
    def url_encode(text):
        return urllib.parse.quote(text)
        
    def url_decode(text):
        return urllib.parse.unquote(text)
        
    def is_valid_url(url):
        return bool(re.match(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$", url))
        
    def normalize_url(url):
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        return url
        
    def get_domain_from_url(url):
        match = re.match(r"^(?:https?://)?(?:www\.)?([^:/\n?]+)", url)
        if match:
            return match.group(1)
        return ""
        
    def get_severity_color(severity):
        colors = {
            "CRITICAL": Fore.RED + Style.BRIGHT,
            "HIGH": Fore.RED,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.GREEN,
            "INFO": Fore.BLUE
        }
        return colors.get(severity, Fore.WHITE)
        
    def get_severity_level(score):
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 1.0:
            return "LOW"
        else:
            return "INFO"
            
    def create_directory(directory_path):
        os.makedirs(directory_path, exist_ok=True)
        return True

# Konfiguriere Logging
logger = logging.getLogger("XSSHunterPro.XSSValidator")

class XSSValidator:
    """
    Klasse zur Validierung von XSS-Schwachstellen.
    """
    
    def __init__(self, config=None):
        """
        Initialisiert den XSS-Validator.
        
        Args:
            config: Die Konfiguration für den Validator.
        """
        self.config = config or {}
        self.user_agent = self.config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        self.timeout = self.config.get("timeout", 10)
        self.max_retries = self.config.get("max_retries", 3)
        self.delay = self.config.get("delay", 1)
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.screenshot_dir = self.config.get("screenshot_dir", "screenshots")
        self.create_screenshots = self.config.get("create_screenshots", True)
        self.validation_level = self.config.get("validation_level", 2)  # 0=keine, 1=einfach, 2=standard, 3=streng
        
        # Erstelle Screenshot-Verzeichnis, wenn es nicht existiert
        if self.create_screenshots:
            create_directory(self.screenshot_dir)
            
        # Marker für die Validierung
        self.marker_template = "xss{0}"
        
    def generate_marker(self, length=8):
        """
        Generiert einen zufälligen Marker für die XSS-Validierung.
        
        Args:
            length: Die Länge des Markers.
            
        Returns:
            Der generierte Marker.
        """
        chars = string.ascii_letters + string.digits
        random_str = ''.join(random.choice(chars) for _ in range(length))
        return self.marker_template.format(random_str)
        
    def validate_xss(self, url, parameter, payload, method="GET", headers=None, cookies=None, data=None, proxies=None):
        """
        Validiert eine XSS-Schwachstelle.
        
        Args:
            url: Die URL der Webseite.
            parameter: Der Parameter, der für den XSS-Angriff verwendet wird.
            payload: Der XSS-Payload.
            method: Die HTTP-Methode (GET oder POST).
            headers: Zusätzliche HTTP-Header.
            cookies: Cookies für die Anfrage.
            data: Daten für POST-Anfragen.
            proxies: Proxies für die Anfrage.
            
        Returns:
            Ein Dictionary mit den Validierungsergebnissen.
        """
        headers = headers or {}
        cookies = cookies or {}
        data = data or {}
        proxies = proxies or {}
        
        # Füge User-Agent hinzu, wenn nicht vorhanden
        if "User-Agent" not in headers:
            headers["User-Agent"] = self.user_agent
            
        # Generiere einen eindeutigen Marker
        marker = self.generate_marker()
        
        # Ersetze Platzhalter im Payload durch den Marker
        if "MARKER" in payload:
            test_payload = payload.replace("MARKER", marker)
        else:
            # Füge den Marker zum Payload hinzu, wenn kein Platzhalter vorhanden ist
            if "alert(" in payload:
                test_payload = payload.replace("alert(", f"alert('{marker}'+")
            elif "prompt(" in payload:
                test_payload = payload.replace("prompt(", f"prompt('{marker}'+")
            elif "confirm(" in payload:
                test_payload = payload.replace("confirm(", f"confirm('{marker}'+")
            elif "console.log(" in payload:
                test_payload = payload.replace("console.log(", f"console.log('{marker}'+")
            else:
                # Fallback: Verwende den Payload unverändert
                test_payload = payload
                
        # Erstelle die Test-URL oder Daten
        if method.upper() == "GET":
            if "?" in url:
                test_url = f"{url}&{parameter}={url_encode(test_payload)}"
            else:
                test_url = f"{url}?{parameter}={url_encode(test_payload)}"
            test_data = None
        else:  # POST
            test_url = url
            test_data = data.copy()
            test_data[parameter] = test_payload
            
        # Führe die Anfrage durch
        try:
            response = self._make_request(test_url, method, headers, cookies, test_data, proxies)
            if not response:
                return {
                    "valid": False,
                    "reason": "Keine Antwort vom Server erhalten",
                    "confidence": 0.0,
                    "severity": "INFO",
                    "details": {}
                }
                
            # Validiere die Antwort
            validation_result = self._validate_response(response, marker, test_payload, parameter, method)
            
            # Erstelle einen Screenshot, wenn aktiviert
            screenshot_path = None
            if self.create_screenshots and validation_result["valid"]:
                screenshot_path = self._create_screenshot(test_url, marker)
                validation_result["screenshot"] = screenshot_path
                
            return validation_result
            
        except Exception as e:
            logger.error(f"Fehler bei der XSS-Validierung: {e}")
            return {
                "valid": False,
                "reason": f"Fehler bei der Validierung: {str(e)}",
                "confidence": 0.0,
                "severity": "INFO",
                "details": {}
            }
            
    def _make_request(self, url, method, headers, cookies, data, proxies):
        """
        Führt eine HTTP-Anfrage durch.
        
        Args:
            url: Die URL der Webseite.
            method: Die HTTP-Methode (GET oder POST).
            headers: HTTP-Header für die Anfrage.
            cookies: Cookies für die Anfrage.
            data: Daten für POST-Anfragen.
            proxies: Proxies für die Anfrage.
            
        Returns:
            Die HTTP-Antwort oder None, wenn ein Fehler auftritt.
        """
        for attempt in range(self.max_retries):
            try:
                if method.upper() == "GET":
                    response = requests.get(
                        url,
                        headers=headers,
                        cookies=cookies,
                        proxies=proxies,
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=self.verify_ssl
                    )
                else:  # POST
                    response = requests.post(
                        url,
                        headers=headers,
                        cookies=cookies,
                        data=data,
                        proxies=proxies,
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=self.verify_ssl
                    )
                return response
            except requests.exceptions.RequestException as e:
                logger.warning(f"Fehler bei der Anfrage (Versuch {attempt+1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.delay)
                    
        return None
        
    def _validate_response(self, response, marker, payload, parameter, method):
        """
        Validiert die Antwort auf eine XSS-Anfrage.
        
        Args:
            response: Die HTTP-Antwort.
            marker: Der Marker für die Validierung.
            payload: Der XSS-Payload.
            parameter: Der Parameter, der für den XSS-Angriff verwendet wird.
            method: Die HTTP-Methode (GET oder POST).
            
        Returns:
            Ein Dictionary mit den Validierungsergebnissen.
        """
        if not response:
            return {
                "valid": False,
                "reason": "Keine Antwort vom Server erhalten",
                "confidence": 0.0,
                "severity": "INFO",
                "details": {}
            }
            
        # Überprüfe, ob der Marker in der Antwort enthalten ist
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Initialisiere das Ergebnis
        result = {
            "valid": False,
            "reason": "",
            "confidence": 0.0,
            "severity": "INFO",
            "details": {
                "url": response.url,
                "status_code": response.status_code,
                "parameter": parameter,
                "payload": payload,
                "method": method,
                "content_type": response.headers.get("Content-Type", ""),
                "response_size": len(html_content),
                "marker": marker,
                "marker_found": False,
                "context": "",
                "validation_level": self.validation_level
            }
        }
        
        # Überprüfe, ob der Marker in der Antwort enthalten ist
        if marker in html_content:
            result["details"]["marker_found"] = True
            
            # Bestimme den Kontext des Markers
            context = self._determine_context(html_content, marker)
            result["details"]["context"] = context
            
            # Validiere basierend auf dem Kontext und dem Validierungslevel
            if self.validation_level == 0:
                # Keine Validierung, akzeptiere alle Funde
                result["valid"] = True
                result["reason"] = "XSS-Schwachstelle gefunden (keine Validierung)"
                result["confidence"] = 0.5
                result["severity"] = "MEDIUM"
            elif self.validation_level == 1:
                # Einfache Validierung: Marker muss in der Antwort enthalten sein
                result["valid"] = True
                result["reason"] = "XSS-Schwachstelle gefunden (einfache Validierung)"
                result["confidence"] = 0.7
                result["severity"] = "MEDIUM"
            elif self.validation_level == 2:
                # Standard-Validierung: Marker muss in der Antwort enthalten sein und der Kontext muss bestimmt werden können
                if context:
                    result["valid"] = True
                    result["reason"] = f"XSS-Schwachstelle gefunden im Kontext: {context}"
                    result["confidence"] = 0.85
                    result["severity"] = "HIGH"
                else:
                    result["valid"] = False
                    result["reason"] = "Marker gefunden, aber Kontext konnte nicht bestimmt werden"
                    result["confidence"] = 0.3
                    result["severity"] = "LOW"
            elif self.validation_level == 3:
                # Strenge Validierung: Marker muss in der Antwort enthalten sein, der Kontext muss bestimmt werden können und der Payload muss ausführbar sein
                if context and self._is_executable(html_content, marker, context):
                    result["valid"] = True
                    result["reason"] = f"XSS-Schwachstelle gefunden im Kontext: {context} (ausführbar)"
                    result["confidence"] = 0.95
                    result["severity"] = "CRITICAL"
                else:
                    result["valid"] = False
                    result["reason"] = "Marker gefunden, aber Payload ist nicht ausführbar"
                    result["confidence"] = 0.4
                    result["severity"] = "LOW"
        else:
            # Marker nicht gefunden
            result["valid"] = False
            result["reason"] = "Marker nicht in der Antwort gefunden"
            result["confidence"] = 0.0
            result["severity"] = "INFO"
            
        # Setze die Schweregrad-Farbe
        result["details"]["severity_color"] = get_severity_color(result["severity"])
        
        return result
        
    def _determine_context(self, html_content, marker):
        """
        Bestimmt den Kontext eines Markers in HTML-Inhalt.
        
        Args:
            html_content: Der HTML-Inhalt.
            marker: Der Marker.
            
        Returns:
            Der Kontext des Markers oder None, wenn der Kontext nicht bestimmt werden kann.
        """
        # Suche nach dem Marker im HTML-Inhalt
        marker_index = html_content.find(marker)
        if marker_index == -1:
            return None
            
        # Extrahiere einen Teil des HTML-Inhalts um den Marker herum
        start_index = max(0, marker_index - 100)
        end_index = min(len(html_content), marker_index + 100 + len(marker))
        context_html = html_content[start_index:end_index]
        
        # Überprüfe, ob der Marker in einem Script-Tag ist
        script_pattern = r"<script[^>]*>(.*?)</script>"
        script_matches = re.finditer(script_pattern, context_html, re.DOTALL)
        for match in script_matches:
            if marker in match.group(1):
                return "javascript"
                
        # Überprüfe, ob der Marker in einem Event-Handler ist
        event_pattern = r"on\w+\s*=\s*['\"]([^'\"]*?)" + re.escape(marker) + r"([^'\"]*?)['\"]"
        event_match = re.search(event_pattern, context_html)
        if event_match:
            return "event_handler"
            
        # Überprüfe, ob der Marker in einem Attribut ist
        attr_pattern = r"<[^>]+\s+\w+\s*=\s*['\"]([^'\"]*?)" + re.escape(marker) + r"([^'\"]*?)['\"]"
        attr_match = re.search(attr_pattern, context_html)
        if attr_match:
            return "attribute"
            
        # Überprüfe, ob der Marker in einem HTML-Tag ist
        tag_pattern = r"<([^>]*?)" + re.escape(marker) + r"([^>]*?)>"
        tag_match = re.search(tag_pattern, context_html)
        if tag_match:
            return "tag"
            
        # Überprüfe, ob der Marker im HTML-Text ist
        text_pattern = r">([^<]*?)" + re.escape(marker) + r"([^<]*?)<"
        text_match = re.search(text_pattern, context_html)
        if text_match:
            return "text"
            
        # Überprüfe, ob der Marker in einem Kommentar ist
        comment_pattern = r"<!--(.*?)" + re.escape(marker) + r"(.*?)-->"
        comment_match = re.search(comment_pattern, context_html)
        if comment_match:
            return "comment"
            
        # Überprüfe, ob der Marker in einem Style-Tag ist
        style_pattern = r"<style[^>]*>(.*?)</style>"
        style_matches = re.finditer(style_pattern, context_html, re.DOTALL)
        for match in style_matches:
            if marker in match.group(1):
                return "css"
                
        # Wenn kein spezifischer Kontext gefunden wurde, aber der Marker im HTML ist
        if marker in context_html:
            return "unknown"
            
        return None
        
    def _is_executable(self, html_content, marker, context):
        """
        Überprüft, ob ein Payload in einem bestimmten Kontext ausführbar ist.
        
        Args:
            html_content: Der HTML-Inhalt.
            marker: Der Marker.
            context: Der Kontext des Markers.
            
        Returns:
            True, wenn der Payload ausführbar ist, sonst False.
        """
        if context == "javascript":
            # Überprüfe, ob der Marker in einem ausführbaren JavaScript-Kontext ist
            script_pattern = r"<script[^>]*>(.*?)</script>"
            script_matches = re.finditer(script_pattern, html_content, re.DOTALL)
            for match in script_matches:
                script_content = match.group(1)
                if marker in script_content:
                    # Überprüfe, ob der Marker in einem String ist
                    string_pattern = r"['\"]([^'\"]*?)" + re.escape(marker) + r"([^'\"]*?)['\"]"
                    string_match = re.search(string_pattern, script_content)
                    if string_match:
                        # Marker ist in einem String, nicht direkt ausführbar
                        return False
                    # Marker ist nicht in einem String, potenziell ausführbar
                    return True
            return False
        elif context == "event_handler":
            # Event-Handler sind in der Regel ausführbar
            return True
        elif context == "attribute":
            # Überprüfe, ob der Marker in einem Event-Handler-Attribut ist
            event_pattern = r"<[^>]+\s+on\w+\s*=\s*['\"]([^'\"]*?)" + re.escape(marker) + r"([^'\"]*?)['\"]"
            event_match = re.search(event_pattern, html_content)
            if event_match:
                return True
            # Marker ist in einem normalen Attribut, nicht ausführbar
            return False
        elif context == "tag":
            # Überprüfe, ob der Marker in einem Tag-Namen oder in einem Attributnamen ist
            tag_name_pattern = r"<\s*" + re.escape(marker)
            tag_name_match = re.search(tag_name_pattern, html_content)
            if tag_name_match:
                return True
            attr_name_pattern = r"<[^>]+\s+" + re.escape(marker) + r"\s*="
            attr_name_match = re.search(attr_name_pattern, html_content)
            if attr_name_match:
                return True
            # Marker ist in einem Tag, aber nicht in einer ausführbaren Position
            return False
        elif context == "text":
            # Text ist in der Regel nicht ausführbar
            return False
        elif context == "comment":
            # Kommentare sind nicht ausführbar
            return False
        elif context == "css":
            # CSS ist in der Regel nicht ausführbar (außer in speziellen Fällen)
            return False
        elif context == "unknown":
            # Unbekannter Kontext, vorsichtshalber als nicht ausführbar betrachten
            return False
        else:
            # Unbekannter Kontext, vorsichtshalber als nicht ausführbar betrachten
            return False
            
    def _create_screenshot(self, url, marker):
        """
        Erstellt einen Screenshot einer Webseite.
        
        Args:
            url: Die URL der Webseite.
            marker: Der Marker für den Dateinamen.
            
        Returns:
            Der Pfad zum Screenshot oder None, wenn ein Fehler auftritt.
        """
        try:
            # Erstelle einen eindeutigen Dateinamen
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"xss_{timestamp}_{marker}.png"
            filepath = os.path.join(self.screenshot_dir, filename)
            
            # Hier würde normalerweise der Screenshot erstellt werden
            # Da wir keine Browser-Automatisierung haben, simulieren wir dies
            with open(filepath, 'w') as f:
                f.write(f"Screenshot für {url} mit Marker {marker}")
                
            logger.info(f"Screenshot erstellt: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des Screenshots: {e}")
            return None
            
    def get_xss_description(self, context):
        """
        Gibt eine Beschreibung für einen XSS-Typ basierend auf dem Kontext zurück.
        
        Args:
            context: Der Kontext des XSS.
            
        Returns:
            Eine Beschreibung des XSS-Typs.
        """
        descriptions = {
            "javascript": "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle im JavaScript-Kontext. Der Angreifer kann beliebigen JavaScript-Code in die Seite einschleusen, der im Kontext des Browsers des Opfers ausgeführt wird.",
            "event_handler": "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle in einem Event-Handler. Der Angreifer kann JavaScript-Code in einen Event-Handler einschleusen, der bei bestimmten Benutzeraktionen ausgeführt wird.",
            "attribute": "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle in einem HTML-Attribut. Der Angreifer kann den Wert eines Attributs manipulieren und möglicherweise JavaScript-Code einschleusen.",
            "tag": "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle in einem HTML-Tag. Der Angreifer kann HTML-Tags oder Attribute manipulieren und möglicherweise JavaScript-Code einschleusen.",
            "text": "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle im HTML-Text. Der Angreifer kann HTML-Code in den Text einschleusen, der vom Browser interpretiert wird.",
            "comment": "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle in einem HTML-Kommentar. Der Angreifer kann den Kommentar manipulieren und möglicherweise JavaScript-Code einschleusen.",
            "css": "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle im CSS-Kontext. Der Angreifer kann CSS-Code einschleusen, der in bestimmten Browsern zu einer XSS-Schwachstelle führen kann.",
            "unknown": "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle in einem unbekannten Kontext. Der Angreifer kann möglicherweise JavaScript-Code einschleusen, der im Browser des Opfers ausgeführt wird."
        }
        
        return descriptions.get(context, "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle. Der Angreifer kann möglicherweise JavaScript-Code einschleusen, der im Browser des Opfers ausgeführt wird.")
        
    def get_xss_exploitation(self, context, url, parameter, payload):
        """
        Gibt eine Anleitung zur Ausnutzung eines XSS basierend auf dem Kontext zurück.
        
        Args:
            context: Der Kontext des XSS.
            url: Die URL der Webseite.
            parameter: Der Parameter, der für den XSS-Angriff verwendet wird.
            payload: Der XSS-Payload.
            
        Returns:
            Eine Anleitung zur Ausnutzung des XSS.
        """
        # Erstelle eine Debug-URL
        if "?" in url:
            debug_url = f"{url}&{parameter}={url_encode(payload)}"
        else:
            debug_url = f"{url}?{parameter}={url_encode(payload)}"
            
        exploitations = {
            "javascript": f"Um diese Schwachstelle auszunutzen, kann ein Angreifer einen Link mit bösartigem JavaScript-Code erstellen und das Opfer dazu bringen, diesen Link zu öffnen. Der JavaScript-Code wird dann im Kontext des Browsers des Opfers ausgeführt und kann beispielsweise Cookies stehlen, die Seite manipulieren oder andere schädliche Aktionen durchführen.\n\nBeispiel-URL: {debug_url}",
            "event_handler": f"Um diese Schwachstelle auszunutzen, kann ein Angreifer einen Link mit einem bösartigen Event-Handler erstellen und das Opfer dazu bringen, diesen Link zu öffnen. Wenn das Opfer dann die entsprechende Aktion ausführt (z.B. mit der Maus über ein Element fährt), wird der JavaScript-Code ausgeführt.\n\nBeispiel-URL: {debug_url}",
            "attribute": f"Um diese Schwachstelle auszunutzen, kann ein Angreifer einen Link mit einem bösartigen Attributwert erstellen und das Opfer dazu bringen, diesen Link zu öffnen. Je nach Attribut kann der Angreifer möglicherweise JavaScript-Code einschleusen, der ausgeführt wird.\n\nBeispiel-URL: {debug_url}",
            "tag": f"Um diese Schwachstelle auszunutzen, kann ein Angreifer einen Link mit bösartigen HTML-Tags erstellen und das Opfer dazu bringen, diesen Link zu öffnen. Der Angreifer kann dann beliebigen HTML-Code in die Seite einschleusen, einschließlich Script-Tags oder Event-Handler.\n\nBeispiel-URL: {debug_url}",
            "text": f"Um diese Schwachstelle auszunutzen, kann ein Angreifer einen Link mit bösartigem HTML-Code erstellen und das Opfer dazu bringen, diesen Link zu öffnen. Der HTML-Code wird dann vom Browser interpretiert und kann beispielsweise Script-Tags oder Event-Handler enthalten.\n\nBeispiel-URL: {debug_url}",
            "comment": f"Um diese Schwachstelle auszunutzen, kann ein Angreifer einen Link mit einem bösartigen Kommentar erstellen und das Opfer dazu bringen, diesen Link zu öffnen. In bestimmten Fällen kann der Angreifer den Kommentar so manipulieren, dass er JavaScript-Code enthält, der ausgeführt wird.\n\nBeispiel-URL: {debug_url}",
            "css": f"Um diese Schwachstelle auszunutzen, kann ein Angreifer einen Link mit bösartigem CSS-Code erstellen und das Opfer dazu bringen, diesen Link zu öffnen. In bestimmten Browsern kann CSS-Code zu einer XSS-Schwachstelle führen, insbesondere wenn er in Kombination mit bestimmten HTML-Elementen verwendet wird.\n\nBeispiel-URL: {debug_url}",
            "unknown": f"Um diese Schwachstelle auszunutzen, kann ein Angreifer einen Link mit bösartigem Code erstellen und das Opfer dazu bringen, diesen Link zu öffnen. Je nach Kontext kann der Angreifer möglicherweise JavaScript-Code einschleusen, der im Browser des Opfers ausgeführt wird.\n\nBeispiel-URL: {debug_url}"
        }
        
        return exploitations.get(context, f"Um diese Schwachstelle auszunutzen, kann ein Angreifer einen Link mit bösartigem Code erstellen und das Opfer dazu bringen, diesen Link zu öffnen. Der Code wird dann im Kontext des Browsers des Opfers ausgeführt und kann beispielsweise Cookies stehlen, die Seite manipulieren oder andere schädliche Aktionen durchführen.\n\nBeispiel-URL: {debug_url}")
