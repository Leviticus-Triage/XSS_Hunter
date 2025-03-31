#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Stored XSS Detector
=======================================

Dieses Modul ist verantwortlich für:
1. Erkennung von persistenten (Stored) XSS-Schwachstellen
2. Verfolgung von Payloads über mehrere Seiten hinweg
3. Identifizierung von Eingabe- und Ausgabepunkten für Stored XSS

Autor: Anonymous
Lizenz: MIT
Version: 0.3.2
"""

import logging
import re
import json
import os
import random
import string
import time
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.StoredXSSDetector")

class StoredXSSDetector:
    """Erkennt persistente (Stored) XSS-Schwachstellen in Webanwendungen."""

    def __init__(self, config: Dict[str, Any] = None, browser=None, callback_server=None):
        """
        Initialisiert den Stored-XSS-Detektor.

        Args:
            config: Ein Dictionary mit Konfigurationsoptionen.
            browser: Eine Instanz des Browsers für die Seitennavigation.
            callback_server: Eine Instanz des Callback-Servers für die Erkennung.
        """
        self.config = config or {}
        self.browser = browser
        self.callback_server = callback_server
        self.payloads = {}  # Speichert aktive Payloads für die Nachverfolgung
        self.input_points = []  # Speichert potenzielle Eingabepunkte
        self.output_points = []  # Speichert potenzielle Ausgabepunkte
        
        logger.info("Stored-XSS-Detektor initialisiert")

    def detect_stored_xss(self, input_url: str, input_param: str, output_urls: List[str] = None, payload: str = None) -> Dict[str, Any]:
        """
        Erkennt Stored-XSS-Schwachstellen zwischen Eingabe- und Ausgabepunkten.

        Args:
            input_url: Die URL des Eingabepunkts (z.B. ein Formular).
            input_param: Der Parameter, in den der Payload eingefügt wird.
            output_urls: Liste von URLs, die auf den Payload überprüft werden sollen.
            payload: Der zu verwendende Payload (optional).

        Returns:
            Ein Dictionary mit den Ergebnissen der Erkennung.
        """
        logger.info(f"Starte Stored-XSS-Erkennung für Eingabe-URL: {input_url}, Parameter: {input_param}")
        
        # Initialisiere das Ergebnis
        result = {
            "input_url": input_url,
            "input_param": input_param,
            "output_urls": output_urls or [],
            "payload": payload,
            "success": False,
            "evidence": None,
            "output_url": None,
            "error": None
        }
        
        try:
            # Überprüfe, ob der Browser verfügbar ist
            if not self.browser:
                logger.error("Browser nicht verfügbar für Stored-XSS-Erkennung")
                result["error"] = "Browser nicht verfügbar"
                return result
            
            # Generiere einen eindeutigen Payload, falls keiner angegeben wurde
            if not payload:
                payload_id = self._generate_unique_id()
                payload = f"<script>alert('STORED-XSS-{payload_id}')</script>"
            
            # Speichere den Payload für die spätere Nachverfolgung
            payload_hash = hashlib.md5(payload.encode()).hexdigest()
            self.payloads[payload_hash] = {
                "payload": payload,
                "input_url": input_url,
                "input_param": input_param,
                "timestamp": time.time()
            }
            
            # Sende den Payload an den Eingabepunkt
            logger.info(f"Sende Payload an Eingabepunkt: {input_url}, Parameter: {input_param}")
            submission_result = self._submit_payload(input_url, input_param, payload)
            
            if not submission_result["success"]:
                logger.error(f"Fehler beim Senden des Payloads: {submission_result.get('error')}")
                result["error"] = submission_result.get("error")
                return result
            
            # Wenn keine Ausgabe-URLs angegeben wurden, versuche sie automatisch zu finden
            if not output_urls:
                logger.info("Keine Ausgabe-URLs angegeben, versuche sie automatisch zu finden")
                output_urls = self._discover_potential_output_points(input_url)
                result["output_urls"] = output_urls
            
            # Überprüfe die Ausgabepunkte auf den Payload
            for output_url in output_urls:
                logger.info(f"Überprüfe Ausgabepunkt auf Payload: {output_url}")
                check_result = self._check_for_payload(output_url, payload)
                
                if check_result["success"]:
                    # Payload gefunden, Stored-XSS bestätigt
                    result["success"] = True
                    result["evidence"] = check_result["evidence"]
                    result["output_url"] = output_url
                    
                    logger.info(f"Stored-XSS-Schwachstelle gefunden: {input_url} -> {output_url}")
                    return result
            
            # Kein Payload in den Ausgabepunkten gefunden
            logger.info("Kein Payload in den Ausgabepunkten gefunden")
            
        except Exception as e:
            logger.error(f"Fehler bei der Stored-XSS-Erkennung: {e}")
            result["error"] = str(e)
        
        return result

    def _submit_payload(self, url: str, param: str, payload: str) -> Dict[str, Any]:
        """
        Sendet einen Payload an einen Eingabepunkt.

        Args:
            url: Die URL des Eingabepunkts.
            param: Der Parameter, in den der Payload eingefügt wird.
            payload: Der zu sendende Payload.

        Returns:
            Ein Dictionary mit dem Ergebnis der Übermittlung.
        """
        result = {
            "success": False,
            "error": None
        }
        
        try:
            # Navigiere zur URL
            response = self.browser.get(url)
            
            if response.get("status_code", 0) == 0:
                result["error"] = response.get("error")
                return result
            
            # Identifiziere Formulare auf der Seite
            forms = self._extract_forms(response.get("content", ""))
            
            if not forms:
                result["error"] = "Keine Formulare auf der Seite gefunden"
                return result
            
            # Finde ein passendes Formular mit dem angegebenen Parameter
            form = None
            for f in forms:
                if param in f["fields"]:
                    form = f
                    break
            
            if not form:
                result["error"] = f"Kein Formular mit Parameter '{param}' gefunden"
                return result
            
            # Fülle das Formular aus
            form_data = {}
            for field_name, field_type in form["fields"].items():
                if field_name == param:
                    form_data[field_name] = payload
                else:
                    # Fülle andere Felder mit Standardwerten aus
                    if field_type == "text":
                        form_data[field_name] = "test"
                    elif field_type == "email":
                        form_data[field_name] = "test@example.com"
                    elif field_type == "password":
                        form_data[field_name] = "password123"
                    else:
                        form_data[field_name] = "test"
            
            # Sende das Formular ab
            if form["method"].upper() == "GET":
                response = self.browser.get(form["action"], params=form_data)
            else:  # POST
                response = self.browser.post(form["action"], data=form_data)
            
            if response.get("status_code", 0) == 0:
                result["error"] = response.get("error")
                return result
            
            # Übermittlung erfolgreich
            result["success"] = True
            
        except Exception as e:
            result["error"] = str(e)
        
        return result

    def _check_for_payload(self, url: str, payload: str) -> Dict[str, Any]:
        """
        Überprüft eine URL auf das Vorhandensein eines Payloads.

        Args:
            url: Die zu überprüfende URL.
            payload: Der zu suchende Payload.

        Returns:
            Ein Dictionary mit dem Ergebnis der Überprüfung.
        """
        result = {
            "success": False,
            "evidence": None,
            "error": None
        }
        
        try:
            # Navigiere zur URL
            response = self.browser.get(url)
            
            if response.get("status_code", 0) == 0:
                result["error"] = response.get("error")
                return result
            
            # Suche nach dem Payload im Quellcode
            content = response.get("content", "")
            
            # Erstelle einen vereinfachten Payload für die Suche (ohne Tags)
            payload_content = re.sub(r"<[^>]*>", "", payload)
            
            if payload in content or payload_content in content:
                # Payload gefunden
                result["success"] = True
                result["evidence"] = f"Payload im Quellcode gefunden: {payload}"
                
                # Nimm einen Screenshot, falls verfügbar
                if hasattr(self.browser, "take_screenshot"):
                    screenshot = self.browser.take_screenshot()
                    result["screenshot"] = screenshot
            
        except Exception as e:
            result["error"] = str(e)
        
        return result

    def _discover_potential_output_points(self, input_url: str) -> List[str]:
        """
        Entdeckt potenzielle Ausgabepunkte basierend auf einer Eingabe-URL.

        Args:
            input_url: Die URL des Eingabepunkts.

        Returns:
            Eine Liste potenzieller Ausgabe-URLs.
        """
        output_urls = []
        
        try:
            # Parse die Basis-URL
            parsed_url = urlparse(input_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Navigiere zur Basis-URL
            response = self.browser.get(base_url)
            
            if response.get("status_code", 0) == 0:
                logger.error(f"Fehler beim Zugriff auf die Basis-URL: {response.get('error')}")
                return output_urls
            
            # Extrahiere Links von der Startseite
            links = self._extract_links(response.get("content", ""), base_url)
            
            # Filtere Links, die potenziell Ausgabepunkte sein könnten
            for link in links:
                # Ignoriere die Eingabe-URL selbst
                if link == input_url:
                    continue
                
                # Ignoriere externe Links
                if not link.startswith(base_url):
                    continue
                
                # Füge den Link zu den potenziellen Ausgabepunkten hinzu
                output_urls.append(link)
            
            # Begrenze die Anzahl der zu überprüfenden URLs
            max_urls = self.config.get("max_output_urls", 10)
            output_urls = output_urls[:max_urls]
            
        except Exception as e:
            logger.error(f"Fehler bei der Entdeckung potenzieller Ausgabepunkte: {e}")
        
        return output_urls

    def _extract_forms(self, html_content: str) -> List[Dict[str, Any]]:
        """
        Extrahiert Formulare aus HTML-Inhalt.

        Args:
            html_content: Der HTML-Inhalt.

        Returns:
            Eine Liste von Formularen mit ihren Feldern und Aktionen.
        """
        forms = []
        
        # Einfacher Regex-basierter Form-Extraktor
        form_pattern = r"<form[^>]*action=['\"]([^'\"]*)['\"][^>]*method=['\"]([^'\"]*)['\"][^>]*>(.*?)</form>"
        form_matches = re.findall(form_pattern, html_content, re.MULTILINE | re.DOTALL)
        
        for action, method, form_content in form_matches:
            # Extrahiere Eingabefelder
            input_pattern = r"<input[^>]*name=['\"]([^'\"]*)['\"][^>]*type=['\"]([^'\"]*)['\"][^>]*>"
            input_matches = re.findall(input_pattern, form_content)
            
            # Extrahiere Textbereiche
            textarea_pattern = r"<textarea[^>]*name=['\"]([^'\"]*)['\"][^>]*>"
            textarea_matches = re.findall(textarea_pattern, form_content)
            
            # Kombiniere alle Felder
            fields = {}
            for name, field_type in input_matches:
                fields[name] = field_type
            
            for name in textarea_matches:
                fields[name] = "textarea"
            
            forms.append({
                "action": action,
                "method": method,
                "fields": fields
            })
        
        return forms

    def _extract_links(self, html_content: str, base_url: str) -> List[str]:
        """
        Extrahiert Links aus HTML-Inhalt.

        Args:
            html_content: Der HTML-Inhalt.
            base_url: Die Basis-URL für relative Links.

        Returns:
            Eine Liste von absoluten URLs.
        """
        links = []
        
        # Extrahiere Links
        link_pattern = r"<a[^>]*href=['\"]([^'\"]*)['\"][^>]*>"
        link_matches = re.findall(link_pattern, html_content)
        
        for link in link_matches:
            # Konvertiere relative Links zu absoluten URLs
            absolute_link = urljoin(base_url, link)
            
            # Entferne Fragmente
            absolute_link = absolute_link.split("#")[0]
            
            # Füge den Link zur Liste hinzu, wenn er noch nicht enthalten ist
            if absolute_link not in links:
                links.append(absolute_link)
        
        return links

    def _generate_unique_id(self) -> str:
        """
        Generiert eine eindeutige ID für Payloads.

        Returns:
            Eine eindeutige ID.
        """
        return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

    def clear_payloads(self):
        """Löscht alle gespeicherten Payloads."""
        self.payloads = {}
        logger.info("Alle gespeicherten Payloads gelöscht")

# Wenn dieses Skript direkt ausgeführt wird
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Teste den Stored-XSS-Detektor
    from browser_abstraction import BrowserFactory
    
    # Erstelle einen Browser
    browser = BrowserFactory.create_browser()
    
    # Erstelle einen Stored-XSS-Detektor
    detector = StoredXSSDetector(browser=browser)
    
    # Teste eine URL
    result = detector.detect_stored_xss(
        input_url="https://example.com/comment.php",
        input_param="comment",
        output_urls=["https://example.com/comments.php"]
    )
    
    print(json.dumps(result, indent=4))
