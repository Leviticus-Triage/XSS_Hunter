#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Modules - Vulnerability Categorization
================================================================

Dieses Modul implementiert die Kategorisierung von XSS-Schwachstellen.

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
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.VulnCategorization")

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


# Klasse für die Kategorisierung von XSS-Schwachstellen
class VulnerabilityClassifier:
    """
    Klasse für die Kategorisierung von XSS-Schwachstellen.
    """
    
    # XSS-Typen
    XSS_TYPES = {
        "reflected": {
            "name": "Reflected XSS",
            "description": "Reflected Cross-Site Scripting (XSS) tritt auf, wenn ein Angreifer bösartigen Code in eine Anfrage einschleust, die vom Server zurückgegeben und im Browser des Opfers ausgeführt wird.",
            "severity": "medium",
            "cvss_base": 6.1,
            "remediation": "Validiere und bereinige alle Benutzereingaben, bevor sie in die Antwort eingefügt werden. Verwende Content-Security-Policy (CSP) und X-XSS-Protection-Header."
        },
        "stored": {
            "name": "Stored XSS",
            "description": "Stored Cross-Site Scripting (XSS) tritt auf, wenn ein Angreifer bösartigen Code auf dem Server speichert, der später an andere Benutzer gesendet und in deren Browsern ausgeführt wird.",
            "severity": "high",
            "cvss_base": 7.5,
            "remediation": "Validiere und bereinige alle Benutzereingaben, bevor sie gespeichert werden. Verwende Content-Security-Policy (CSP) und X-XSS-Protection-Header."
        },
        "dom": {
            "name": "DOM-based XSS",
            "description": "DOM-based Cross-Site Scripting (XSS) tritt auf, wenn ein Angreifer bösartigen Code in das Document Object Model (DOM) des Browsers einschleust, der dann vom Client-seitigen JavaScript ausgeführt wird.",
            "severity": "medium",
            "cvss_base": 6.1,
            "remediation": "Verwende sichere JavaScript-Methoden wie textContent statt innerHTML. Validiere und bereinige alle Benutzereingaben, bevor sie im DOM verwendet werden."
        },
        "blind": {
            "name": "Blind XSS",
            "description": "Blind Cross-Site Scripting (XSS) tritt auf, wenn ein Angreifer bösartigen Code einschleust, der erst später ausgeführt wird, wenn ein Administrator oder ein anderer Benutzer mit höheren Rechten auf die Daten zugreift.",
            "severity": "high",
            "cvss_base": 7.5,
            "remediation": "Validiere und bereinige alle Benutzereingaben, bevor sie gespeichert werden. Verwende Content-Security-Policy (CSP) und X-XSS-Protection-Header."
        },
        "universal": {
            "name": "Universal XSS",
            "description": "Universal Cross-Site Scripting (XSS) tritt auf, wenn ein Angreifer eine Schwachstelle im Browser oder in einer Browser-Erweiterung ausnutzt, um bösartigen Code in beliebige Websites einzuschleusen.",
            "severity": "critical",
            "cvss_base": 9.0,
            "remediation": "Halte Browser und Browser-Erweiterungen auf dem neuesten Stand. Verwende Content-Security-Policy (CSP) und X-XSS-Protection-Header."
        },
        "self": {
            "name": "Self XSS",
            "description": "Self Cross-Site Scripting (XSS) tritt auf, wenn ein Angreifer ein Opfer dazu verleitet, bösartigen Code in seinen eigenen Browser einzugeben, der dann ausgeführt wird.",
            "severity": "low",
            "cvss_base": 3.5,
            "remediation": "Sensibilisiere Benutzer für Social-Engineering-Angriffe. Validiere und bereinige alle Benutzereingaben, bevor sie in die Antwort eingefügt werden."
        }
    }
    
    # Schweregrade
    SEVERITY_LEVELS = {
        "low": {
            "name": "Niedrig",
            "description": "Niedrige Schwachstellen haben geringe Auswirkungen und sind schwer auszunutzen.",
            "cvss_range": (0.1, 3.9),
            "color": "#4CAF50"  # Grün
        },
        "medium": {
            "name": "Mittel",
            "description": "Mittlere Schwachstellen haben moderate Auswirkungen oder sind relativ leicht auszunutzen.",
            "cvss_range": (4.0, 6.9),
            "color": "#FFC107"  # Gelb
        },
        "high": {
            "name": "Hoch",
            "description": "Hohe Schwachstellen haben erhebliche Auswirkungen und sind relativ leicht auszunutzen.",
            "cvss_range": (7.0, 8.9),
            "color": "#FF9800"  # Orange
        },
        "critical": {
            "name": "Kritisch",
            "description": "Kritische Schwachstellen haben schwerwiegende Auswirkungen und sind leicht auszunutzen.",
            "cvss_range": (9.0, 10.0),
            "color": "#F44336"  # Rot
        }
    }
    
    def __init__(self, config=None):
        """
        Initialisiert die Vulnerability Categorization.
        
        Args:
            config: Die Konfiguration für die Vulnerability Categorization.
        """
        self.config = config or {}
        self.vulnerabilities = []
        
        logger.info("VulnerabilityClassifier initialisiert.")
    
    @handle_exception
    def categorize_vulnerability(self, vulnerability_data):
        """
        Kategorisiert eine Schwachstelle.
        
        Args:
            vulnerability_data: Die Daten der Schwachstelle.
        
        Returns:
            Die kategorisierte Schwachstelle.
        """
        # Überprüfe, ob die Schwachstellendaten gültig sind
        if not vulnerability_data:
            logger.error("Ungültige Schwachstellendaten.")
            return None
        
        # Extrahiere die Schwachstellendaten
        vuln_type = vulnerability_data.get("type", "reflected")
        url = vulnerability_data.get("url", "")
        payload = vulnerability_data.get("payload", "")
        context = vulnerability_data.get("context", "html")
        
        # Überprüfe, ob der Schwachstellentyp gültig ist
        if vuln_type not in self.XSS_TYPES:
            logger.error(f"Ungültiger Schwachstellentyp: {vuln_type}")
            vuln_type = "reflected"
        
        # Überprüfe, ob die URL gültig ist
        if not is_valid_url(url):
            logger.error(f"Ungültige URL: {url}")
            return None
        
        # Erstelle die kategorisierte Schwachstelle
        categorized_vulnerability = {
            "id": f"XSS-{get_timestamp()}",
            "type": vuln_type,
            "url": url,
            "payload": payload,
            "context": context,
            "timestamp": get_timestamp(),
            "formatted_timestamp": format_timestamp(get_timestamp()),
            "name": self.XSS_TYPES[vuln_type]["name"],
            "description": self.XSS_TYPES[vuln_type]["description"],
            "severity": self.XSS_TYPES[vuln_type]["severity"],
            "cvss_base": self.XSS_TYPES[vuln_type]["cvss_base"],
            "remediation": self.XSS_TYPES[vuln_type]["remediation"],
            "severity_details": self.SEVERITY_LEVELS[self.XSS_TYPES[vuln_type]["severity"]]
        }
        
        # Füge die kategorisierte Schwachstelle hinzu
        self.vulnerabilities.append(categorized_vulnerability)
        
        logger.info(f"Schwachstelle kategorisiert: {categorized_vulnerability['id']}")
        
        return categorized_vulnerability
    
    @handle_exception
    def categorize_vulnerabilities(self, vulnerabilities_data):
        """
        Kategorisiert mehrere Schwachstellen.
        
        Args:
            vulnerabilities_data: Die Daten der Schwachstellen.
        
        Returns:
            Die kategorisierten Schwachstellen.
        """
        categorized_vulnerabilities = []
        
        # Überprüfe, ob die Schwachstellendaten gültig sind
        if not vulnerabilities_data:
            logger.error("Ungültige Schwachstellendaten.")
            return categorized_vulnerabilities
        
        # Kategorisiere jede Schwachstelle
        for vulnerability_data in vulnerabilities_data:
            categorized_vulnerability = self.categorize_vulnerability(vulnerability_data)
            
            if categorized_vulnerability:
                categorized_vulnerabilities.append(categorized_vulnerability)
        
        logger.info(f"{len(categorized_vulnerabilities)} Schwachstellen kategorisiert.")
        
        return categorized_vulnerabilities
    
    @handle_exception
    def get_vulnerability_statistics(self):
        """
        Gibt Statistiken über die Schwachstellen zurück.
        
        Returns:
            Die Schwachstellenstatistiken.
        """
        statistics = {
            "total": len(self.vulnerabilities),
            "by_type": {},
            "by_severity": {},
            "by_context": {}
        }
        
        # Zähle die Schwachstellen nach Typ
        for vuln_type in self.XSS_TYPES:
            statistics["by_type"][vuln_type] = len([v for v in self.vulnerabilities if v["type"] == vuln_type])
        
        # Zähle die Schwachstellen nach Schweregrad
        for severity in self.SEVERITY_LEVELS:
            statistics["by_severity"][severity] = len([v for v in self.vulnerabilities if v["severity"] == severity])
        
        # Zähle die Schwachstellen nach Kontext
        contexts = set([v["context"] for v in self.vulnerabilities])
        for context in contexts:
            statistics["by_context"][context] = len([v for v in self.vulnerabilities if v["context"] == context])
        
        logger.info(f"Schwachstellenstatistiken erstellt: {statistics}")
        
        return statistics
    
    @handle_exception
    def get_vulnerability_recommendations(self):
        """
        Gibt Empfehlungen zur Behebung der Schwachstellen zurück.
        
        Returns:
            Die Schwachstellenempfehlungen.
        """
        recommendations = {}
        
        # Erstelle Empfehlungen für jeden Schwachstellentyp
        for vuln_type, count in self.get_vulnerability_statistics()["by_type"].items():
            if count > 0:
                recommendations[vuln_type] = {
                    "name": self.XSS_TYPES[vuln_type]["name"],
                    "count": count,
                    "remediation": self.XSS_TYPES[vuln_type]["remediation"]
                }
        
        logger.info(f"Schwachstellenempfehlungen erstellt: {recommendations}")
        
        return recommendations
    
    @handle_exception
    def save_vulnerabilities(self, file_path):
        """
        Speichert die Schwachstellen in einer Datei.
        
        Args:
            file_path: Der Pfad zur Datei.
        
        Returns:
            True, wenn die Schwachstellen erfolgreich gespeichert wurden, sonst False.
        """
        # Erstelle das Verzeichnis, falls es nicht existiert
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Speichere die Schwachstellen
        result = save_json_file(self.vulnerabilities, file_path)
        
        if result:
            logger.info(f"Schwachstellen gespeichert: {file_path}")
        else:
            logger.error(f"Fehler beim Speichern der Schwachstellen: {file_path}")
        
        return result
    
    @handle_exception
    def load_vulnerabilities(self, file_path):
        """
        Lädt die Schwachstellen aus einer Datei.
        
        Args:
            file_path: Der Pfad zur Datei.
        
        Returns:
            Die geladenen Schwachstellen.
        """
        # Überprüfe, ob die Datei existiert
        if not os.path.exists(file_path):
            logger.error(f"Datei nicht gefunden: {file_path}")
            return []
        
        # Lade die Schwachstellen
        self.vulnerabilities = load_json_file(file_path)
        
        logger.info(f"Schwachstellen geladen: {file_path}")
        
        return self.vulnerabilities


# Alias für Kompatibilität mit älteren Versionen
VulnCategorization = VulnerabilityClassifier


# Beispielverwendung
if __name__ == "__main__":
    # Erstelle eine Vulnerability Categorization
    vuln_categorization = VulnerabilityClassifier()
    
    # Kategorisiere eine Schwachstelle
    vulnerability_data = {
        "type": "reflected",
        "url": "https://example.com/search?q=test",
        "payload": "<script>alert('XSS')</script>",
        "context": "html"
    }
    
    categorized_vulnerability = vuln_categorization.categorize_vulnerability(vulnerability_data)
    
    print(f"Kategorisierte Schwachstelle: {categorized_vulnerability}")
    
    # Erstelle Schwachstellenstatistiken
    statistics = vuln_categorization.get_vulnerability_statistics()
    
    print(f"Schwachstellenstatistiken: {statistics}")
    
    # Erstelle Schwachstellenempfehlungen
    recommendations = vuln_categorization.get_vulnerability_recommendations()
    
    print(f"Schwachstellenempfehlungen: {recommendations}")
