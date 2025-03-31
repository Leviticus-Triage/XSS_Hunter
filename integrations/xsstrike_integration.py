#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - XSStrike Integration
==============================================

Dieses Modul implementiert die Integration mit dem XSStrike-Tool.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import json
import subprocess
import logging
import re
import time
from abc import ABC, abstractmethod

# Füge das Hauptverzeichnis zum Pfad hinzu, um Module zu importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from integrations.vulnerability_scanner import VulnerabilityScanner
    import utils
except ImportError:
    logger = logging.getLogger("XSSHunterPro.XSStrikeIntegration")
    logger.error("Erforderliche Module konnten nicht importiert werden.")
    
    # Einfache Implementierung der VulnerabilityScanner-Klasse
    class VulnerabilityScanner(ABC):
        def __init__(self, config=None):
            self.config = config or {}
            self.results = []
            
        @abstractmethod
        def scan(self, target, options=None):
            pass
            
        @abstractmethod
        def parse_results(self, raw_results):
            pass
            
        def save_results(self, output_file):
            return False
            
        def get_results(self):
            return self.results
    
    # Einfache Implementierung der Utils-Klasse
    class SimpleUtils:
        @staticmethod
        def create_directory(directory_path):
            if not directory_path:
                return False
            try:
                os.makedirs(directory_path, exist_ok=True)
                return True
            except Exception as e:
                print(f"Fehler beim Erstellen des Verzeichnisses {directory_path}: {e}")
                return False
                
        @staticmethod
        def load_json_file(file_path):
            try:
                if not os.path.exists(file_path):
                    print(f"Datei nicht gefunden: {file_path}")
                    return None
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Fehler beim Laden der JSON-Datei {file_path}: {e}")
                return None
                
        @staticmethod
        def save_json_file(file_path, data):
            try:
                directory = os.path.dirname(file_path)
                if directory and not os.path.exists(directory):
                    os.makedirs(directory, exist_ok=True)
                    
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                return True
            except Exception as e:
                print(f"Fehler beim Speichern der JSON-Datei {file_path}: {e}")
                return False
    
    utils = SimpleUtils()

# Konfiguriere Logging
logger = logging.getLogger("XSSHunterPro.XSStrikeIntegration")

class XSStrikeIntegration(VulnerabilityScanner):
    """
    Integration für XSStrike.
    """
    
    def __init__(self, config=None):
        """
        Initialisiert die XSStrike-Integration.
        
        Args:
            config: Die Konfiguration für XSStrike.
        """
        super().__init__(config)
        self.xsstrike_path = self.config.get("xsstrike_path", "xsstrike")
        self.output_dir = self.config.get("output_dir", "./output/xsstrike")
        
        # Erstelle das Ausgabeverzeichnis, falls es nicht existiert
        utils.create_directory(self.output_dir)
        
    def scan(self, target, options=None):
        """
        Führt einen XSStrike-Scan durch.
        
        Args:
            target: Das Ziel des Scans.
            options: Optionen für den Scan.
            
        Returns:
            Die Ergebnisse des Scans.
        """
        options = options or {}
        
        # Erstelle temporäre Datei für die Ausgabe
        timestamp = int(time.time())
        output_file = options.get("output_file", os.path.join(self.output_dir, f"xsstrike_results_{timestamp}.json"))
        
        # Erstelle Kommandozeile
        cmd = [self.xsstrike_path, "-u", target, "--json", "-o", output_file]
        
        # Füge zusätzliche Optionen hinzu
        if options.get("params"):
            cmd.extend(["--params", options["params"]])
            
        if options.get("data"):
            cmd.extend(["--data", options["data"]])
            
        if options.get("headers"):
            cmd.extend(["--headers", options["headers"]])
            
        if options.get("cookies"):
            cmd.extend(["--cookie", options["cookies"]])
            
        if options.get("proxy"):
            cmd.extend(["--proxy", options["proxy"]])
            
        if options.get("timeout"):
            cmd.extend(["--timeout", str(options["timeout"])])
            
        if options.get("level"):
            cmd.extend(["--level", str(options["level"])])
            
        # Führe XSStrike aus
        try:
            logger.info(f"Führe XSStrike-Scan aus: {' '.join(cmd)}")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"XSStrike-Scan fehlgeschlagen: {stderr.decode('utf-8')}")
                return []
                
            # Lade Ergebnisse aus der Ausgabedatei
            if os.path.exists(output_file):
                raw_results = utils.load_json_file(output_file)
                self.results = self.parse_results(raw_results)
                return self.results
            else:
                logger.error(f"XSStrike-Ausgabedatei nicht gefunden: {output_file}")
                return []
                
        except Exception as e:
            logger.error(f"Fehler beim Ausführen des XSStrike-Scans: {e}")
            return []
            
    def parse_results(self, raw_results):
        """
        Parst die Ergebnisse des XSStrike-Scans.
        
        Args:
            raw_results: Die Rohergebnisse des Scans.
            
        Returns:
            Die geparsten Ergebnisse.
        """
        if not raw_results:
            return []
            
        parsed_results = []
        
        # XSStrike-Ergebnisse können unterschiedliche Formate haben
        # Hier wird ein allgemeines Format angenommen
        if isinstance(raw_results, dict):
            # Einzelnes Ergebnis
            vulnerabilities = raw_results.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                parsed_result = {
                    "type": "xsstrike",
                    "name": "XSS Vulnerability",
                    "severity": "HIGH",
                    "url": raw_results.get("url", ""),
                    "parameter": vuln.get("parameter", ""),
                    "payload": vuln.get("payload", ""),
                    "context": vuln.get("context", ""),
                    "description": "Cross-Site Scripting (XSS) Schwachstelle gefunden",
                    "raw": vuln
                }
                
                parsed_results.append(parsed_result)
        elif isinstance(raw_results, list):
            # Liste von Ergebnissen
            for result in raw_results:
                if isinstance(result, dict):
                    parsed_result = {
                        "type": "xsstrike",
                        "name": "XSS Vulnerability",
                        "severity": "HIGH",
                        "url": result.get("url", ""),
                        "parameter": result.get("parameter", ""),
                        "payload": result.get("payload", ""),
                        "context": result.get("context", ""),
                        "description": "Cross-Site Scripting (XSS) Schwachstelle gefunden",
                        "raw": result
                    }
                    
                    parsed_results.append(parsed_result)
                    
        return parsed_results
        
    def get_version(self):
        """
        Gibt die Version von XSStrike zurück.
        
        Returns:
            Die Version von XSStrike oder None, wenn die Version nicht ermittelt werden kann.
        """
        try:
            cmd = [self.xsstrike_path, "--version"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Fehler beim Ermitteln der XSStrike-Version: {stderr.decode('utf-8')}")
                return None
                
            # Versuche, die Version aus der Ausgabe zu extrahieren
            output = stdout.decode("utf-8")
            version_match = re.search(r"XSStrike\s+(\d+\.\d+\.\d+)", output)
            if version_match:
                return version_match.group(1)
                
            return None
            
        except Exception as e:
            logger.error(f"Fehler beim Ermitteln der XSStrike-Version: {e}")
            return None
            
    def is_available(self):
        """
        Überprüft, ob XSStrike verfügbar ist.
        
        Returns:
            True, wenn XSStrike verfügbar ist, sonst False.
        """
        try:
            cmd = [self.xsstrike_path, "--help"]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.communicate()
            
            return process.returncode == 0
            
        except Exception:
            return False
