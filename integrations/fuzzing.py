#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Fuzzing Integration
=================================================

Diese Datei implementiert die Integration für Fuzzing-Tools.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import json
import os
import re
import subprocess
import logging
from typing import Dict, List, Any, Optional, Union, Tuple

from .base import ToolIntegration

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.Integrations.Fuzzing")


class FuzzingIntegration(ToolIntegration):
    """Basisklasse für Fuzzing-Tool Integrationen."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialisiert die Fuzzing-Integration.
        
        Args:
            config: Die Konfiguration für die Integration.
        """
        super().__init__(config or {})
        self.results = {
            "payloads": [],
            "successful_payloads": [],
            "failed_payloads": []
        }
    
    def _get_tool_name(self) -> str:
        """
        Gibt den Namen des Tools zurück.
        
        Returns:
            Der Name des Tools.
        """
        return "fuzzing"
    
    def _get_installation_command(self) -> List[str]:
        """
        Gibt den Befehl zur Installation des Tools zurück.
        
        Returns:
            Eine Liste mit dem Installationsbefehl und seinen Argumenten.
        """
        return ["echo", "Basisklasse kann nicht direkt installiert werden"]
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Führt das Fuzzing-Tool mit den angegebenen Optionen aus.
        
        Args:
            target: Die Ziel-URL oder Domain.
            options: Zusätzliche Optionen für das Fuzzing-Tool.
            
        Returns:
            Ein Dictionary mit den Ergebnissen der Ausführung.
        """
        raise NotImplementedError("Diese Methode muss von einer Unterklasse implementiert werden")
    
    def get_results(self) -> Dict[str, List[str]]:
        """
        Gibt die Ergebnisse des Fuzzing-Tools zurück.
        
        Returns:
            Ein Dictionary mit den Ergebnissen.
        """
        return self.results


class WfuzzIntegration(FuzzingIntegration):
    """Integration für das Wfuzz-Tool."""

    def _get_tool_name(self) -> str:
        """
        Gibt den Namen des Tools zurück.
        
        Returns:
            Der Name des Tools.
        """
        return "wfuzz"
    
    def _get_installation_command(self) -> List[str]:
        """
        Gibt den Befehl zur Installation des Tools zurück.
        
        Returns:
            Eine Liste mit dem Installationsbefehl und seinen Argumenten.
        """
        return ["pip", "install", "wfuzz"]
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Führt Wfuzz mit den angegebenen Optionen aus.
        
        Args:
            target: Die Ziel-URL oder Domain.
            options: Zusätzliche Optionen für Wfuzz.
            
        Returns:
            Ein Dictionary mit den Ergebnissen der Ausführung.
        """
        if not self.executable_path:
            return {"error": f"{self._get_tool_name()} nicht gefunden oder installiert"}
        
        if options is None:
            options = {}
        
        # Standardoptionen
        wordlist = options.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        concurrent = options.get("concurrent", 10)
        timeout = options.get("timeout", 30)
        output_file = options.get("output_file", "")
        
        # Kommando zusammenstellen
        command = [
            self.executable_path,
            "-c",
            "-z", f"file,{wordlist}",
            "--hc", "404",
            "-t", str(concurrent),
            "-f", "json",
            target
        ]
        
        # Optionale Parameter
        if "user_agent" in options:
            command.extend(["-H", f"User-Agent: {options['user_agent']}"])
        
        if "cookie" in options:
            command.extend(["-b", options["cookie"]])
        
        # Ausführen
        returncode, stdout, stderr = self.execute_command(command, timeout=timeout+30)
        
        # Ergebnisse verarbeiten
        results = {
            "tool": self._get_tool_name(),
            "target": target,
            "command": " ".join(command),
            "returncode": returncode,
            "payloads": [],
            "successful_payloads": [],
            "failed_payloads": [],
            "error": stderr if returncode != 0 else ""
        }
        
        if returncode == 0:
            # Verarbeite die Ausgabe
            try:
                data = json.loads(stdout)
                for item in data.get("results", []):
                    payload = item.get("payload", "")
                    status = item.get("code", 0)
                    
                    results["payloads"].append(payload)
                    
                    if 200 <= status < 300:
                        results["successful_payloads"].append(payload)
                    else:
                        results["failed_payloads"].append(payload)
            except json.JSONDecodeError:
                # Fallback für nicht-JSON-Ausgabe
                for line in stdout.splitlines():
                    if "200" in line:
                        payload = line.split("|")[1].strip() if "|" in line else line.strip()
                        results["payloads"].append(payload)
                        results["successful_payloads"].append(payload)
        
        # Aktualisiere die Ergebnisse der Klasse
        self.results = results
        
        # Speichere Ausgabe in Datei, falls gewünscht
        if output_file and stdout:
            try:
                with open(output_file, "w") as f:
                    f.write(stdout)
            except Exception as e:
                logger.error(f"Fehler beim Schreiben der Ausgabe in {output_file}: {e}")
        
        return results


class FFuFIntegration(FuzzingIntegration):
    """Integration für das FFuf-Tool."""

    def _get_tool_name(self) -> str:
        """
        Gibt den Namen des Tools zurück.
        
        Returns:
            Der Name des Tools.
        """
        return "ffuf"
    
    def _get_installation_command(self) -> List[str]:
        """
        Gibt den Befehl zur Installation des Tools zurück.
        
        Returns:
            Eine Liste mit dem Installationsbefehl und seinen Argumenten.
        """
        return ["go", "install", "github.com/ffuf/ffuf@latest"]
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Führt FFuf mit den angegebenen Optionen aus.
        
        Args:
            target: Die Ziel-URL oder Domain.
            options: Zusätzliche Optionen für FFuf.
            
        Returns:
            Ein Dictionary mit den Ergebnissen der Ausführung.
        """
        if not self.executable_path:
            return {"error": f"{self._get_tool_name()} nicht gefunden oder installiert"}
        
        if options is None:
            options = {}
        
        # Standardoptionen
        wordlist = options.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads = options.get("threads", 10)
        timeout = options.get("timeout", 30)
        output_file = options.get("output_file", "")
        
        # Kommando zusammenstellen
        command = [
            self.executable_path,
            "-w", wordlist,
            "-u", target,
            "-mc", "200,201,202,203,204,205,206,207,208,226",
            "-c",
            "-t", str(threads),
            "-o", output_file if output_file else "/dev/null",
            "-of", "json"
        ]
        
        # Optionale Parameter
        if "user_agent" in options:
            command.extend(["-H", f"User-Agent: {options['user_agent']}"])
        
        if "cookie" in options:
            command.extend(["-b", options["cookie"]])
        
        # Ausführen
        returncode, stdout, stderr = self.execute_command(command, timeout=timeout+30)
        
        # Ergebnisse verarbeiten
        results = {
            "tool": self._get_tool_name(),
            "target": target,
            "command": " ".join(command),
            "returncode": returncode,
            "payloads": [],
            "successful_payloads": [],
            "failed_payloads": [],
            "error": stderr if returncode != 0 else ""
        }
        
        if returncode == 0:
            # Verarbeite die Ausgabe
            try:
                if output_file and os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        data = json.load(f)
                        for result in data.get("results", []):
                            payload = result.get("input", {}).get("FUZZ", "")
                            status = result.get("status", 0)
                            
                            results["payloads"].append(payload)
                            
                            if 200 <= status < 300:
                                results["successful_payloads"].append(payload)
                            else:
                                results["failed_payloads"].append(payload)
            except (json.JSONDecodeError, FileNotFoundError) as e:
                logger.error(f"Fehler beim Verarbeiten der FFuf-Ausgabe: {e}")
        
        # Aktualisiere die Ergebnisse der Klasse
        self.results = results
        
        return results


class FuzzingToolFactory:
    """Factory-Klasse für Fuzzing-Tool Integrationen."""
    
    @staticmethod
    def create(fuzzer_type: str, config: Dict[str, Any]) -> FuzzingIntegration:
        """
        Erstellt eine Fuzzing-Tool Integration basierend auf dem angegebenen Typ.
        
        Args:
            fuzzer_type: Der Typ des Fuzzing-Tools ("wfuzz" oder "ffuf").
            config: Die Konfiguration für das Fuzzing-Tool.
            
        Returns:
            Eine Fuzzing-Tool Integration.
            
        Raises:
            ValueError: Wenn der angegebene Typ nicht unterstützt wird.
        """
        if fuzzer_type.lower() == "wfuzz":
            return WfuzzIntegration(config)
        elif fuzzer_type.lower() == "ffuf":
            return FFuFIntegration(config)
        else:
            raise ValueError(f"Nicht unterstützter Fuzzing-Tool Typ: {fuzzer_type}")
