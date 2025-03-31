#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Fuzzing Tools Integration
===================================================

Diese Datei implementiert die Integration für Fuzzing Tools (FFuF, Wfuzz).

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import json
import os
import re
import logging
from typing import Dict, List, Any, Optional, Union, Tuple

from .base import ToolIntegration

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.Integrations.Fuzzing")


class FFuFIntegration(ToolIntegration):
    """Integration für das FFuF Tool."""

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
        Führt FFuF mit den angegebenen Optionen aus.
        
        Args:
            target: Die Ziel-URL mit FUZZ-Platzhalter.
            options: Zusätzliche Optionen für FFuF.
            
        Returns:
            Ein Dictionary mit den Ergebnissen der Ausführung.
        """
        if not self.executable_path:
            return {"error": f"{self._get_tool_name()} nicht gefunden oder installiert"}
        
        if options is None:
            options = {}
        
        # Standardoptionen
        timeout = options.get("timeout", 60)
        output_file = options.get("output_file", "")
        wordlist = options.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        
        # Stelle sicher, dass die Wordlist existiert
        if not os.path.exists(wordlist):
            return {"error": f"Wordlist nicht gefunden: {wordlist}"}
        
        # Kommando zusammenstellen
        command = [
            self.executable_path,
            "-u", target,
            "-w", wordlist,
            "-json"
        ]
        
        # Optionale Parameter
        if "method" in options:
            command.extend(["-X", options["method"]])
        
        if "headers" in options:
            for header, value in options["headers"].items():
                command.extend(["-H", f"{header}: {value}"])
        
        if "cookies" in options:
            command.extend(["-b", options["cookies"]])
        
        if "data" in options:
            command.extend(["-d", options["data"]])
        
        if "follow_redirects" in options and options["follow_redirects"]:
            command.append("-r")
        
        if "threads" in options:
            command.extend(["-t", str(options["threads"])])
        
        if "delay" in options:
            command.extend(["-p", str(options["delay"])])
        
        if "timeout" in options:
            command.extend(["-timeout", str(options["timeout"])])
        
        if "matchers" in options:
            for matcher in options["matchers"]:
                command.extend(["-mc", matcher])
        
        if "filters" in options:
            for filter_val in options["filters"]:
                command.extend(["-fc", filter_val])
        
        if output_file:
            command.extend(["-o", output_file])
        
        # Ausführen
        returncode, stdout, stderr = self.execute_command(command, timeout=timeout+30)
        
        # Ergebnisse verarbeiten
        results = {
            "tool": self._get_tool_name(),
            "target": target,
            "command": " ".join(command),
            "returncode": returncode,
            "findings": [],
            "error": stderr if returncode != 0 else ""
        }
        
        if returncode == 0:
            # Verarbeite die Ausgabe
            try:
                if stdout.strip():
                    data = json.loads(stdout)
                    
                    if "results" in data:
                        for result in data["results"]:
                            finding = {
                                "input": result.get("input", {}),
                                "position": result.get("position", 0),
                                "status": result.get("status", 0),
                                "length": result.get("length", 0),
                                "words": result.get("words", 0),
                                "lines": result.get("lines", 0),
                                "url": result.get("url", ""),
                                "content_type": result.get("content-type", ""),
                                "redirect_location": result.get("redirectlocation", "")
                            }
                            results["findings"].append(finding)
                    
                    # Füge Statistiken hinzu
                    if "stats" in data:
                        results["stats"] = data["stats"]
            except json.JSONDecodeError:
                logger.warning("Konnte JSON nicht parsen, versuche alternative Extraktion")
                
                # Fallback für nicht-JSON-Ausgabe
                for line in stdout.splitlines():
                    if "Status:" in line and "Size:" in line:
                        parts = line.split()
                        status = None
                        size = None
                        url = None
                        
                        for i, part in enumerate(parts):
                            if part == "Status:":
                                status = parts[i+1]
                            elif part == "Size:":
                                size = parts[i+1]
                            elif part.startswith("http"):
                                url = part
                        
                        if status and size and url:
                            finding = {
                                "status": int(status),
                                "length": int(size),
                                "url": url
                            }
                            results["findings"].append(finding)
        
        return results


class WfuzzIntegration(ToolIntegration):
    """Integration für das Wfuzz Tool."""

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
            target: Die Ziel-URL mit FUZZ-Platzhalter.
            options: Zusätzliche Optionen für Wfuzz.
            
        Returns:
            Ein Dictionary mit den Ergebnissen der Ausführung.
        """
        if not self.executable_path:
            return {"error": f"{self._get_tool_name()} nicht gefunden oder installiert"}
        
        if options is None:
            options = {}
        
        # Standardoptionen
        timeout = options.get("timeout", 60)
        output_file = options.get("output_file", "")
        wordlist = options.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        
        # Stelle sicher, dass die Wordlist existiert
        if not os.path.exists(wordlist):
            return {"error": f"Wordlist nicht gefunden: {wordlist}"}
        
        # Kommando zusammenstellen
        command = [
            self.executable_path,
            "-c",
            "-f", "json",
            "-w", wordlist
        ]
        
        # Optionale Parameter
        if "method" in options:
            command.extend(["-X", options["method"]])
        
        if "headers" in options:
            for header, value in options["headers"].items():
                command.extend(["-H", f"{header}: {value}"])
        
        if "cookies" in options:
            command.extend(["-b", options["cookies"]])
        
        if "data" in options:
            command.extend(["-d", options["data"]])
        
        if "follow_redirects" in options and options["follow_redirects"]:
            command.append("-L")
        
        if "threads" in options:
            command.extend(["-t", str(options["threads"])])
        
        if "delay" in options:
            command.extend(["-s", str(options["delay"])])
        
        if "timeout" in options:
            command.extend(["--timeout", str(options["timeout"])])
        
        if "hide" in options:
            command.extend(["--hc", options["hide"]])
        
        if "show" in options:
            command.extend(["--sc", options["show"]])
        
        # Ziel-URL hinzufügen (muss am Ende stehen)
        command.append(target)
        
        # Ausgabedatei
        if output_file:
            command.extend(["-o", output_file])
        
        # Ausführen
        returncode, stdout, stderr = self.execute_command(command, timeout=timeout+30)
        
        # Ergebnisse verarbeiten
        results = {
            "tool": self._get_tool_name(),
            "target": target,
            "command": " ".join(command),
            "returncode": returncode,
            "findings": [],
            "error": stderr if returncode != 0 else ""
        }
        
        if returncode == 0:
            # Verarbeite die Ausgabe
            try:
                if stdout.strip():
                    data = json.loads(stdout)
                    
                    if "results" in data:
                        for result in data["results"]:
                            finding = {
                                "lines": result.get("lines", 0),
                                "words": result.get("words", 0),
                                "chars": result.get("chars", 0),
                                "code": result.get("code", 0),
                                "payload": result.get("payload", {}),
                                "url": result.get("url", ""),
                                "description": result.get("description", "")
                            }
                            results["findings"].append(finding)
                    
                    # Füge Statistiken hinzu
                    if "stats" in data:
                        results["stats"] = data["stats"]
            except json.JSONDecodeError:
                logger.warning("Konnte JSON nicht parsen, versuche alternative Extraktion")
                
                # Fallback für nicht-JSON-Ausgabe
                for line in stdout.splitlines():
                    if "Code:" in line and "Lines:" in line:
                        parts = line.split()
                        code = None
                        lines = None
                        words = None
                        chars = None
                        payload = None
                        
                        for i, part in enumerate(parts):
                            if part == "Code:":
                                code = parts[i+1]
                            elif part == "Lines:":
                                lines = parts[i+1]
                            elif part == "Words:":
                                words = parts[i+1]
                            elif part == "Chars:":
                                chars = parts[i+1]
                            elif "FUZZ:" in part:
                                payload = part.split("FUZZ:")[1]
                        
                        if code and payload:
                            finding = {
                                "code": int(code),
                                "lines": int(lines) if lines else 0,
                                "words": int(words) if words else 0,
                                "chars": int(chars) if chars else 0,
                                "payload": {"FUZZ": payload}
                            }
                            results["findings"].append(finding)
        
        return results


class FuzzingToolFactory:
    """Factory-Klasse für Fuzzing Tool Integrationen."""
    
    @staticmethod
    def create(tool_type: str, config: Dict[str, Any]) -> ToolIntegration:
        """
        Erstellt eine Fuzzing Tool Integration basierend auf dem angegebenen Typ.
        
        Args:
            tool_type: Der Typ des Tools ("ffuf" oder "wfuzz").
            config: Die Konfiguration für das Tool.
            
        Returns:
            Eine Fuzzing Tool Integration.
            
        Raises:
            ValueError: Wenn der angegebene Typ nicht unterstützt wird.
        """
        if tool_type.lower() == "ffuf":
            return FFuFIntegration(config)
        elif tool_type.lower() == "wfuzz":
            return WfuzzIntegration(config)
        else:
            raise ValueError(f"Nicht unterstützter Fuzzing Tool Typ: {tool_type}")
