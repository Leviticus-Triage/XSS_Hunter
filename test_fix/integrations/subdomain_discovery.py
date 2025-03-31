#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Subdomain Discovery Integration
=========================================================

Diese Datei implementiert die Integration für Subdomain Discovery Tools (Subfinder, Amass).

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
logger = logging.getLogger("XSSHunterPro.Integrations.SubdomainDiscovery")


class SubfinderIntegration(ToolIntegration):
    """Integration für das Subfinder Tool."""

    def _get_tool_name(self) -> str:
        """
        Gibt den Namen des Tools zurück.
        
        Returns:
            Der Name des Tools.
        """
        return "subfinder"
    
    def _get_installation_command(self) -> List[str]:
        """
        Gibt den Befehl zur Installation des Tools zurück.
        
        Returns:
            Eine Liste mit dem Installationsbefehl und seinen Argumenten.
        """
        return ["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"]
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Führt Subfinder mit den angegebenen Optionen aus.
        
        Args:
            target: Die Ziel-Domain.
            options: Zusätzliche Optionen für Subfinder.
            
        Returns:
            Ein Dictionary mit den Ergebnissen der Ausführung.
        """
        if not self.executable_path:
            return {"error": f"{self._get_tool_name()} nicht gefunden oder installiert"}
        
        if options is None:
            options = {}
        
        # Standardoptionen
        timeout = options.get("timeout", 30)
        output_file = options.get("output_file", "")
        
        # Kommando zusammenstellen
        command = [
            self.executable_path,
            "-d", target,
            "-json"
        ]
        
        # Optionale Parameter
        if "resolvers" in options:
            command.extend(["-r", options["resolvers"]])
        
        if "sources" in options:
            command.extend(["-sources", options["sources"]])
        
        if "exclude_sources" in options:
            command.extend(["-exclude-sources", options["exclude_sources"]])
        
        if "recursive" in options and options["recursive"]:
            command.append("-recursive")
        
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
            "subdomains": [],
            "error": stderr if returncode != 0 else ""
        }
        
        if returncode == 0:
            # Verarbeite die Ausgabe
            for line in stdout.splitlines():
                try:
                    if line.strip():
                        data = json.loads(line)
                        if "host" in data:
                            results["subdomains"].append(data["host"])
                except json.JSONDecodeError:
                    # Fallback für nicht-JSON-Ausgabe
                    if line.strip() and "." in line:
                        results["subdomains"].append(line.strip())
        
        # Entferne Duplikate
        results["subdomains"] = list(set(results["subdomains"]))
        
        return results


class AmassIntegration(ToolIntegration):
    """Integration für das Amass Tool."""

    def _get_tool_name(self) -> str:
        """
        Gibt den Namen des Tools zurück.
        
        Returns:
            Der Name des Tools.
        """
        return "amass"
    
    def _get_installation_command(self) -> List[str]:
        """
        Gibt den Befehl zur Installation des Tools zurück.
        
        Returns:
            Eine Liste mit dem Installationsbefehl und seinen Argumenten.
        """
        return ["go", "install", "github.com/owasp-amass/amass/v3/...@master"]
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Führt Amass mit den angegebenen Optionen aus.
        
        Args:
            target: Die Ziel-Domain.
            options: Zusätzliche Optionen für Amass.
            
        Returns:
            Ein Dictionary mit den Ergebnissen der Ausführung.
        """
        if not self.executable_path:
            return {"error": f"{self._get_tool_name()} nicht gefunden oder installiert"}
        
        if options is None:
            options = {}
        
        # Standardoptionen
        timeout = options.get("timeout", 300)  # Amass kann länger dauern
        output_file = options.get("output_file", "")
        mode = options.get("mode", "enum")  # enum, intel, db, viz
        
        # Kommando zusammenstellen
        command = [
            self.executable_path,
            mode,
            "-d", target,
            "-json"
        ]
        
        # Optionale Parameter
        if "config" in options:
            command.extend(["-config", options["config"]])
        
        if "resolvers" in options:
            command.extend(["-r", options["resolvers"]])
        
        if "passive" in options and options["passive"]:
            command.append("-passive")
        
        if "timeout" in options:
            command.extend(["-timeout", str(options["timeout"])])
        
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
            "subdomains": [],
            "ips": [],
            "asns": [],
            "error": stderr if returncode != 0 else ""
        }
        
        if returncode == 0:
            # Verarbeite die Ausgabe
            for line in stdout.splitlines():
                try:
                    if line.strip():
                        data = json.loads(line)
                        if "name" in data:
                            results["subdomains"].append(data["name"])
                        
                        if "addresses" in data:
                            for addr in data.get("addresses", []):
                                if "ip" in addr:
                                    results["ips"].append(addr["ip"])
                        
                        if "asn" in data:
                            for asn_data in data.get("asn", []):
                                if "asn" in asn_data:
                                    results["asns"].append(asn_data["asn"])
                except json.JSONDecodeError:
                    # Fallback für nicht-JSON-Ausgabe
                    if line.strip() and "." in line:
                        results["subdomains"].append(line.strip())
        
        # Entferne Duplikate
        results["subdomains"] = list(set(results["subdomains"]))
        results["ips"] = list(set(results["ips"]))
        results["asns"] = list(set(results["asns"]))
        
        return results


class SubdomainDiscoveryFactory:
    """Factory-Klasse für Subdomain Discovery Integrationen."""
    
    @staticmethod
    def create(tool_type: str, config: Dict[str, Any]) -> ToolIntegration:
        """
        Erstellt eine Subdomain Discovery Integration basierend auf dem angegebenen Typ.
        
        Args:
            tool_type: Der Typ des Tools ("subfinder" oder "amass").
            config: Die Konfiguration für das Tool.
            
        Returns:
            Eine Subdomain Discovery Integration.
            
        Raises:
            ValueError: Wenn der angegebene Typ nicht unterstützt wird.
        """
        if tool_type.lower() == "subfinder":
            return SubfinderIntegration(config)
        elif tool_type.lower() == "amass":
            return AmassIntegration(config)
        else:
            raise ValueError(f"Nicht unterstützter Subdomain Discovery Typ: {tool_type}")
