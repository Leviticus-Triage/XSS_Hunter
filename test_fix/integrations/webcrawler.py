#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Web Crawler Integration
=================================================

Diese Datei implementiert die Integration für Web Crawler Tools (Gospider/Hakrawler).

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import json
import os
import re
import subprocess
import logging
from typing import Dict, List, Any, Optional, Union, Tuple

from .base import ToolIntegration

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.Integrations.WebCrawler")


class GospiderIntegration(ToolIntegration):
    """Integration für das Gospider Tool."""

    def _get_tool_name(self) -> str:
        """
        Gibt den Namen des Tools zurück.
        
        Returns:
            Der Name des Tools.
        """
        return "gospider"
    
    def _get_installation_command(self) -> List[str]:
        """
        Gibt den Befehl zur Installation des Tools zurück.
        
        Returns:
            Eine Liste mit dem Installationsbefehl und seinen Argumenten.
        """
        return ["go", "install", "github.com/jaeles-project/gospider@latest"]
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Führt Gospider mit den angegebenen Optionen aus.
        
        Args:
            target: Die Ziel-URL oder Domain.
            options: Zusätzliche Optionen für Gospider.
            
        Returns:
            Ein Dictionary mit den Ergebnissen der Ausführung.
        """
        if not self.executable_path:
            return {"error": f"{self._get_tool_name()} nicht gefunden oder installiert"}
        
        if options is None:
            options = {}
        
        # Standardoptionen
        depth = options.get("depth", 3)
        concurrent = options.get("concurrent", 5)
        delay = options.get("delay", 1)
        timeout = options.get("timeout", 30)
        output_file = options.get("output_file", "")
        
        # Kommando zusammenstellen
        command = [
            self.executable_path,
            "-s", target,
            "-d", str(depth),
            "-c", str(concurrent),
            "-t", str(timeout),
            "--delay", str(delay),
            "--json"
        ]
        
        # Optionale Parameter
        if "user_agent" in options:
            command.extend(["--user-agent", options["user_agent"]])
        
        if "cookie" in options:
            command.extend(["--cookie", options["cookie"]])
        
        if output_file:
            command.extend(["--output", output_file])
        
        # Ausführen
        returncode, stdout, stderr = self.execute_command(command, timeout=timeout+30)
        
        # Ergebnisse verarbeiten
        results = {
            "tool": self._get_tool_name(),
            "target": target,
            "command": " ".join(command),
            "returncode": returncode,
            "urls": [],
            "forms": [],
            "js_files": [],
            "subdomains": [],
            "error": stderr if returncode != 0 else ""
        }
        
        if returncode == 0:
            # Verarbeite die Ausgabe
            for line in stdout.splitlines():
                try:
                    if line.strip():
                        data = json.loads(line)
                        
                        if "url" in data:
                            results["urls"].append(data["url"])
                        
                        if "form" in data:
                            results["forms"].append(data["form"])
                        
                        if "js" in data:
                            results["js_files"].append(data["js"])
                        
                        if "subdomains" in data:
                            results["subdomains"].extend(data["subdomains"])
                except json.JSONDecodeError:
                    # Fallback für nicht-JSON-Ausgabe
                    url_match = re.search(r'\[url\] - (https?://[^\s]+)', line)
                    if url_match:
                        results["urls"].append(url_match.group(1))
                    
                    form_match = re.search(r'\[form\] - (https?://[^\s]+)', line)
                    if form_match:
                        results["forms"].append(form_match.group(1))
                    
                    js_match = re.search(r'\[javascript\] - (https?://[^\s]+)', line)
                    if js_match:
                        results["js_files"].append(js_match.group(1))
                    
                    subdomain_match = re.search(r'\[subdomains\] - ([^\s]+)', line)
                    if subdomain_match:
                        results["subdomains"].append(subdomain_match.group(1))
        
        # Entferne Duplikate
        results["urls"] = list(set(results["urls"]))
        results["forms"] = list(set(results["forms"]))
        results["js_files"] = list(set(results["js_files"]))
        results["subdomains"] = list(set(results["subdomains"]))
        
        return results


class HakrawlerIntegration(ToolIntegration):
    """Integration für das Hakrawler Tool."""

    def _get_tool_name(self) -> str:
        """
        Gibt den Namen des Tools zurück.
        
        Returns:
            Der Name des Tools.
        """
        return "hakrawler"
    
    def _get_installation_command(self) -> List[str]:
        """
        Gibt den Befehl zur Installation des Tools zurück.
        
        Returns:
            Eine Liste mit dem Installationsbefehl und seinen Argumenten.
        """
        return ["go", "install", "github.com/hakluke/hakrawler@latest"]
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Führt Hakrawler mit den angegebenen Optionen aus.
        
        Args:
            target: Die Ziel-URL oder Domain.
            options: Zusätzliche Optionen für Hakrawler.
            
        Returns:
            Ein Dictionary mit den Ergebnissen der Ausführung.
        """
        if not self.executable_path:
            return {"error": f"{self._get_tool_name()} nicht gefunden oder installiert"}
        
        if options is None:
            options = {}
        
        # Standardoptionen
        depth = options.get("depth", 3)
        timeout = options.get("timeout", 30)
        output_file = options.get("output_file", "")
        
        # Kommando zusammenstellen
        command = [
            self.executable_path,
            "-d", str(depth),
            "-t", str(timeout),
            "-json"
        ]
        
        # Optionale Parameter
        if "user_agent" in options:
            command.extend(["-h", options["user_agent"]])
        
        if "cookie" in options:
            command.extend(["-c", options["cookie"]])
        
        if "scope" in options and options["scope"]:
            command.append("-s")
        
        if "insecure" in options and options["insecure"]:
            command.append("-k")
        
        # Ziel hinzufügen (Hakrawler erwartet die Eingabe über stdin)
        command_input = target
        
        # Ausführen
        try:
            logger.debug(f"Führe Befehl aus: {' '.join(command)}")
            
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input=command_input, timeout=timeout+30)
            returncode = process.returncode
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout bei der Ausführung von: {' '.join(command)}")
            returncode = -1
            stdout = ""
            stderr = f"Timeout nach {timeout+30} Sekunden"
            
        except Exception as e:
            logger.error(f"Fehler bei der Ausführung von {' '.join(command)}: {e}")
            returncode = -1
            stdout = ""
            stderr = str(e)
        
        # Ergebnisse verarbeiten
        results = {
            "tool": self._get_tool_name(),
            "target": target,
            "command": " ".join(command),
            "returncode": returncode,
            "urls": [],
            "forms": [],
            "js_files": [],
            "subdomains": [],
            "error": stderr if returncode != 0 else ""
        }
        
        if returncode == 0:
            # Verarbeite die Ausgabe
            for line in stdout.splitlines():
                try:
                    if line.strip():
                        data = json.loads(line)
                        
                        if "url" in data:
                            url = data["url"]
                            results["urls"].append(url)
                            
                            # Hakrawler kennzeichnet JS-Dateien nicht explizit
                            if url.endswith(".js"):
                                results["js_files"].append(url)
                            
                            # Hakrawler kennzeichnet Formulare nicht explizit
                            # Wir könnten hier später eine Heuristik implementieren
                        
                        if "host" in data and data["host"] != target:
                            results["subdomains"].append(data["host"])
                except json.JSONDecodeError:
                    # Fallback für nicht-JSON-Ausgabe
                    if line.startswith("http"):
                        results["urls"].append(line.strip())
                        
                        if line.strip().endswith(".js"):
                            results["js_files"].append(line.strip())
        
        # Entferne Duplikate
        results["urls"] = list(set(results["urls"]))
        results["forms"] = list(set(results["forms"]))
        results["js_files"] = list(set(results["js_files"]))
        results["subdomains"] = list(set(results["subdomains"]))
        
        # Speichere Ausgabe in Datei, falls gewünscht
        if output_file and stdout:
            try:
                with open(output_file, "w") as f:
                    f.write(stdout)
            except Exception as e:
                logger.error(f"Fehler beim Schreiben der Ausgabe in {output_file}: {e}")
        
        return results


class WebCrawlerFactory:
    """Factory-Klasse für Web Crawler Integrationen."""
    
    @staticmethod
    def create(crawler_type: str, config: Dict[str, Any]) -> ToolIntegration:
        """
        Erstellt eine Web Crawler Integration basierend auf dem angegebenen Typ.
        
        Args:
            crawler_type: Der Typ des Web Crawlers ("gospider" oder "hakrawler").
            config: Die Konfiguration für den Web Crawler.
            
        Returns:
            Eine Web Crawler Integration.
            
        Raises:
            ValueError: Wenn der angegebene Typ nicht unterstützt wird.
        """
        if crawler_type.lower() == "gospider":
            return GospiderIntegration(config)
        elif crawler_type.lower() == "hakrawler":
            return HakrawlerIntegration(config)
        else:
            raise ValueError(f"Nicht unterstützter Web Crawler Typ: {crawler_type}")
