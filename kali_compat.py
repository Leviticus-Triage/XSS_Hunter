#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Kali Linux Compatibility Module
=============================================

Dieses Modul implementiert Kompatibilitätsfunktionen für Kali Linux.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import logging
import subprocess
import shutil
import platform
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.KaliCompat")


class KaliCompat:
    """
    Kali Linux Kompatibilitätsklasse für das XSS Hunter Framework.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialisiert die Kali Linux Kompatibilitätsklasse.

        Args:
            config: Die Konfiguration.
        """
        # Setze die Standardkonfiguration
        self.config = {
            "check_tools": True,
            "auto_install": False,
            "tools": {
                "gospider": {
                    "package": "gospider",
                    "command": "gospider",
                    "install_command": "go install github.com/jaeles-project/gospider@latest"
                },
                "hakrawler": {
                    "package": "hakrawler",
                    "command": "hakrawler",
                    "install_command": "go install github.com/hakluke/hakrawler@latest"
                },
                "wfuzz": {
                    "package": "wfuzz",
                    "command": "wfuzz",
                    "install_command": "apt-get install -y wfuzz"
                },
                "subfinder": {
                    "package": "subfinder",
                    "command": "subfinder",
                    "install_command": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
                },
                "nuclei": {
                    "package": "nuclei",
                    "command": "nuclei",
                    "install_command": "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
                },
                "chromium": {
                    "package": "chromium",
                    "command": "chromium",
                    "install_command": "apt-get install -y chromium"
                },
                "firefox": {
                    "package": "firefox-esr",
                    "command": "firefox",
                    "install_command": "apt-get install -y firefox-esr"
                }
            }
        }
        
        # Überschreibe die Standardkonfiguration mit der übergebenen Konfiguration
        if config:
            self.config.update(config)
        
        # Prüfe, ob wir auf Kali Linux laufen
        self.is_kali = self._check_kali()
        
        # Prüfe die Tools, wenn gewünscht
        if self.config["check_tools"]:
            self.check_tools()

    def _check_kali(self) -> bool:
        """
        Prüft, ob wir auf Kali Linux laufen.

        Returns:
            True, wenn wir auf Kali Linux laufen, sonst False.
        """
        # Prüfe das Betriebssystem
        if platform.system() != "Linux":
            logger.info("Nicht auf Linux, Kali-Kompatibilität deaktiviert")
            return False
        
        # Prüfe, ob die Datei /etc/os-release existiert
        if not os.path.exists("/etc/os-release"):
            logger.info("Datei /etc/os-release nicht gefunden, Kali-Kompatibilität deaktiviert")
            return False
        
        # Lese die Datei /etc/os-release
        with open("/etc/os-release", "r") as f:
            os_release = f.read()
        
        # Prüfe, ob "Kali" in der Datei vorkommt
        if "Kali" in os_release:
            logger.info("Kali Linux erkannt, Kali-Kompatibilität aktiviert")
            return True
        
        logger.info("Kein Kali Linux erkannt, Kali-Kompatibilität deaktiviert")
        return False

    def check_tools(self) -> Dict[str, bool]:
        """
        Prüft, ob die benötigten Tools installiert sind.

        Returns:
            Ein Dictionary mit den Prüfergebnissen.
        """
        results = {}
        
        # Prüfe jedes Tool
        for tool_name, tool_info in self.config["tools"].items():
            # Prüfe, ob das Tool installiert ist
            is_installed = self._check_tool(tool_info["command"])
            results[tool_name] = is_installed
            
            # Installiere das Tool, wenn gewünscht
            if not is_installed and self.config["auto_install"] and self.is_kali:
                self.install_tool(tool_name)
                # Prüfe erneut, ob das Tool installiert ist
                results[tool_name] = self._check_tool(tool_info["command"])
        
        return results

    def _check_tool(self, command: str) -> bool:
        """
        Prüft, ob ein Tool installiert ist.

        Args:
            command: Der Befehl des Tools.

        Returns:
            True, wenn das Tool installiert ist, sonst False.
        """
        # Prüfe, ob der Befehl im PATH ist
        return shutil.which(command) is not None

    def install_tool(self, tool_name: str) -> bool:
        """
        Installiert ein Tool.

        Args:
            tool_name: Der Name des Tools.

        Returns:
            True, wenn das Tool erfolgreich installiert wurde, sonst False.
        """
        # Prüfe, ob wir auf Kali Linux laufen
        if not self.is_kali:
            logger.warning("Nicht auf Kali Linux, Installation nicht möglich")
            return False
        
        # Prüfe, ob das Tool in der Konfiguration ist
        if tool_name not in self.config["tools"]:
            logger.warning(f"Tool {tool_name} nicht in der Konfiguration")
            return False
        
        # Hole die Tool-Informationen
        tool_info = self.config["tools"][tool_name]
        
        try:
            # Führe den Installationsbefehl aus
            logger.info(f"Installiere {tool_name}...")
            subprocess.run(tool_info["install_command"], shell=True, check=True)
            
            # Prüfe, ob das Tool installiert wurde
            if self._check_tool(tool_info["command"]):
                logger.info(f"Tool {tool_name} erfolgreich installiert")
                return True
            else:
                logger.warning(f"Tool {tool_name} konnte nicht installiert werden")
                return False
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Fehler bei der Installation von {tool_name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unerwarteter Fehler bei der Installation von {tool_name}: {e}")
            return False

    def install_all_tools(self) -> Dict[str, bool]:
        """
        Installiert alle Tools.

        Returns:
            Ein Dictionary mit den Installationsergebnissen.
        """
        results = {}
        
        # Prüfe, ob wir auf Kali Linux laufen
        if not self.is_kali:
            logger.warning("Nicht auf Kali Linux, Installation nicht möglich")
            return {tool_name: False for tool_name in self.config["tools"]}
        
        # Installiere jedes Tool
        for tool_name in self.config["tools"]:
            results[tool_name] = self.install_tool(tool_name)
        
        return results

    def get_tool_path(self, tool_name: str) -> str:
        """
        Gibt den Pfad zu einem Tool zurück.

        Args:
            tool_name: Der Name des Tools.

        Returns:
            Der Pfad zum Tool oder eine leere Zeichenkette, wenn das Tool nicht gefunden wurde.
        """
        # Prüfe, ob das Tool in der Konfiguration ist
        if tool_name not in self.config["tools"]:
            logger.warning(f"Tool {tool_name} nicht in der Konfiguration")
            return ""
        
        # Hole die Tool-Informationen
        tool_info = self.config["tools"][tool_name]
        
        # Prüfe, ob das Tool installiert ist
        tool_path = shutil.which(tool_info["command"])
        
        if tool_path:
            return tool_path
        else:
            logger.warning(f"Tool {tool_name} nicht gefunden")
            return ""

    def run_tool(self, tool_name: str, args: List[str] = None) -> Tuple[int, str, str]:
        """
        Führt ein Tool aus.

        Args:
            tool_name: Der Name des Tools.
            args: Die Argumente für das Tool.

        Returns:
            Ein Tupel mit dem Exit-Code, der Standardausgabe und der Standardfehlerausgabe.
        """
        # Prüfe, ob das Tool in der Konfiguration ist
        if tool_name not in self.config["tools"]:
            logger.warning(f"Tool {tool_name} nicht in der Konfiguration")
            return (1, "", f"Tool {tool_name} nicht in der Konfiguration")
        
        # Hole die Tool-Informationen
        tool_info = self.config["tools"][tool_name]
        
        # Prüfe, ob das Tool installiert ist
        tool_path = shutil.which(tool_info["command"])
        
        if not tool_path:
            logger.warning(f"Tool {tool_name} nicht gefunden")
            return (1, "", f"Tool {tool_name} nicht gefunden")
        
        # Erstelle den Befehl
        command = [tool_path]
        
        if args:
            command.extend(args)
        
        try:
            # Führe den Befehl aus
            logger.info(f"Führe {tool_name} aus: {' '.join(command)}")
            process = subprocess.run(command, capture_output=True, text=True, check=False)
            
            # Gib das Ergebnis zurück
            return (process.returncode, process.stdout, process.stderr)
            
        except Exception as e:
            logger.error(f"Fehler beim Ausführen von {tool_name}: {e}")
            return (1, "", str(e))


# Beispiel für die Verwendung
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(level=logging.INFO)
    
    # Erstelle die Kali-Kompatibilitätsklasse
    kali_compat = KaliCompat()
    
    # Prüfe, ob wir auf Kali Linux laufen
    print(f"Auf Kali Linux: {kali_compat.is_kali}")
    
    # Prüfe die Tools
    results = kali_compat.check_tools()
    print("Tool-Status:")
    for tool_name, is_installed in results.items():
        print(f"  {tool_name}: {'Installiert' if is_installed else 'Nicht installiert'}")
    
    # Installiere fehlende Tools, wenn gewünscht
    if kali_compat.is_kali and input("Fehlende Tools installieren? (j/n) ").lower() == "j":
        for tool_name, is_installed in results.items():
            if not is_installed:
                print(f"Installiere {tool_name}...")
                kali_compat.install_tool(tool_name)
    
    # Führe ein Tool aus, wenn es installiert ist
    if results.get("wfuzz", False):
        print("Führe wfuzz aus...")
        exit_code, stdout, stderr = kali_compat.run_tool("wfuzz", ["--version"])
        print(f"Exit-Code: {exit_code}")
        print(f"Standardausgabe: {stdout}")
        print(f"Standardfehlerausgabe: {stderr}")
