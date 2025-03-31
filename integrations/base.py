#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Tool Integration Base Class
=====================================================

Diese Datei definiert die Basisklasse für alle Tool-Integrationen.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import subprocess
import logging
import shutil
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, Tuple

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.Integrations.Base")


class ToolIntegration(ABC):
    """Basisklasse für alle Tool-Integrationen."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialisiert die Tool-Integration mit der angegebenen Konfiguration.

        Args:
            config: Ein Dictionary mit Konfigurationsoptionen.
        """
        self.config = config
        self.tool_name = self._get_tool_name()
        self.executable_path = self._find_executable()
        self.version = self._get_version()
        
        if not self.executable_path:
            logger.warning(f"Tool {self.tool_name} nicht gefunden. Versuche automatische Installation.")
            self._install_tool()
            self.executable_path = self._find_executable()
            
        if self.executable_path:
            logger.info(f"Tool {self.tool_name} gefunden: {self.executable_path} (Version: {self.version})")
        else:
            logger.error(f"Tool {self.tool_name} konnte nicht gefunden oder installiert werden.")

    @abstractmethod
    def _get_tool_name(self) -> str:
        """
        Gibt den Namen des Tools zurück.
        
        Returns:
            Der Name des Tools.
        """
        pass
    
    @abstractmethod
    def _get_installation_command(self) -> List[str]:
        """
        Gibt den Befehl zur Installation des Tools zurück.
        
        Returns:
            Eine Liste mit dem Installationsbefehl und seinen Argumenten.
        """
        pass
    
    @abstractmethod
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Führt das Tool mit den angegebenen Optionen aus.
        
        Args:
            target: Das Ziel für das Tool (z.B. eine URL oder Domain).
            options: Zusätzliche Optionen für das Tool.
            
        Returns:
            Ein Dictionary mit den Ergebnissen der Ausführung.
        """
        pass
    
    def _find_executable(self) -> Optional[str]:
        """
        Sucht nach dem ausführbaren Programm des Tools im System.
        
        Returns:
            Der Pfad zum ausführbaren Programm oder None, wenn es nicht gefunden wurde.
        """
        tool_name = self._get_tool_name()
        
        # Prüfe, ob das Tool im PATH ist
        executable_path = shutil.which(tool_name)
        if executable_path:
            return executable_path
            
        # Prüfe, ob das Tool in gängigen Verzeichnissen ist
        common_dirs = [
            "/usr/bin",
            "/usr/local/bin",
            "/opt/local/bin",
            "/home/ubuntu/.local/bin",
            "/home/ubuntu/go/bin",
            os.path.expanduser("~/go/bin"),
        ]
        
        for directory in common_dirs:
            path = os.path.join(directory, tool_name)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
                
        return None
    
    def _get_version(self) -> str:
        """
        Ermittelt die Version des Tools.
        
        Returns:
            Die Version des Tools oder "unbekannt", wenn sie nicht ermittelt werden konnte.
        """
        if not self.executable_path:
            return "unbekannt"
            
        try:
            # Versuche mit --version
            result = subprocess.run(
                [self.executable_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout:
                return result.stdout.strip().split("\n")[0]
                
            # Versuche mit -v
            result = subprocess.run(
                [self.executable_path, "-v"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout:
                return result.stdout.strip().split("\n")[0]
                
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug(f"Fehler beim Ermitteln der Version von {self.tool_name}: {e}")
            
        return "unbekannt"
    
    def _install_tool(self) -> bool:
        """
        Installiert das Tool.
        
        Returns:
            True, wenn die Installation erfolgreich war, sonst False.
        """
        try:
            install_command = self._get_installation_command()
            
            if not install_command:
                logger.error(f"Kein Installationsbefehl für {self.tool_name} verfügbar.")
                return False
                
            logger.info(f"Installiere {self.tool_name}...")
            
            result = subprocess.run(
                install_command,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"{self.tool_name} erfolgreich installiert.")
                return True
            else:
                logger.error(f"Fehler bei der Installation von {self.tool_name}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Fehler bei der Installation von {self.tool_name}: {e}")
            return False
    
    def execute_command(self, command: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """
        Führt einen Befehl aus und gibt das Ergebnis zurück.
        
        Args:
            command: Der auszuführende Befehl als Liste.
            timeout: Timeout in Sekunden.
            
        Returns:
            Ein Tupel aus Rückgabecode, Standardausgabe und Standardfehlerausgabe.
        """
        try:
            logger.debug(f"Führe Befehl aus: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout bei der Ausführung von: {' '.join(command)}")
            return -1, "", f"Timeout nach {timeout} Sekunden"
            
        except Exception as e:
            logger.error(f"Fehler bei der Ausführung von {' '.join(command)}: {e}")
            return -1, "", str(e)
