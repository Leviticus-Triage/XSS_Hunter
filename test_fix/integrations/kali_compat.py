#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Kali Linux Compatibility
==================================================

Dieses Modul bietet Kompatibilitätsfunktionen für Kali Linux.
Es erkennt Kali Linux-Umgebungen und passt Pfade und Konfigurationen entsprechend an.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.1
"""

import os
import sys
import subprocess
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("XSSHunterPro.KaliCompat")

class KaliCompat:
    """Bietet Kompatibilitätsfunktionen für Kali Linux."""
    
    def __init__(self):
        """Initialisiert die Kali Linux-Kompatibilitätsklasse."""
        self.is_kali = self._detect_kali_linux()
        
        if self.is_kali:
            logger.info("Kali Linux-Umgebung erkannt")
    
    def _detect_kali_linux(self) -> bool:
        """
        Erkennt, ob das System Kali Linux ist.
        
        Returns:
            True, wenn das System Kali Linux ist, sonst False.
        """
        # Methode 1: Überprüfe, ob die Kali-Release-Datei existiert
        if os.path.exists("/etc/kali-release") or os.path.exists("/etc/kali_release"):
            logger.info("Kali Linux erkannt über /etc/os-release")
            return True
        
        # Methode 2: Überprüfe den Inhalt von /etc/os-release
        try:
            with open("/etc/os-release", "r") as f:
                content = f.read()
                if "kali" in content.lower():
                    logger.info("Kali Linux erkannt über /etc/os-release")
                    return True
        except:
            pass
        
        # Methode 3: Überprüfe die Ausgabe von lsb_release
        try:
            output = subprocess.check_output(["lsb_release", "-i"]).decode().strip()
            if "kali" in output.lower():
                logger.info("Kali Linux erkannt über lsb_release")
                return True
        except:
            pass
        
        # Methode 4: Überprüfe, ob typische Kali-Tools vorhanden sind
        kali_tools = ["metasploit-framework", "aircrack-ng", "hydra", "nmap"]
        for tool in kali_tools:
            try:
                subprocess.check_output(["which", tool], stderr=subprocess.DEVNULL)
                logger.info(f"Kali Linux erkannt über Vorhandensein von {tool}")
                return True
            except:
                pass
        
        return False
    
    def is_kali_linux(self) -> bool:
        """
        Gibt zurück, ob das System Kali Linux ist.
        
        Returns:
            True, wenn das System Kali Linux ist, sonst False.
        """
        return self.is_kali
    
    def get_kali_paths(self) -> List[str]:
        """
        Gibt eine Liste von Kali-spezifischen Pfaden zurück.
        
        Returns:
            Eine Liste von Pfaden, die für Kali Linux spezifisch sind.
        """
        if not self.is_kali:
            return []
        
        paths = []
        
        # Metasploit-Framework-Pfad
        if os.path.exists("/usr/share/metasploit-framework"):
            paths.append("/usr/share/metasploit-framework")
        
        # Python-Pakete
        if os.path.exists("/usr/lib/python3/dist-packages"):
            paths.append("/usr/lib/python3/dist-packages")
        
        return paths
    
    def get_chromedriver_path(self) -> str:
        """
        Gibt den Pfad zum Chrome-Treiber auf Kali Linux zurück.
        
        Returns:
            Der Pfad zum Chrome-Treiber oder eine leere Zeichenfolge, wenn nicht gefunden.
        """
        if not self.is_kali:
            return ""
        
        # Überprüfe übliche Pfade
        paths = [
            "/usr/bin/chromedriver",
            "/usr/local/bin/chromedriver",
            "/usr/lib/chromium/chromedriver"
        ]
        
        for path in paths:
            if os.path.exists(path):
                return path
        
        # Versuche, den Treiber im PATH zu finden
        try:
            return subprocess.check_output(["which", "chromedriver"]).decode().strip()
        except:
            return ""
    
    def get_geckodriver_path(self) -> str:
        """
        Gibt den Pfad zum Firefox-Treiber auf Kali Linux zurück.
        
        Returns:
            Der Pfad zum Firefox-Treiber oder eine leere Zeichenfolge, wenn nicht gefunden.
        """
        if not self.is_kali:
            return ""
        
        # Überprüfe übliche Pfade
        paths = [
            "/usr/bin/geckodriver",
            "/usr/local/bin/geckodriver"
        ]
        
        for path in paths:
            if os.path.exists(path):
                return path
        
        # Versuche, den Treiber im PATH zu finden
        try:
            return subprocess.check_output(["which", "geckodriver"]).decode().strip()
        except:
            return ""
    
    def install_dependencies(self) -> bool:
        """
        Installiert Abhängigkeiten für Kali Linux.
        
        Returns:
            True, wenn die Installation erfolgreich war, sonst False.
        """
        if not self.is_kali:
            return False
        
        try:
            # Installiere Python-Pakete
            subprocess.check_call(["apt-get", "update"])
            subprocess.check_call([
                "apt-get", "install", "-y",
                "python3-selenium",
                "python3-requests",
                "python3-bs4",
                "python3-lxml",
                "chromedriver",
                "firefox-esr",
                "geckodriver"
            ])
            
            return True
        except Exception as e:
            logger.error(f"Fehler bei der Installation von Abhängigkeiten: {e}")
            return False
    
    def fix_permissions(self) -> bool:
        """
        Behebt Berechtigungsprobleme auf Kali Linux.
        
        Returns:
            True, wenn die Behebung erfolgreich war, sonst False.
        """
        if not self.is_kali:
            return False
        
        try:
            # Berechtigungen für Chrome-Treiber
            chromedriver_path = self.get_chromedriver_path()
            if chromedriver_path and os.path.exists(chromedriver_path):
                subprocess.check_call(["chmod", "+x", chromedriver_path])
            
            # Berechtigungen für Firefox-Treiber
            geckodriver_path = self.get_geckodriver_path()
            if geckodriver_path and os.path.exists(geckodriver_path):
                subprocess.check_call(["chmod", "+x", geckodriver_path])
            
            return True
        except Exception as e:
            logger.error(f"Fehler bei der Behebung von Berechtigungsproblemen: {e}")
            return False
