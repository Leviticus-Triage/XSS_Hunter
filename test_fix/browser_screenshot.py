#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Browser Screenshot Module
===================================================

Dieses Modul implementiert die Browser-Screenshot-Funktionalität für das XSS Hunter Framework.
Es ermöglicht das Erstellen von Screenshots von Webseiten mit XSS-Schwachstellen.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import time
import logging
import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime
from urllib.parse import urlparse

from screenshot_manager import ScreenshotManager

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.BrowserScreenshot")


class BrowserScreenshot:
    """Klasse für die Browser-Screenshot-Funktionalität."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialisiert die Browser-Screenshot-Klasse.

        Args:
            config: Konfigurationsoptionen für die Browser-Screenshot-Klasse.
        """
        self.config = config or {}
        self.screenshot_dir = self.config.get("screenshot_dir", "screenshots")
        self.delay_before_screenshot = self.config.get("delay_before_screenshot", 2)
        self.screenshot_manager = ScreenshotManager(self.config)
        
        logger.info(f"Browser-Screenshot-Modul initialisiert mit Verzeichnis: {self.screenshot_dir}")

    def capture_xss(self, url: str, payload: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Erstellt einen Screenshot einer URL mit XSS-Payload.

        Args:
            url: Die URL, von der ein Screenshot erstellt werden soll.
            payload: Der XSS-Payload, der in der URL enthalten ist.
            context: Zusätzlicher Kontext für den Screenshot.

        Returns:
            Der Pfad zum erstellten Screenshot oder None bei Fehler.
        """
        try:
            logger.info(f"Erstelle Screenshot für XSS in {url} mit Payload: {payload}")
            
            # Erstelle den Screenshot
            filepath = self.screenshot_manager.take_screenshot(
                url=url,
                payload=payload,
                delay=self.delay_before_screenshot
            )
            
            if filepath:
                # Speichere zusätzlichen Kontext, falls vorhanden
                if context:
                    self._save_context(filepath, context)
                
                logger.info(f"XSS-Screenshot erfolgreich erstellt: {filepath}")
                return filepath
            else:
                logger.error(f"Fehler beim Erstellen des XSS-Screenshots für {url}")
                return None
                
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des XSS-Screenshots für {url}: {e}")
            return None

    def capture_multiple(self, urls: List[str], delay_between: int = 5) -> List[str]:
        """
        Erstellt Screenshots von mehreren URLs.

        Args:
            urls: Die URLs, von denen Screenshots erstellt werden sollen.
            delay_between: Verzögerung zwischen den Screenshots in Sekunden.

        Returns:
            Eine Liste der Pfade zu den erstellten Screenshots.
        """
        filepaths = []
        
        for url in urls:
            try:
                filepath = self.screenshot_manager.take_screenshot(
                    url=url,
                    delay=self.delay_before_screenshot
                )
                
                if filepath:
                    filepaths.append(filepath)
                    logger.info(f"Screenshot erfolgreich erstellt: {filepath}")
                else:
                    logger.error(f"Fehler beim Erstellen des Screenshots für {url}")
                
                # Warte zwischen den Screenshots
                if delay_between > 0 and url != urls[-1]:
                    time.sleep(delay_between)
                    
            except Exception as e:
                logger.error(f"Fehler beim Erstellen des Screenshots für {url}: {e}")
        
        return filepaths

    def _save_context(self, filepath: str, context: Dict[str, Any]) -> None:
        """
        Speichert zusätzlichen Kontext zu einem Screenshot.

        Args:
            filepath: Der Pfad zum Screenshot.
            context: Der zu speichernde Kontext.
        """
        try:
            # Erstelle die Kontext-Datei
            base_filepath = os.path.splitext(filepath)[0]
            context_filepath = f"{base_filepath}.context.txt"
            
            # Formatiere den Kontext
            formatted_context = "\n".join([f"{key}: {value}" for key, value in context.items()])
            
            # Schreibe den Kontext in die Datei
            with open(context_filepath, "w") as f:
                f.write(formatted_context)
                
            logger.info(f"Kontext gespeichert: {context_filepath}")
                
        except Exception as e:
            logger.error(f"Fehler beim Speichern des Kontexts: {e}")

    def get_recent_screenshots(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Gibt eine Liste der letzten Screenshots zurück.

        Args:
            limit: Maximale Anzahl der zurückzugebenden Screenshots.

        Returns:
            Eine Liste von Screenshot-Metadaten.
        """
        return self.screenshot_manager.get_screenshots(limit)

    def cleanup(self, max_age_days: int = 30) -> int:
        """
        Löscht alte Screenshots.

        Args:
            max_age_days: Maximales Alter der Screenshots in Tagen.

        Returns:
            Die Anzahl der gelöschten Screenshots.
        """
        return self.screenshot_manager.cleanup_old_screenshots(max_age_days)


# Beispiel für die Verwendung
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(level=logging.INFO)
    
    # Erstelle die Browser-Screenshot-Klasse
    config = {
        "screenshot_dir": "screenshots",
        "browser_type": "chrome",
        "headless": True,
        "width": 1366,
        "height": 768,
        "timeout": 30,
        "delay_before_screenshot": 2
    }
    browser_screenshot = BrowserScreenshot(config)
    
    # Erstelle einen Screenshot
    url = "https://example.com"
    payload = "<script>alert(1)</script>"
    context = {
        "vulnerability_type": "Reflected XSS",
        "severity": "High",
        "discovered_by": "XSS Hunter Pro",
        "notes": "Found in search parameter"
    }
    
    filepath = browser_screenshot.capture_xss(url, payload, context)
    
    if filepath:
        print(f"XSS-Screenshot erstellt: {filepath}")
    else:
        print("Fehler beim Erstellen des XSS-Screenshots")
