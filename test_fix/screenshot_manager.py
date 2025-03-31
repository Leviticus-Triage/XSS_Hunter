#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Screenshot Manager
============================================

Diese Datei implementiert die Screenshot-Funktionalität für das XSS Hunter Framework.
Sie ermöglicht das automatische Erstellen von Screenshots bei erkannten XSS-Schwachstellen.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import time
import logging
import uuid
import base64
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from urllib.parse import urlparse

# Versuche, verschiedene Browser-Automatisierungsbibliotheken zu importieren
SELENIUM_AVAILABLE = False
PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.common.exceptions import WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    pass

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.ScreenshotManager")


class ScreenshotManager:
    """Manager für die Screenshot-Funktionalität."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialisiert den Screenshot-Manager.

        Args:
            config: Konfigurationsoptionen für den Screenshot-Manager.
        """
        self.config = config or {}
        self.screenshot_dir = self.config.get("screenshot_dir", "screenshots")
        self.browser_type = self.config.get("browser_type", "chrome")
        self.timeout = self.config.get("timeout", 30)
        self.width = self.config.get("width", 1366)
        self.height = self.config.get("height", 768)
        self.headless = self.config.get("headless", True)
        
        # Erstelle das Screenshot-Verzeichnis, falls es nicht existiert
        os.makedirs(self.screenshot_dir, exist_ok=True)
        os.makedirs(os.path.join(self.screenshot_dir, "screenshots"), exist_ok=True)
        
        # Initialisiere den Browser-Treiber
        self.driver = None
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        
        logger.info(f"Screenshot-Manager initialisiert mit Verzeichnis: {self.screenshot_dir}")
        logger.info(f"Verfügbare Browser-Engines: Selenium: {SELENIUM_AVAILABLE}, Playwright: {PLAYWRIGHT_AVAILABLE}")

    def take_screenshot(self, url: str, payload: Optional[str] = None, delay: int = 2) -> Optional[str]:
        """
        Erstellt einen Screenshot einer URL.

        Args:
            url: Die URL, von der ein Screenshot erstellt werden soll.
            payload: Optionaler XSS-Payload, der in der URL enthalten ist.
            delay: Verzögerung in Sekunden vor dem Screenshot.

        Returns:
            Der Pfad zum erstellten Screenshot oder None bei Fehler.
        """
        try:
            # Generiere einen eindeutigen Dateinamen
            timestamp = int(time.time())
            random_id = uuid.uuid4().hex[:8]
            filename = f"xss_{timestamp}_{random_id}.png"
            filepath = os.path.join(self.screenshot_dir, "screenshots", filename)
            
            # Erstelle den Screenshot
            if PLAYWRIGHT_AVAILABLE:
                success = self._take_screenshot_playwright(url, filepath, delay)
            elif SELENIUM_AVAILABLE:
                success = self._take_screenshot_selenium(url, filepath, delay)
            else:
                logger.error("Keine Browser-Automatisierungsbibliothek verfügbar")
                return None
            
            if success:
                logger.info(f"Screenshot erstellt: {filepath}")
                
                # Speichere Metadaten
                metadata = {
                    "url": url,
                    "timestamp": timestamp,
                    "payload": payload,
                    "filename": filename
                }
                self._save_metadata(metadata)
                
                return filepath
            else:
                logger.error(f"Fehler beim Erstellen des Screenshots für {url}")
                return None
                
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des Screenshots für {url}: {e}")
            return None

    def _take_screenshot_playwright(self, url: str, filepath: str, delay: int = 2) -> bool:
        """
        Erstellt einen Screenshot mit Playwright.

        Args:
            url: Die URL, von der ein Screenshot erstellt werden soll.
            filepath: Der Pfad, unter dem der Screenshot gespeichert werden soll.
            delay: Verzögerung in Sekunden vor dem Screenshot.

        Returns:
            True bei Erfolg, False bei Fehler.
        """
        try:
            with sync_playwright() as playwright:
                if self.browser_type == "chrome":
                    browser = playwright.chromium.launch(headless=self.headless)
                elif self.browser_type == "firefox":
                    browser = playwright.firefox.launch(headless=self.headless)
                elif self.browser_type == "webkit":
                    browser = playwright.webkit.launch(headless=self.headless)
                else:
                    browser = playwright.chromium.launch(headless=self.headless)
                
                context = browser.new_context(
                    viewport={"width": self.width, "height": self.height}
                )
                page = context.new_page()
                
                # Navigiere zur URL
                page.goto(url, timeout=self.timeout * 1000)
                
                # Warte auf die angegebene Verzögerung
                page.wait_for_timeout(delay * 1000)
                
                # Erstelle den Screenshot
                page.screenshot(path=filepath)
                
                # Schließe den Browser
                context.close()
                browser.close()
                
                return True
                
        except Exception as e:
            logger.error(f"Playwright-Fehler: {e}")
            return False

    def _take_screenshot_selenium(self, url: str, filepath: str, delay: int = 2) -> bool:
        """
        Erstellt einen Screenshot mit Selenium.

        Args:
            url: Die URL, von der ein Screenshot erstellt werden soll.
            filepath: Der Pfad, unter dem der Screenshot gespeichert werden soll.
            delay: Verzögerung in Sekunden vor dem Screenshot.

        Returns:
            True bei Erfolg, False bei Fehler.
        """
        driver = None
        try:
            # Initialisiere den Browser-Treiber
            if self.browser_type == "chrome":
                options = ChromeOptions()
                if self.headless:
                    options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument(f"--window-size={self.width},{self.height}")
                driver = webdriver.Chrome(options=options)
            elif self.browser_type == "firefox":
                options = FirefoxOptions()
                if self.headless:
                    options.add_argument("--headless")
                driver = webdriver.Firefox(options=options)
            else:
                options = ChromeOptions()
                if self.headless:
                    options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument(f"--window-size={self.width},{self.height}")
                driver = webdriver.Chrome(options=options)
            
            # Setze Timeout
            driver.set_page_load_timeout(self.timeout)
            
            # Navigiere zur URL
            driver.get(url)
            
            # Warte auf die angegebene Verzögerung
            time.sleep(delay)
            
            # Erstelle den Screenshot
            driver.save_screenshot(filepath)
            
            # Schließe den Browser
            driver.quit()
            
            return True
            
        except Exception as e:
            logger.error(f"Selenium-Fehler: {e}")
            if driver:
                driver.quit()
            return False

    def _save_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        Speichert Metadaten zu einem Screenshot.

        Args:
            metadata: Die zu speichernden Metadaten.
        """
        try:
            # Erstelle die Metadaten-Datei
            metadata_file = os.path.join(self.screenshot_dir, "metadata.txt")
            
            # Formatiere die Metadaten
            formatted_metadata = (
                f"URL: {metadata['url']}\n"
                f"Timestamp: {metadata['timestamp']}\n"
                f"Date: {datetime.fromtimestamp(metadata['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Payload: {metadata['payload'] or 'N/A'}\n"
                f"Filename: {metadata['filename']}\n"
                f"---\n"
            )
            
            # Schreibe die Metadaten in die Datei
            with open(metadata_file, "a") as f:
                f.write(formatted_metadata)
                
        except Exception as e:
            logger.error(f"Fehler beim Speichern der Metadaten: {e}")

    def get_screenshots(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Gibt eine Liste der letzten Screenshots zurück.

        Args:
            limit: Maximale Anzahl der zurückzugebenden Screenshots.

        Returns:
            Eine Liste von Screenshot-Metadaten.
        """
        try:
            # Lese die Metadaten-Datei
            metadata_file = os.path.join(self.screenshot_dir, "metadata.txt")
            if not os.path.exists(metadata_file):
                return []
                
            with open(metadata_file, "r") as f:
                content = f.read()
                
            # Parse die Metadaten
            entries = content.split("---\n")
            screenshots = []
            
            for entry in entries:
                if not entry.strip():
                    continue
                    
                metadata = {}
                for line in entry.strip().split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        metadata[key.strip()] = value.strip()
                
                if "Filename" in metadata:
                    filepath = os.path.join(self.screenshot_dir, "screenshots", metadata["Filename"])
                    if os.path.exists(filepath):
                        metadata["filepath"] = filepath
                        screenshots.append(metadata)
            
            # Sortiere nach Timestamp (absteigend)
            screenshots.sort(key=lambda x: int(x.get("Timestamp", 0)), reverse=True)
            
            # Begrenze die Anzahl
            return screenshots[:limit]
                
        except Exception as e:
            logger.error(f"Fehler beim Abrufen der Screenshots: {e}")
            return []

    def get_screenshot_as_base64(self, filename: str) -> Optional[str]:
        """
        Gibt einen Screenshot als Base64-kodiertes Bild zurück.

        Args:
            filename: Der Dateiname des Screenshots.

        Returns:
            Der Base64-kodierte Screenshot oder None bei Fehler.
        """
        try:
            filepath = os.path.join(self.screenshot_dir, "screenshots", filename)
            if not os.path.exists(filepath):
                return None
                
            with open(filepath, "rb") as f:
                image_data = f.read()
                
            return base64.b64encode(image_data).decode("utf-8")
                
        except Exception as e:
            logger.error(f"Fehler beim Abrufen des Screenshots als Base64: {e}")
            return None

    def cleanup_old_screenshots(self, max_age_days: int = 30) -> int:
        """
        Löscht alte Screenshots.

        Args:
            max_age_days: Maximales Alter der Screenshots in Tagen.

        Returns:
            Die Anzahl der gelöschten Screenshots.
        """
        try:
            # Berechne den Timestamp für das maximale Alter
            max_age_timestamp = int(time.time()) - (max_age_days * 24 * 60 * 60)
            
            # Lese die Metadaten-Datei
            metadata_file = os.path.join(self.screenshot_dir, "metadata.txt")
            if not os.path.exists(metadata_file):
                return 0
                
            with open(metadata_file, "r") as f:
                content = f.read()
                
            # Parse die Metadaten
            entries = content.split("---\n")
            new_entries = []
            deleted_count = 0
            
            for entry in entries:
                if not entry.strip():
                    continue
                    
                metadata = {}
                for line in entry.strip().split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        metadata[key.strip()] = value.strip()
                
                if "Timestamp" in metadata and "Filename" in metadata:
                    timestamp = int(metadata["Timestamp"])
                    filename = metadata["Filename"]
                    
                    if timestamp < max_age_timestamp:
                        # Lösche den Screenshot
                        filepath = os.path.join(self.screenshot_dir, "screenshots", filename)
                        if os.path.exists(filepath):
                            os.remove(filepath)
                            deleted_count += 1
                    else:
                        # Behalte den Eintrag
                        new_entries.append(entry + "---\n")
            
            # Schreibe die aktualisierten Metadaten zurück
            with open(metadata_file, "w") as f:
                f.write("".join(new_entries))
                
            return deleted_count
                
        except Exception as e:
            logger.error(f"Fehler beim Bereinigen alter Screenshots: {e}")
            return 0


# Beispiel für die Verwendung
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(level=logging.INFO)
    
    # Erstelle den Screenshot-Manager
    config = {
        "screenshot_dir": "screenshots",
        "browser_type": "chrome",
        "headless": True,
        "width": 1366,
        "height": 768,
        "timeout": 30
    }
    manager = ScreenshotManager(config)
    
    # Erstelle einen Screenshot
    url = "https://example.com"
    filepath = manager.take_screenshot(url, payload="<script>alert(1)</script>")
    
    if filepath:
        print(f"Screenshot erstellt: {filepath}")
    else:
        print("Fehler beim Erstellen des Screenshots")
