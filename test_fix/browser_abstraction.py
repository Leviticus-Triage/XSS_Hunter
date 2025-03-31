#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Browser Abstraction
============================================

Diese Datei implementiert die Browser-Abstraktionsschicht für das XSS Hunter Framework.
Sie bietet eine einheitliche Schnittstelle für verschiedene Browser-Automatisierungstools.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import logging
import time
import json
import tempfile
import subprocess
from typing import Dict, List, Optional, Any, Tuple, Union

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.BrowserAbstraction")


class BrowserBase:
    """Basisklasse für Browser-Abstraktionen."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialisiert die Browser-Abstraktion.

        Args:
            config: Die Konfiguration für den Browser.
        """
        self.config = config or {}
        self.browser = None
        self.driver = None
        self.headless = self.config.get("headless", True)
        self.width = self.config.get("width", 1366)
        self.height = self.config.get("height", 768)
        self.timeout = self.config.get("timeout", 30)
        self.user_agent = self.config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        
        logger.info(f"Browser-Abstraktion initialisiert: {self.__class__.__name__}")

    def setup(self) -> bool:
        """
        Richtet den Browser ein.

        Returns:
            True, wenn die Einrichtung erfolgreich war, sonst False.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def teardown(self) -> None:
        """Beendet den Browser."""
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def navigate(self, url: str) -> bool:
        """
        Navigiert zu einer URL.

        Args:
            url: Die URL, zu der navigiert werden soll.

        Returns:
            True, wenn die Navigation erfolgreich war, sonst False.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def get_page_source(self) -> str:
        """
        Gibt den Quellcode der aktuellen Seite zurück.

        Returns:
            Der Quellcode der aktuellen Seite.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def get_cookies(self) -> List[Dict[str, Any]]:
        """
        Gibt die Cookies der aktuellen Seite zurück.

        Returns:
            Die Cookies der aktuellen Seite.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def set_cookies(self, cookies: List[Dict[str, Any]]) -> bool:
        """
        Setzt die Cookies für die aktuelle Seite.

        Args:
            cookies: Die zu setzenden Cookies.

        Returns:
            True, wenn das Setzen erfolgreich war, sonst False.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def execute_script(self, script: str) -> Any:
        """
        Führt JavaScript-Code auf der aktuellen Seite aus.

        Args:
            script: Der auszuführende JavaScript-Code.

        Returns:
            Das Ergebnis der Ausführung.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def take_screenshot(self, output_path: str = None) -> Optional[str]:
        """
        Erstellt einen Screenshot der aktuellen Seite.

        Args:
            output_path: Der Pfad, unter dem der Screenshot gespeichert werden soll.

        Returns:
            Der Pfad zum Screenshot oder None bei Fehler.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def find_element(self, selector: str, by: str = "css") -> Any:
        """
        Findet ein Element auf der aktuellen Seite.

        Args:
            selector: Der Selektor für das Element.
            by: Die Methode, mit der das Element gefunden werden soll (css, xpath, id, etc.).

        Returns:
            Das gefundene Element oder None bei Fehler.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def find_elements(self, selector: str, by: str = "css") -> List[Any]:
        """
        Findet mehrere Elemente auf der aktuellen Seite.

        Args:
            selector: Der Selektor für die Elemente.
            by: Die Methode, mit der die Elemente gefunden werden sollen (css, xpath, id, etc.).

        Returns:
            Die gefundenen Elemente oder eine leere Liste bei Fehler.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def click_element(self, element: Any) -> bool:
        """
        Klickt auf ein Element.

        Args:
            element: Das zu klickende Element.

        Returns:
            True, wenn der Klick erfolgreich war, sonst False.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def send_keys(self, element: Any, keys: str) -> bool:
        """
        Sendet Tastatureingaben an ein Element.

        Args:
            element: Das Element, an das die Eingaben gesendet werden sollen.
            keys: Die zu sendenden Tastatureingaben.

        Returns:
            True, wenn das Senden erfolgreich war, sonst False.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def wait_for_element(self, selector: str, by: str = "css", timeout: int = None) -> Any:
        """
        Wartet auf ein Element.

        Args:
            selector: Der Selektor für das Element.
            by: Die Methode, mit der das Element gefunden werden soll (css, xpath, id, etc.).
            timeout: Die maximale Wartezeit in Sekunden.

        Returns:
            Das gefundene Element oder None bei Timeout.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")

    def wait_for_page_load(self, timeout: int = None) -> bool:
        """
        Wartet auf das Laden der Seite.

        Args:
            timeout: Die maximale Wartezeit in Sekunden.

        Returns:
            True, wenn die Seite geladen wurde, sonst False.
        """
        raise NotImplementedError("Diese Methode muss von abgeleiteten Klassen implementiert werden")


class SeleniumBrowser(BrowserBase):
    """Browser-Abstraktion für Selenium."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialisiert die Selenium-Browser-Abstraktion.

        Args:
            config: Die Konfiguration für den Browser.
        """
        super().__init__(config)
        self.browser_type = self.config.get("browser_type", "chrome").lower()
        
        # Prüfe, ob Selenium installiert ist
        try:
            import selenium
            logger.info(f"Selenium {selenium.__version__} gefunden")
        except ImportError:
            logger.warning("Selenium nicht gefunden, versuche zu installieren...")
            self._install_selenium()

    def _install_selenium(self) -> bool:
        """
        Installiert Selenium.

        Returns:
            True, wenn die Installation erfolgreich war, sonst False.
        """
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "selenium"])
            logger.info("Selenium erfolgreich installiert")
            return True
        except Exception as e:
            logger.error(f"Fehler bei der Installation von Selenium: {e}")
            return False

    def setup(self) -> bool:
        """
        Richtet den Selenium-Browser ein.

        Returns:
            True, wenn die Einrichtung erfolgreich war, sonst False.
        """
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options as ChromeOptions
            from selenium.webdriver.firefox.options import Options as FirefoxOptions
            from selenium.webdriver.edge.options import Options as EdgeOptions
            
            if self.browser_type == "chrome":
                options = ChromeOptions()
                if self.headless:
                    options.add_argument("--headless")
                options.add_argument(f"--window-size={self.width},{self.height}")
                options.add_argument(f"--user-agent={self.user_agent}")
                options.add_argument("--disable-gpu")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                
                self.driver = webdriver.Chrome(options=options)
                
            elif self.browser_type == "firefox":
                options = FirefoxOptions()
                if self.headless:
                    options.add_argument("--headless")
                options.add_argument(f"--width={self.width}")
                options.add_argument(f"--height={self.height}")
                
                profile = webdriver.FirefoxProfile()
                profile.set_preference("general.useragent.override", self.user_agent)
                
                self.driver = webdriver.Firefox(options=options, firefox_profile=profile)
                
            elif self.browser_type == "edge":
                options = EdgeOptions()
                if self.headless:
                    options.add_argument("--headless")
                options.add_argument(f"--window-size={self.width},{self.height}")
                options.add_argument(f"--user-agent={self.user_agent}")
                
                self.driver = webdriver.Edge(options=options)
                
            else:
                logger.error(f"Nicht unterstützter Browser-Typ: {self.browser_type}")
                return False
                
            self.driver.set_page_load_timeout(self.timeout)
            logger.info(f"Selenium-Browser ({self.browser_type}) erfolgreich eingerichtet")
            return True
            
        except Exception as e:
            logger.error(f"Fehler bei der Einrichtung des Selenium-Browsers: {e}")
            return False

    def teardown(self) -> None:
        """Beendet den Selenium-Browser."""
        try:
            if self.driver:
                self.driver.quit()
                self.driver = None
                logger.info("Selenium-Browser beendet")
        except Exception as e:
            logger.error(f"Fehler beim Beenden des Selenium-Browsers: {e}")

    def navigate(self, url: str) -> bool:
        """
        Navigiert zu einer URL mit Selenium.

        Args:
            url: Die URL, zu der navigiert werden soll.

        Returns:
            True, wenn die Navigation erfolgreich war, sonst False.
        """
        try:
            if not self.driver:
                if not self.setup():
                    return False
                    
            self.driver.get(url)
            logger.info(f"Zu URL navigiert: {url}")
            return True
            
        except Exception as e:
            logger.error(f"Fehler bei der Navigation zu {url}: {e}")
            return False

    def get_page_source(self) -> str:
        """
        Gibt den Quellcode der aktuellen Seite mit Selenium zurück.

        Returns:
            Der Quellcode der aktuellen Seite.
        """
        try:
            if not self.driver:
                if not self.setup():
                    return ""
                    
            return self.driver.page_source
            
        except Exception as e:
            logger.error(f"Fehler beim Abrufen des Quellcodes: {e}")
            return ""

    def get_cookies(self) -> List[Dict[str, Any]]:
        """
        Gibt die Cookies der aktuellen Seite mit Selenium zurück.

        Returns:
            Die Cookies der aktuellen Seite.
        """
        try:
            if not self.driver:
                if not self.setup():
                    return []
                    
            return self.driver.get_cookies()
            
        except Exception as e:
            logger.error(f"Fehler beim Abrufen der Cookies: {e}")
            return []

    def set_cookies(self, cookies: List[Dict[str, Any]]) -> bool:
        """
        Setzt die Cookies für die aktuelle Seite mit Selenium.

        Args:
            cookies: Die zu setzenden Cookies.

        Returns:
            True, wenn das Setzen erfolgreich war, sonst False.
        """
        try:
            if not self.driver:
                if not self.setup():
                    return False
                    
            for cookie in cookies:
                self.driver.add_cookie(cookie)
                
            logger.info(f"{len(cookies)} Cookies gesetzt")
            return True
            
        except Exception as e:
            logger.error(f"Fehler beim Setzen der Cookies: {e}")
            return False

    def execute_script(self, script: str) -> Any:
        """
        Führt JavaScript-Code auf der aktuellen Seite mit Selenium aus.

        Args:
            script: Der auszuführende JavaScript-Code.

        Returns:
            Das Ergebnis der Ausführung.
        """
        try:
            if not self.driver:
                if not self.setup():
                    return None
                    
            return self.driver.execute_script(script)
            
        except Exception as e:
            logger.error(f"Fehler bei der Ausführung des Scripts: {e}")
            return None

    def take_screenshot(self, output_path: str = None) -> Optional[str]:
        """
        Erstellt einen Screenshot der aktuellen Seite mit Selenium.

        Args:
            output_path: Der Pfad, unter dem der Screenshot gespeichert werden soll.

        Returns:
            Der Pfad zum Screenshot oder None bei Fehler.
        """
        try:
            if not self.driver:
                if not self.setup():
                    return None
                    
            if not output_path:
                # Erstelle einen temporären Dateinamen
                temp_dir = tempfile.gettempdir()
                output_path = os.path.join(temp_dir, f"screenshot_{int(time.time())}.png")
                
            self.driver.save_screenshot(output_path)
            logger.info(f"Screenshot erstellt: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des Screenshots: {e}")
            return None

    def find_element(self, selector: str, by: str = "css") -> Any:
        """
        Findet ein Element auf der aktuellen Seite mit Selenium.

        Args:
            selector: Der Selektor für das Element.
            by: Die Methode, mit der das Element gefunden werden soll (css, xpath, id, etc.).

        Returns:
            Das gefundene Element oder None bei Fehler.
        """
        try:
            if not self.driver:
                if not self.setup():
                    return None
                    
            from selenium.webdriver.common.by import By
            
            by_map = {
                "css": By.CSS_SELECTOR,
                "xpath": By.XPATH,
                "id": By.ID,
                "name": By.NAME,
                "tag": By.TAG_NAME,
                "class": By.CLASS_NAME,
                "link_text": By.LINK_TEXT,
                "partial_link_text": By.PARTIAL_LINK_TEXT
            }
            
            by_method = by_map.get(by.lower(), By.CSS_SELECTOR)
            
            return self.driver.find_element(by_method, selector)
            
        except Exception as e:
            logger.debug(f"Element nicht gefunden: {selector} (by={by}): {e}")
            return None

    def find_elements(self, selector: str, by: str = "css") -> List[Any]:
        """
        Findet mehrere Elemente auf der aktuellen Seite mit Selenium.

        Args:
            selector: Der Selektor für die Elemente.
            by: Die Methode, mit der die Elemente gefunden werden sollen (css, xpath, id, etc.).

        Returns:
            Die gefundenen Elemente oder eine leere Liste bei Fehler.
        """
        try:
            if not self.driver:
                if not self.setup():
                    return []
                    
            from selenium.webdriver.common.by import By
            
            by_map = {
                "css": By.CSS_SELECTOR,
                "xpath": By.XPATH,
                "id": By.ID,
                "name": By.NAME,
                "tag": By.TAG_NAME,
                "class": By.CLASS_NAME,
                "link_text": By.LINK_TEXT,
                "partial_link_text": By.PARTIAL_LINK_TEXT
            }
            
            by_method = by_map.get(by.lower(), By.CSS_SELECTOR)
            
            return self.driver.find_elements(by_method, selector)
            
        except Exception as e:
            logger.debug(f"Elemente nicht gefunden: {selector} (by={by}): {e}")
            return []

    def click_element(self, element: Any) -> bool:
        """
        Klickt auf ein Element mit Selenium.

        Args:
            element: Das zu klickende Element.

        Returns:
            True, wenn der Klick erfolgreich war, sonst False.
        """
        try:
            if not element:
                return False
                
            element.click()
            return True
            
        except Exception as e:
            logger.error(f"Fehler beim Klicken auf das Element: {e}")
            return False

    def send_keys(self, element: Any, keys: str) -> bool:
        """
        Sendet Tastatureingaben an ein Element mit Selenium.

        Args:
            element: Das Element, an das die Eingaben gesendet werden sollen.
            keys: Die zu sendenden Tastatureingaben.

        Returns:
            True, wenn das Senden erfolgreich war, sonst False.
        """
        try:
            if not element:
                return False
                
            element.send_keys(keys)
            return True
            
        except Exception as e:
            logger.error(f"Fehler beim Senden von Tastatureingaben: {e}")
            return False

    def wait_for_element(self, selector: str, by: str = "css", timeout: int = None) -> Any:
        """
        Wartet auf ein Element mit Selenium.

        Args:
            selector: Der Selektor für das Element.
            by: Die Methode, mit der das Element gefunden werden soll (css, xpath, id, etc.).
            timeout: Die maximale Wartezeit in Sekunden.

        Returns:
            Das gefundene Element oder None bei Timeout.
        """
        try:
            if not self.driver:
                if not self.setup():
                    return None
                    
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.common.by import By
            
            by_map = {
                "css": By.CSS_SELECTOR,
                "xpath": By.XPATH,
                "id": By.ID,
                "name": By.NAME,
                "tag": By.TAG_NAME,
                "class": By.CLASS_NAME,
                "link_text": By.LINK_TEXT,
                "partial_link_text": By.PARTIAL_LINK_TEXT
            }
            
            by_method = by_map.get(by.lower(), By.CSS_SELECTOR)
            
            if timeout is None:
                timeout = self.timeout
                
            wait = WebDriverWait(self.driver, timeout)
            return wait.until(EC.presence_of_element_located((by_method, selector)))
            
        except Exception as e:
            logger.debug(f"Timeout beim Warten auf Element: {selector} (by={by}): {e}")
            return None

    def wait_for_page_load(self, timeout: int = None) -> bool:
        """
        Wartet auf das Laden der Seite mit Selenium.

        Args:
            timeout: Die maximale Wartezeit in Sekunden.

        Returns:
            True, wenn die Seite geladen wurde, sonst False.
        """
        try:
            if not self.driver:
                if not self.setup():
                    return False
                    
            from selenium.webdriver.support.ui import WebDriverWait
            
            if timeout is None:
                timeout = self.timeout
                
            def page_has_loaded(driver):
                return driver.execute_script("return document.readyState") == "complete"
                
            wait = WebDriverWait(self.driver, timeout)
            wait.until(page_has_loaded)
            return True
            
        except Exception as e:
            logger.error(f"Timeout beim Warten auf das Laden der Seite: {e}")
            return False


class PlaywrightBrowser(BrowserBase):
    """Browser-Abstraktion für Playwright."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialisiert die Playwright-Browser-Abstraktion.

        Args:
            config: Die Konfiguration für den Browser.
        """
        super().__init__(config)
        self.browser_type = self.config.get("browser_type", "chromium").lower()
        self.context = None
        self.page = None
        
        # Prüfe, ob Playwright installiert ist
        try:
            import playwright
            logger.info(f"Playwright gefunden")
        except ImportError:
            logger.warning("Playwright nicht gefunden, versuche zu installieren...")
            self._install_playwright()

    def _install_playwright(self) -> bool:
        """
        Installiert Playwright.

        Returns:
            True, wenn die Installation erfolgreich war, sonst False.
        """
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "playwright"])
            subprocess.check_call([sys.executable, "-m", "playwright", "install"])
            logger.info("Playwright erfolgreich installiert")
            return True
        except Exception as e:
            logger.error(f"Fehler bei der Installation von Playwright: {e}")
            return False

    def setup(self) -> bool:
        """
        Richtet den Playwright-Browser ein.

        Returns:
            True, wenn die Einrichtung erfolgreich war, sonst False.
        """
        try:
            from playwright.sync_api import sync_playwright
            
            playwright_instance = sync_playwright().start()
            
            if self.browser_type == "chromium":
                self.browser = playwright_instance.chromium.launch(headless=self.headless)
            elif self.browser_type == "firefox":
                self.browser = playwright_instance.firefox.launch(headless=self.headless)
            elif self.browser_type == "webkit":
                self.browser = playwright_instance.webkit.launch(headless=self.headless)
            else:
                logger.error(f"Nicht unterstützter Browser-Typ: {self.browser_type}")
                return False
                
            self.context = self.browser.new_context(
                viewport={"width": self.width, "height": self.height},
                user_agent=self.user_agent
            )
            
            self.page = self.context.new_page()
            self.page.set_default_timeout(self.timeout * 1000)  # Playwright verwendet Millisekunden
            
            logger.info(f"Playwright-Browser ({self.browser_type}) erfolgreich eingerichtet")
            return True
            
        except Exception as e:
            logger.error(f"Fehler bei der Einrichtung des Playwright-Browsers: {e}")
            return False

    def teardown(self) -> None:
        """Beendet den Playwright-Browser."""
        try:
            if self.page:
                self.page.close()
                self.page = None
                
            if self.context:
                self.context.close()
                self.context = None
                
            if self.browser:
                self.browser.close()
                self.browser = None
                
            logger.info("Playwright-Browser beendet")
        except Exception as e:
            logger.error(f"Fehler beim Beenden des Playwright-Browsers: {e}")

    def navigate(self, url: str) -> bool:
        """
        Navigiert zu einer URL mit Playwright.

        Args:
            url: Die URL, zu der navigiert werden soll.

        Returns:
            True, wenn die Navigation erfolgreich war, sonst False.
        """
        try:
            if not self.page:
                if not self.setup():
                    return False
                    
            self.page.goto(url, wait_until="networkidle")
            logger.info(f"Zu URL navigiert: {url}")
            return True
            
        except Exception as e:
            logger.error(f"Fehler bei der Navigation zu {url}: {e}")
            return False

    def get_page_source(self) -> str:
        """
        Gibt den Quellcode der aktuellen Seite mit Playwright zurück.

        Returns:
            Der Quellcode der aktuellen Seite.
        """
        try:
            if not self.page:
                if not self.setup():
                    return ""
                    
            return self.page.content()
            
        except Exception as e:
            logger.error(f"Fehler beim Abrufen des Quellcodes: {e}")
            return ""

    def get_cookies(self) -> List[Dict[str, Any]]:
        """
        Gibt die Cookies der aktuellen Seite mit Playwright zurück.

        Returns:
            Die Cookies der aktuellen Seite.
        """
        try:
            if not self.context:
                if not self.setup():
                    return []
                    
            return self.context.cookies()
            
        except Exception as e:
            logger.error(f"Fehler beim Abrufen der Cookies: {e}")
            return []

    def set_cookies(self, cookies: List[Dict[str, Any]]) -> bool:
        """
        Setzt die Cookies für die aktuelle Seite mit Playwright.

        Args:
            cookies: Die zu setzenden Cookies.

        Returns:
            True, wenn das Setzen erfolgreich war, sonst False.
        """
        try:
            if not self.context:
                if not self.setup():
                    return False
                    
            self.context.add_cookies(cookies)
            logger.info(f"{len(cookies)} Cookies gesetzt")
            return True
            
        except Exception as e:
            logger.error(f"Fehler beim Setzen der Cookies: {e}")
            return False

    def execute_script(self, script: str) -> Any:
        """
        Führt JavaScript-Code auf der aktuellen Seite mit Playwright aus.

        Args:
            script: Der auszuführende JavaScript-Code.

        Returns:
            Das Ergebnis der Ausführung.
        """
        try:
            if not self.page:
                if not self.setup():
                    return None
                    
            return self.page.evaluate(script)
            
        except Exception as e:
            logger.error(f"Fehler bei der Ausführung des Scripts: {e}")
            return None

    def take_screenshot(self, output_path: str = None) -> Optional[str]:
        """
        Erstellt einen Screenshot der aktuellen Seite mit Playwright.

        Args:
            output_path: Der Pfad, unter dem der Screenshot gespeichert werden soll.

        Returns:
            Der Pfad zum Screenshot oder None bei Fehler.
        """
        try:
            if not self.page:
                if not self.setup():
                    return None
                    
            if not output_path:
                # Erstelle einen temporären Dateinamen
                temp_dir = tempfile.gettempdir()
                output_path = os.path.join(temp_dir, f"screenshot_{int(time.time())}.png")
                
            self.page.screenshot(path=output_path, full_page=True)
            logger.info(f"Screenshot erstellt: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des Screenshots: {e}")
            return None

    def find_element(self, selector: str, by: str = "css") -> Any:
        """
        Findet ein Element auf der aktuellen Seite mit Playwright.

        Args:
            selector: Der Selektor für das Element.
            by: Die Methode, mit der das Element gefunden werden soll (css, xpath, id, etc.).

        Returns:
            Das gefundene Element oder None bei Fehler.
        """
        try:
            if not self.page:
                if not self.setup():
                    return None
                    
            if by.lower() == "xpath":
                return self.page.locator(f"xpath={selector}").first
            elif by.lower() == "id":
                return self.page.locator(f"#{selector}").first
            elif by.lower() == "name":
                return self.page.locator(f"[name='{selector}']").first
            elif by.lower() == "tag":
                return self.page.locator(selector).first
            elif by.lower() == "class":
                return self.page.locator(f".{selector}").first
            elif by.lower() == "link_text":
                return self.page.get_by_text(selector).first
            else:  # css
                return self.page.locator(selector).first
                
        except Exception as e:
            logger.debug(f"Element nicht gefunden: {selector} (by={by}): {e}")
            return None

    def find_elements(self, selector: str, by: str = "css") -> List[Any]:
        """
        Findet mehrere Elemente auf der aktuellen Seite mit Playwright.

        Args:
            selector: Der Selektor für die Elemente.
            by: Die Methode, mit der die Elemente gefunden werden sollen (css, xpath, id, etc.).

        Returns:
            Die gefundenen Elemente oder eine leere Liste bei Fehler.
        """
        try:
            if not self.page:
                if not self.setup():
                    return []
                    
            if by.lower() == "xpath":
                return self.page.locator(f"xpath={selector}").all()
            elif by.lower() == "id":
                return self.page.locator(f"#{selector}").all()
            elif by.lower() == "name":
                return self.page.locator(f"[name='{selector}']").all()
            elif by.lower() == "tag":
                return self.page.locator(selector).all()
            elif by.lower() == "class":
                return self.page.locator(f".{selector}").all()
            elif by.lower() == "link_text":
                return self.page.get_by_text(selector).all()
            else:  # css
                return self.page.locator(selector).all()
                
        except Exception as e:
            logger.debug(f"Elemente nicht gefunden: {selector} (by={by}): {e}")
            return []

    def click_element(self, element: Any) -> bool:
        """
        Klickt auf ein Element mit Playwright.

        Args:
            element: Das zu klickende Element.

        Returns:
            True, wenn der Klick erfolgreich war, sonst False.
        """
        try:
            if not element:
                return False
                
            element.click()
            return True
            
        except Exception as e:
            logger.error(f"Fehler beim Klicken auf das Element: {e}")
            return False

    def send_keys(self, element: Any, keys: str) -> bool:
        """
        Sendet Tastatureingaben an ein Element mit Playwright.

        Args:
            element: Das Element, an das die Eingaben gesendet werden sollen.
            keys: Die zu sendenden Tastatureingaben.

        Returns:
            True, wenn das Senden erfolgreich war, sonst False.
        """
        try:
            if not element:
                return False
                
            element.fill(keys)
            return True
            
        except Exception as e:
            logger.error(f"Fehler beim Senden von Tastatureingaben: {e}")
            return False

    def wait_for_element(self, selector: str, by: str = "css", timeout: int = None) -> Any:
        """
        Wartet auf ein Element mit Playwright.

        Args:
            selector: Der Selektor für das Element.
            by: Die Methode, mit der das Element gefunden werden soll (css, xpath, id, etc.).
            timeout: Die maximale Wartezeit in Sekunden.

        Returns:
            Das gefundene Element oder None bei Timeout.
        """
        try:
            if not self.page:
                if not self.setup():
                    return None
                    
            if timeout is None:
                timeout = self.timeout
                
            if by.lower() == "xpath":
                locator = self.page.locator(f"xpath={selector}")
            elif by.lower() == "id":
                locator = self.page.locator(f"#{selector}")
            elif by.lower() == "name":
                locator = self.page.locator(f"[name='{selector}']")
            elif by.lower() == "tag":
                locator = self.page.locator(selector)
            elif by.lower() == "class":
                locator = self.page.locator(f".{selector}")
            elif by.lower() == "link_text":
                locator = self.page.get_by_text(selector)
            else:  # css
                locator = self.page.locator(selector)
                
            locator.wait_for(timeout=timeout * 1000)  # Playwright verwendet Millisekunden
            return locator.first
            
        except Exception as e:
            logger.debug(f"Timeout beim Warten auf Element: {selector} (by={by}): {e}")
            return None

    def wait_for_page_load(self, timeout: int = None) -> bool:
        """
        Wartet auf das Laden der Seite mit Playwright.

        Args:
            timeout: Die maximale Wartezeit in Sekunden.

        Returns:
            True, wenn die Seite geladen wurde, sonst False.
        """
        try:
            if not self.page:
                if not self.setup():
                    return False
                    
            if timeout is None:
                timeout = self.timeout
                
            self.page.wait_for_load_state("networkidle", timeout=timeout * 1000)  # Playwright verwendet Millisekunden
            return True
            
        except Exception as e:
            logger.error(f"Timeout beim Warten auf das Laden der Seite: {e}")
            return False


def create_browser(browser_type: str = "selenium", config: Dict[str, Any] = None) -> BrowserBase:
    """
    Erstellt eine Browser-Instanz.

    Args:
        browser_type: Der Typ des Browsers ("selenium" oder "playwright").
        config: Die Konfiguration für den Browser.

    Returns:
        Eine Browser-Instanz.
    """
    if browser_type.lower() == "playwright":
        return PlaywrightBrowser(config)
    else:  # selenium
        return SeleniumBrowser(config)


# Beispiel für die Verwendung
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(level=logging.INFO)
    
    # Erstelle eine Browser-Instanz
    browser = create_browser("selenium", {
        "headless": True,
        "width": 1366,
        "height": 768,
        "timeout": 30,
        "browser_type": "chrome"
    })
    
    try:
        # Richte den Browser ein
        if browser.setup():
            # Navigiere zu einer URL
            if browser.navigate("https://example.com"):
                # Erstelle einen Screenshot
                screenshot_path = browser.take_screenshot()
                if screenshot_path:
                    print(f"Screenshot erstellt: {screenshot_path}")
                    
                # Führe JavaScript aus
                title = browser.execute_script("return document.title")
                print(f"Seitentitel: {title}")
                
                # Finde ein Element
                element = browser.find_element("h1")
                if element:
                    print(f"Überschrift gefunden: {element.text_content() if hasattr(element, 'text_content') else element.text}")
    finally:
        # Beende den Browser
        browser.teardown()
