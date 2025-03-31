#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Modules - Target Discovery
====================================================

Dieses Modul implementiert die Erkennung und Analyse von Zielen für XSS-Tests.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import json
import logging
import time
import re
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.TargetDiscovery")

# Versuche, den Error Handler zu importieren
try:
    from error_handler import handle_exception, log_error
except ImportError:
    logger.warning("Error Handler konnte nicht importiert werden. Verwende einfache Fehlerbehandlung.")
    
    # Einfache Fehlerbehandlung
    def handle_exception(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Fehler: {e}")
                return None
        return wrapper
    
    def log_error(error, error_type="UNKNOWN_ERROR", details=None):
        logger.error(f"{error_type}: {error}")
        if details:
            logger.error(f"Details: {details}")

# Versuche, die Utility-Funktionen zu importieren
try:
    from utils import (
        is_valid_url, normalize_url, extract_params_from_url, extract_forms_from_html,
        load_json_file, save_json_file, get_timestamp, format_timestamp
    )
except ImportError:
    logger.warning("Utils-Modul konnte nicht importiert werden. Verwende einfache Implementierungen.")
    
    # Einfache Implementierungen der benötigten Funktionen
    def is_valid_url(url):
        return bool(url and url.startswith(("http://", "https://")))
    
    def normalize_url(url):
        return url
    
    def extract_params_from_url(url):
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        return list(query_params.keys())
    
    def extract_forms_from_html(html):
        return []
    
    def load_json_file(file_path):
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Fehler beim Laden der JSON-Datei: {e}")
            return {}
    
    def save_json_file(data, file_path):
        try:
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Fehler beim Speichern der JSON-Datei: {e}")
            return False
    
    def get_timestamp():
        return int(time.time())
    
    def format_timestamp(timestamp, format="%Y-%m-%d %H:%M:%S"):
        return time.strftime(format, time.localtime(timestamp))

# Versuche, Requests zu importieren
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    logger.warning("Requests-Modul konnte nicht importiert werden. HTTP-Anfragen werden eingeschränkt sein.")
    REQUESTS_AVAILABLE = False
    
    # Einfache HTTP-Anfrage-Funktion als Fallback
    class Response:
        def __init__(self, status_code=200, text="", headers=None, url=""):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}
            self.url = url
    
    def requests_get(url, headers=None, params=None, timeout=10):
        logger.error("Requests-Modul ist nicht verfügbar. GET-Anfrage kann nicht durchgeführt werden.")
        return Response(status_code=500, text="Requests module not available", url=url)

# Versuche, BeautifulSoup zu importieren
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    logger.warning("BeautifulSoup-Modul konnte nicht importiert werden. HTML-Parsing wird eingeschränkt sein.")
    BS4_AVAILABLE = False

# Versuche, Selenium zu importieren
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    logger.warning("Selenium-Modul konnte nicht importiert werden. Browser-Automatisierung wird nicht verfügbar sein.")
    SELENIUM_AVAILABLE = False


class TargetDiscovery:
    """
    Klasse für die Erkennung und Analyse von Zielen für XSS-Tests.
    """
    
    def __init__(self, user_agent=None, proxy=None, timeout=10, max_depth=3):
        """
        Initialisiert die Target Discovery.
        
        Args:
            user_agent: Der zu verwendende User-Agent.
            proxy: Der zu verwendende Proxy.
            timeout: Das Timeout für HTTP-Anfragen.
            max_depth: Die maximale Tiefe für die Crawling-Funktion.
        """
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.proxy = proxy
        self.timeout = timeout
        self.max_depth = max_depth
        
        # Initialisiere den Browser, falls Selenium verfügbar ist
        self.browser = None
        
        if SELENIUM_AVAILABLE:
            try:
                self._init_browser()
            except Exception as e:
                log_error(e, "BROWSER_INITIALIZATION_ERROR")
    
    def _init_browser(self):
        """
        Initialisiert den Browser für die Selenium-Automatisierung.
        """
        try:
            # Konfiguriere die Chrome-Optionen
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument(f"--user-agent={self.user_agent}")
            
            if self.proxy:
                chrome_options.add_argument(f"--proxy-server={self.proxy}")
            
            # Initialisiere den Browser
            self.browser = webdriver.Chrome(options=chrome_options)
            
            logger.info("Browser wurde initialisiert.")
        except Exception as e:
            log_error(e, "BROWSER_INITIALIZATION_ERROR")
            self.browser = None
    
    def __del__(self):
        """
        Destruktor für die Target Discovery.
        """
        # Schließe den Browser, falls er initialisiert wurde
        if self.browser:
            try:
                self.browser.quit()
                logger.info("Browser wurde geschlossen.")
            except Exception as e:
                log_error(e, "BROWSER_CLOSING_ERROR")
    
    @handle_exception
    def analyze_url(self, url):
        """
        Analysiert eine URL auf potenzielle XSS-Schwachstellen.
        
        Args:
            url: Die zu analysierende URL.
        
        Returns:
            Ein Dictionary mit den Analyseergebnissen.
        """
        # Überprüfe, ob die URL gültig ist
        if not is_valid_url(url):
            logger.error(f"Ungültige URL: {url}")
            return {"success": False, "error": "Invalid URL", "url": url}
        
        # Normalisiere die URL
        url = normalize_url(url)
        
        # Initialisiere die Ergebnisse
        results = {
            "success": False,
            "url": url,
            "timestamp": get_timestamp(),
            "parameters": [],
            "forms": [],
            "links": [],
            "javascript": [],
            "potential_vulnerabilities": []
        }
        
        try:
            # Extrahiere Parameter aus der URL
            url_params = extract_params_from_url(url)
            
            if url_params:
                results["parameters"].extend([{"name": param, "source": "url"} for param in url_params])
            
            # Hole den HTML-Inhalt der URL
            html_content = self._get_html_content(url)
            
            if not html_content:
                logger.warning(f"Konnte keinen HTML-Inhalt von der URL abrufen: {url}")
                return {"success": False, "error": "Could not retrieve HTML content", "url": url}
            
            # Extrahiere Formulare aus dem HTML-Inhalt
            forms = self._extract_forms(html_content, url)
            
            if forms:
                results["forms"] = forms
            
            # Extrahiere Links aus dem HTML-Inhalt
            links = self._extract_links(html_content, url)
            
            if links:
                results["links"] = links
            
            # Extrahiere JavaScript aus dem HTML-Inhalt
            javascript = self._extract_javascript(html_content)
            
            if javascript:
                results["javascript"] = javascript
            
            # Identifiziere potenzielle Schwachstellen
            potential_vulnerabilities = self._identify_potential_vulnerabilities(url, url_params, forms, javascript)
            
            if potential_vulnerabilities:
                results["potential_vulnerabilities"] = potential_vulnerabilities
            
            # Setze den Erfolg basierend auf den gefundenen potenziellen Schwachstellen
            results["success"] = len(results["potential_vulnerabilities"]) > 0
            
            return results
        except Exception as e:
            log_error(e, "URL_ANALYSIS_ERROR", {"url": url})
            return {"success": False, "error": str(e), "url": url}
    
    def _get_html_content(self, url):
        """
        Holt den HTML-Inhalt einer URL.
        
        Args:
            url: Die URL, von der der HTML-Inhalt geholt werden soll.
        
        Returns:
            Der HTML-Inhalt der URL oder None, wenn ein Fehler auftritt.
        """
        try:
            # Versuche, den HTML-Inhalt mit Selenium zu holen, falls verfügbar
            if SELENIUM_AVAILABLE and self.browser:
                try:
                    self.browser.get(url)
                    
                    # Warte, bis die Seite geladen ist
                    WebDriverWait(self.browser, self.timeout).until(
                        EC.presence_of_element_located((By.TAG_NAME, "body"))
                    )
                    
                    # Hole den HTML-Inhalt
                    html_content = self.browser.page_source
                    
                    return html_content
                except Exception as e:
                    log_error(e, "SELENIUM_HTML_RETRIEVAL_ERROR", {"url": url})
            
            # Versuche, den HTML-Inhalt mit Requests zu holen, falls verfügbar
            if REQUESTS_AVAILABLE:
                try:
                    headers = {"User-Agent": self.user_agent}
                    proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
                    
                    response = requests.get(url, headers=headers, proxies=proxies, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        return response.text
                    else:
                        logger.warning(f"HTTP-Statuscode {response.status_code} für URL: {url}")
                except Exception as e:
                    log_error(e, "REQUESTS_HTML_RETRIEVAL_ERROR", {"url": url})
            
            # Fallback: Gib None zurück
            logger.error(f"Konnte keinen HTML-Inhalt von der URL abrufen: {url}")
            return None
        except Exception as e:
            log_error(e, "HTML_CONTENT_RETRIEVAL_ERROR", {"url": url})
            return None
    
    def _extract_forms(self, html_content, base_url):
        """
        Extrahiert Formulare aus dem HTML-Inhalt.
        
        Args:
            html_content: Der HTML-Inhalt.
            base_url: Die Basis-URL für relative Formular-Aktionen.
        
        Returns:
            Eine Liste der extrahierten Formulare.
        """
        forms = []
        
        try:
            # Verwende BeautifulSoup, falls verfügbar
            if BS4_AVAILABLE:
                soup = BeautifulSoup(html_content, "html.parser")
                
                # Finde alle Formulare
                for form in soup.find_all("form"):
                    form_data = {
                        "action": form.get("action", ""),
                        "method": form.get("method", "get").upper(),
                        "inputs": []
                    }
                    
                    # Normalisiere die Formular-Aktion
                    if form_data["action"]:
                        if form_data["action"].startswith("/"):
                            # Relative URL zur Basis-URL
                            parsed_url = urllib.parse.urlparse(base_url)
                            form_data["action"] = f"{parsed_url.scheme}://{parsed_url.netloc}{form_data['action']}"
                        elif not form_data["action"].startswith(("http://", "https://")):
                            # Relative URL zum aktuellen Pfad
                            form_data["action"] = urllib.parse.urljoin(base_url, form_data["action"])
                    else:
                        # Leere Aktion, verwende die Basis-URL
                        form_data["action"] = base_url
                    
                    # Finde alle Eingabefelder
                    for input_field in form.find_all(["input", "textarea", "select"]):
                        input_type = input_field.get("type", "text").lower()
                        input_name = input_field.get("name", "")
                        
                        if input_name and input_type not in ["submit", "button", "reset", "image"]:
                            form_data["inputs"].append({
                                "name": input_name,
                                "type": input_type
                            })
                    
                    forms.append(form_data)
            else:
                # Verwende reguläre Ausdrücke als Fallback
                form_pattern = re.compile(r'<form[^>]*action=["\'](.*?)["\'][^>]*method=["\'](.*?)["\'][^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
                input_pattern = re.compile(r'<input[^>]*name=["\'](.*?)["\'][^>]*type=["\'](.*?)["\'][^>]*>', re.IGNORECASE)
                textarea_pattern = re.compile(r'<textarea[^>]*name=["\'](.*?)["\'][^>]*>', re.IGNORECASE)
                
                # Finde alle Formulare
                for form_match in form_pattern.finditer(html_content):
                    action = form_match.group(1)
                    method = form_match.group(2).upper()
                    form_content = form_match.group(3)
                    
                    form_data = {
                        "action": action,
                        "method": method,
                        "inputs": []
                    }
                    
                    # Normalisiere die Formular-Aktion
                    if form_data["action"]:
                        if form_data["action"].startswith("/"):
                            # Relative URL zur Basis-URL
                            parsed_url = urllib.parse.urlparse(base_url)
                            form_data["action"] = f"{parsed_url.scheme}://{parsed_url.netloc}{form_data['action']}"
                        elif not form_data["action"].startswith(("http://", "https://")):
                            # Relative URL zum aktuellen Pfad
                            form_data["action"] = urllib.parse.urljoin(base_url, form_data["action"])
                    else:
                        # Leere Aktion, verwende die Basis-URL
                        form_data["action"] = base_url
                    
                    # Finde alle Eingabefelder
                    for input_match in input_pattern.finditer(form_content):
                        input_name = input_match.group(1)
                        input_type = input_match.group(2).lower()
                        
                        if input_name and input_type not in ["submit", "button", "reset", "image"]:
                            form_data["inputs"].append({
                                "name": input_name,
                                "type": input_type
                            })
                    
                    # Finde alle Textbereiche
                    for textarea_match in textarea_pattern.finditer(form_content):
                        input_name = textarea_match.group(1)
                        
                        if input_name:
                            form_data["inputs"].append({
                                "name": input_name,
                                "type": "textarea"
                            })
                    
                    forms.append(form_data)
            
            return forms
        except Exception as e:
            log_error(e, "FORM_EXTRACTION_ERROR", {"base_url": base_url})
            return []
    
    def _extract_links(self, html_content, base_url):
        """
        Extrahiert Links aus dem HTML-Inhalt.
        
        Args:
            html_content: Der HTML-Inhalt.
            base_url: Die Basis-URL für relative Links.
        
        Returns:
            Eine Liste der extrahierten Links.
        """
        links = []
        
        try:
            # Verwende BeautifulSoup, falls verfügbar
            if BS4_AVAILABLE:
                soup = BeautifulSoup(html_content, "html.parser")
                
                # Finde alle Links
                for link in soup.find_all("a", href=True):
                    href = link.get("href", "")
                    
                    # Normalisiere den Link
                    if href:
                        if href.startswith("/"):
                            # Relative URL zur Basis-URL
                            parsed_url = urllib.parse.urlparse(base_url)
                            href = f"{parsed_url.scheme}://{parsed_url.netloc}{href}"
                        elif not href.startswith(("http://", "https://", "#", "javascript:", "mailto:")):
                            # Relative URL zum aktuellen Pfad
                            href = urllib.parse.urljoin(base_url, href)
                        
                        # Füge den Link hinzu, wenn er mit http:// oder https:// beginnt
                        if href.startswith(("http://", "https://")):
                            links.append(href)
            else:
                # Verwende reguläre Ausdrücke als Fallback
                link_pattern = re.compile(r'<a[^>]*href=["\'](.*?)["\'][^>]*>', re.IGNORECASE)
                
                # Finde alle Links
                for link_match in link_pattern.finditer(html_content):
                    href = link_match.group(1)
                    
                    # Normalisiere den Link
                    if href:
                        if href.startswith("/"):
                            # Relative URL zur Basis-URL
                            parsed_url = urllib.parse.urlparse(base_url)
                            href = f"{parsed_url.scheme}://{parsed_url.netloc}{href}"
                        elif not href.startswith(("http://", "https://", "#", "javascript:", "mailto:")):
                            # Relative URL zum aktuellen Pfad
                            href = urllib.parse.urljoin(base_url, href)
                        
                        # Füge den Link hinzu, wenn er mit http:// oder https:// beginnt
                        if href.startswith(("http://", "https://")):
                            links.append(href)
            
            # Entferne Duplikate
            links = list(set(links))
            
            return links
        except Exception as e:
            log_error(e, "LINK_EXTRACTION_ERROR", {"base_url": base_url})
            return []
    
    def _extract_javascript(self, html_content):
        """
        Extrahiert JavaScript aus dem HTML-Inhalt.
        
        Args:
            html_content: Der HTML-Inhalt.
        
        Returns:
            Eine Liste der extrahierten JavaScript-Snippets.
        """
        javascript = []
        
        try:
            # Verwende BeautifulSoup, falls verfügbar
            if BS4_AVAILABLE:
                soup = BeautifulSoup(html_content, "html.parser")
                
                # Finde alle Script-Tags
                for script in soup.find_all("script"):
                    # Hole den Inhalt des Script-Tags
                    script_content = script.string
                    
                    if script_content:
                        javascript.append({
                            "type": "inline",
                            "content": script_content
                        })
                    
                    # Hole die Quelle des Script-Tags
                    script_src = script.get("src", "")
                    
                    if script_src:
                        javascript.append({
                            "type": "external",
                            "src": script_src
                        })
                
                # Finde alle Event-Handler
                event_handlers = []
                
                for tag in soup.find_all(True):
                    for attr in tag.attrs:
                        if attr.lower().startswith("on"):
                            event_handlers.append({
                                "type": "event_handler",
                                "event": attr,
                                "content": tag[attr]
                            })
                
                javascript.extend(event_handlers)
            else:
                # Verwende reguläre Ausdrücke als Fallback
                script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
                script_src_pattern = re.compile(r'<script[^>]*src=["\'](.*?)["\'][^>]*>', re.IGNORECASE)
                event_handler_pattern = re.compile(r'<[^>]*\s+(on\w+)=["\'](.*?)["\'][^>]*>', re.IGNORECASE)
                
                # Finde alle Script-Tags mit Inhalt
                for script_match in script_pattern.finditer(html_content):
                    script_content = script_match.group(1)
                    
                    if script_content:
                        javascript.append({
                            "type": "inline",
                            "content": script_content
                        })
                
                # Finde alle Script-Tags mit Quelle
                for script_src_match in script_src_pattern.finditer(html_content):
                    script_src = script_src_match.group(1)
                    
                    if script_src:
                        javascript.append({
                            "type": "external",
                            "src": script_src
                        })
                
                # Finde alle Event-Handler
                for event_handler_match in event_handler_pattern.finditer(html_content):
                    event = event_handler_match.group(1)
                    content = event_handler_match.group(2)
                    
                    javascript.append({
                        "type": "event_handler",
                        "event": event,
                        "content": content
                    })
            
            return javascript
        except Exception as e:
            log_error(e, "JAVASCRIPT_EXTRACTION_ERROR")
            return []
    
    def _identify_potential_vulnerabilities(self, url, url_params, forms, javascript):
        """
        Identifiziert potenzielle XSS-Schwachstellen.
        
        Args:
            url: Die URL.
            url_params: Die URL-Parameter.
            forms: Die Formulare.
            javascript: Die JavaScript-Snippets.
        
        Returns:
            Eine Liste der potenziellen Schwachstellen.
        """
        potential_vulnerabilities = []
        
        try:
            # Überprüfe URL-Parameter
            for param in url_params:
                potential_vulnerabilities.append({
                    "type": "url_parameter",
                    "url": url,
                    "param": param,
                    "reason": "URL-Parameter können anfällig für Reflected XSS sein."
                })
            
            # Überprüfe Formulare
            for form in forms:
                for input_field in form["inputs"]:
                    if input_field["type"] in ["text", "textarea", "search", "url", "email", "tel", "number"]:
                        potential_vulnerabilities.append({
                            "type": "form_input",
                            "url": url,
                            "form_action": form["action"],
                            "form_method": form["method"],
                            "param": input_field["name"],
                            "reason": "Formular-Eingabefelder können anfällig für XSS sein."
                        })
            
            # Überprüfe JavaScript
            for js in javascript:
                if js["type"] == "inline":
                    # Suche nach potenziell gefährlichen Funktionen
                    dangerous_functions = ["eval", "document.write", "innerHTML", "outerHTML", "insertAdjacentHTML"]
                    
                    for func in dangerous_functions:
                        if func in js["content"]:
                            potential_vulnerabilities.append({
                                "type": "javascript",
                                "url": url,
                                "function": func,
                                "reason": f"Die JavaScript-Funktion {func} kann anfällig für DOM-basiertes XSS sein."
                            })
                
                elif js["type"] == "event_handler":
                    potential_vulnerabilities.append({
                        "type": "event_handler",
                        "url": url,
                        "event": js["event"],
                        "reason": "Event-Handler können anfällig für XSS sein."
                    })
            
            return potential_vulnerabilities
        except Exception as e:
            log_error(e, "VULNERABILITY_IDENTIFICATION_ERROR", {"url": url})
            return []
    
    @handle_exception
    def crawl(self, url, max_depth=None, max_urls=100):
        """
        Crawlt eine Website, um potenzielle XSS-Schwachstellen zu finden.
        
        Args:
            url: Die Start-URL.
            max_depth: Die maximale Tiefe für das Crawling.
            max_urls: Die maximale Anzahl von URLs, die gecrawlt werden sollen.
        
        Returns:
            Ein Dictionary mit den Crawling-Ergebnissen.
        """
        # Überprüfe, ob die URL gültig ist
        if not is_valid_url(url):
            logger.error(f"Ungültige URL: {url}")
            return {"success": False, "error": "Invalid URL", "url": url}
        
        # Setze die maximale Tiefe
        max_depth = max_depth or self.max_depth
        
        # Initialisiere die Ergebnisse
        results = {
            "success": False,
            "url": url,
            "timestamp": get_timestamp(),
            "crawled_urls": [],
            "potential_vulnerabilities": []
        }
        
        try:
            # Initialisiere die Queue für das Crawling
            queue = [(url, 0)]  # (URL, Tiefe)
            visited = set()
            
            # Crawle die Website
            while queue and len(visited) < max_urls:
                current_url, depth = queue.pop(0)
                
                # Überprüfe, ob die URL bereits besucht wurde
                if current_url in visited:
                    continue
                
                # Markiere die URL als besucht
                visited.add(current_url)
                
                # Analysiere die URL
                analysis = self.analyze_url(current_url)
                
                # Füge die URL zu den gecrawlten URLs hinzu
                results["crawled_urls"].append({
                    "url": current_url,
                    "depth": depth,
                    "parameters": analysis.get("parameters", []),
                    "forms": analysis.get("forms", [])
                })
                
                # Füge potenzielle Schwachstellen hinzu
                if "potential_vulnerabilities" in analysis and analysis["potential_vulnerabilities"]:
                    for vuln in analysis["potential_vulnerabilities"]:
                        results["potential_vulnerabilities"].append(vuln)
                
                # Füge Links zur Queue hinzu, wenn die maximale Tiefe noch nicht erreicht ist
                if depth < max_depth:
                    for link in analysis.get("links", []):
                        if link not in visited:
                            queue.append((link, depth + 1))
            
            # Setze den Erfolg basierend auf den gefundenen potenziellen Schwachstellen
            results["success"] = len(results["potential_vulnerabilities"]) > 0
            
            return results
        except Exception as e:
            log_error(e, "CRAWLING_ERROR", {"url": url})
            return {"success": False, "error": str(e), "url": url}
    
    @handle_exception
    def scan_subdomains(self, domain, use_wordlist=False, wordlist_file=None):
        """
        Scannt Subdomains einer Domain.
        
        Args:
            domain: Die zu scannende Domain.
            use_wordlist: Ob eine Wortliste verwendet werden soll.
            wordlist_file: Die Wortlistendatei.
        
        Returns:
            Ein Dictionary mit den Scan-Ergebnissen.
        """
        # Überprüfe, ob die Domain gültig ist
        if not domain:
            logger.error("Keine Domain angegeben.")
            return {"success": False, "error": "No domain specified"}
        
        # Entferne das Protokoll, falls vorhanden
        domain = domain.replace("http://", "").replace("https://", "")
        
        # Entferne den Pfad, falls vorhanden
        domain = domain.split("/")[0]
        
        # Initialisiere die Ergebnisse
        results = {
            "success": False,
            "domain": domain,
            "timestamp": get_timestamp(),
            "subdomains": []
        }
        
        try:
            # Versuche, die Subdomains mit DNS zu finden
            subdomains = self._find_subdomains_dns(domain)
            
            # Versuche, die Subdomains mit einer Wortliste zu finden, falls gewünscht
            if use_wordlist:
                wordlist_subdomains = self._find_subdomains_wordlist(domain, wordlist_file)
                subdomains.extend(wordlist_subdomains)
            
            # Entferne Duplikate
            subdomains = list(set(subdomains))
            
            # Füge die Subdomains zu den Ergebnissen hinzu
            for subdomain in subdomains:
                # Überprüfe, ob die Subdomain erreichbar ist
                if self._is_subdomain_reachable(subdomain):
                    results["subdomains"].append({
                        "subdomain": subdomain,
                        "reachable": True
                    })
                else:
                    results["subdomains"].append({
                        "subdomain": subdomain,
                        "reachable": False
                    })
            
            # Setze den Erfolg basierend auf den gefundenen Subdomains
            results["success"] = len(results["subdomains"]) > 0
            
            return results
        except Exception as e:
            log_error(e, "SUBDOMAIN_SCANNING_ERROR", {"domain": domain})
            return {"success": False, "error": str(e), "domain": domain}
    
    def _find_subdomains_dns(self, domain):
        """
        Findet Subdomains einer Domain mit DNS.
        
        Args:
            domain: Die Domain.
        
        Returns:
            Eine Liste der gefundenen Subdomains.
        """
        subdomains = []
        
        try:
            # Versuche, das dnspython-Modul zu importieren
            try:
                import dns.resolver
                DNS_AVAILABLE = True
            except ImportError:
                logger.warning("dnspython-Modul konnte nicht importiert werden. DNS-Abfragen werden eingeschränkt sein.")
                DNS_AVAILABLE = False
            
            if DNS_AVAILABLE:
                # Versuche, die Subdomains mit DNS zu finden
                try:
                    # Versuche, die MX-Einträge zu finden
                    mx_records = dns.resolver.resolve(domain, "MX")
                    
                    for mx in mx_records:
                        mx_domain = str(mx.exchange).rstrip(".")
                        
                        if domain in mx_domain and mx_domain != domain:
                            subdomains.append(mx_domain)
                except Exception as e:
                    logger.debug(f"Fehler beim Abrufen der MX-Einträge: {e}")
                
                try:
                    # Versuche, die NS-Einträge zu finden
                    ns_records = dns.resolver.resolve(domain, "NS")
                    
                    for ns in ns_records:
                        ns_domain = str(ns).rstrip(".")
                        
                        if domain in ns_domain and ns_domain != domain:
                            subdomains.append(ns_domain)
                except Exception as e:
                    logger.debug(f"Fehler beim Abrufen der NS-Einträge: {e}")
                
                try:
                    # Versuche, die TXT-Einträge zu finden
                    txt_records = dns.resolver.resolve(domain, "TXT")
                    
                    for txt in txt_records:
                        txt_data = str(txt).rstrip(".")
                        
                        # Suche nach Subdomains in den TXT-Einträgen
                        subdomain_pattern = re.compile(r'([a-zA-Z0-9-]+\.)+' + re.escape(domain))
                        
                        for match in subdomain_pattern.finditer(txt_data):
                            subdomain = match.group(0)
                            
                            if subdomain != domain:
                                subdomains.append(subdomain)
                except Exception as e:
                    logger.debug(f"Fehler beim Abrufen der TXT-Einträge: {e}")
            
            # Füge einige häufige Subdomains hinzu
            common_subdomains = ["www", "mail", "ftp", "webmail", "admin", "intranet", "vpn", "api", "dev", "test", "staging"]
            
            for subdomain in common_subdomains:
                subdomains.append(f"{subdomain}.{domain}")
            
            return subdomains
        except Exception as e:
            log_error(e, "DNS_SUBDOMAIN_FINDING_ERROR", {"domain": domain})
            return []
    
    def _find_subdomains_wordlist(self, domain, wordlist_file=None):
        """
        Findet Subdomains einer Domain mit einer Wortliste.
        
        Args:
            domain: Die Domain.
            wordlist_file: Die Wortlistendatei.
        
        Returns:
            Eine Liste der gefundenen Subdomains.
        """
        subdomains = []
        
        try:
            # Verwende die Standard-Wortliste, falls keine angegeben wurde
            if not wordlist_file:
                wordlist = ["www", "mail", "ftp", "webmail", "admin", "intranet", "vpn", "api", "dev", "test", "staging",
                           "blog", "shop", "store", "app", "mobile", "m", "support", "help", "docs", "documentation",
                           "wiki", "forum", "community", "cdn", "media", "static", "assets", "images", "img", "css", "js",
                           "login", "secure", "ssl", "remote", "portal", "internal", "external", "extranet", "partner",
                           "partners", "client", "clients", "customer", "customers", "user", "users", "admin", "administrator",
                           "webadmin", "sysadmin", "root", "mx", "ns", "ns1", "ns2", "dns", "dns1", "dns2", "smtp", "pop",
                           "pop3", "imap", "mail1", "mail2", "mail3", "webmail1", "webmail2", "webmail3", "ftp1", "ftp2",
                           "ftp3", "sftp", "ssh", "git", "svn", "cvs", "trac", "redmine", "jira", "jenkins", "ci", "build",
                           "staging1", "staging2", "staging3", "dev1", "dev2", "dev3", "test1", "test2", "test3", "demo",
                           "beta", "alpha", "gamma", "lab", "labs", "research", "status", "monitor", "monitoring", "stats",
                           "statistics", "analytics", "track", "tracking", "event", "events", "calendar", "chat", "im",
                           "messaging", "sip", "voip", "voice", "video", "conference", "meet", "meeting", "meetings",
                           "webinar", "webinars", "training", "learn", "learning", "edu", "education", "course", "courses",
                           "class", "classes", "school", "university", "college", "academy", "student", "students",
                           "teacher", "teachers", "professor", "faculty", "staff", "hr", "human-resources", "jobs",
                           "career", "careers", "hire", "hiring", "recruit", "recruiting", "recruitment", "talent",
                           "payroll", "salary", "compensation", "benefits", "finance", "financial", "accounting", "account",
                           "accounts", "billing", "invoice", "invoices", "payment", "payments", "checkout", "cart",
                           "order", "orders", "shipping", "delivery", "track", "tracking", "returns", "exchange",
                           "warranty", "support", "helpdesk", "ticket", "tickets", "faq", "knowledgebase", "kb",
                           "answers", "ask", "question", "questions", "feedback", "contact", "contactus", "about",
                           "aboutus", "company", "corporate", "corp", "organization", "org", "foundation", "institute",
                           "press", "media", "news", "blog", "weblog", "article", "articles", "post", "posts", "forum",
                           "forums", "board", "boards", "discussion", "discussions", "comment", "comments", "review",
                           "reviews", "rating", "ratings", "vote", "voting", "poll", "polls", "survey", "surveys",
                           "quiz", "quizzes", "test", "tests", "exam", "exams", "assessment", "assessments", "evaluation",
                           "evaluations", "score", "scores", "result", "results", "grade", "grades", "report", "reports",
                           "dashboard", "panel", "control", "controlpanel", "cp", "cpanel", "whm", "plesk", "manage",
                           "management", "manager", "admin", "administrator", "administrador", "administrateur", "root",
                           "supervisor", "moderator", "mod", "superuser", "su", "webmaster", "hostmaster", "postmaster"]
            else:
                # Lade die Wortliste aus der Datei
                try:
                    with open(wordlist_file, "r") as f:
                        wordlist = [line.strip() for line in f.readlines()]
                except Exception as e:
                    log_error(e, "WORDLIST_LOADING_ERROR", {"wordlist_file": wordlist_file})
                    wordlist = []
            
            # Erstelle die Subdomains
            for word in wordlist:
                subdomains.append(f"{word}.{domain}")
            
            return subdomains
        except Exception as e:
            log_error(e, "WORDLIST_SUBDOMAIN_FINDING_ERROR", {"domain": domain})
            return []
    
    def _is_subdomain_reachable(self, subdomain):
        """
        Überprüft, ob eine Subdomain erreichbar ist.
        
        Args:
            subdomain: Die Subdomain.
        
        Returns:
            True, wenn die Subdomain erreichbar ist, sonst False.
        """
        try:
            # Versuche, die Subdomain mit Requests zu erreichen, falls verfügbar
            if REQUESTS_AVAILABLE:
                try:
                    headers = {"User-Agent": self.user_agent}
                    proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
                    
                    # Versuche, die Subdomain mit HTTP zu erreichen
                    http_url = f"http://{subdomain}"
                    http_response = requests.get(http_url, headers=headers, proxies=proxies, timeout=self.timeout)
                    
                    if http_response.status_code < 400:
                        return True
                    
                    # Versuche, die Subdomain mit HTTPS zu erreichen
                    https_url = f"https://{subdomain}"
                    https_response = requests.get(https_url, headers=headers, proxies=proxies, timeout=self.timeout)
                    
                    if https_response.status_code < 400:
                        return True
                except Exception:
                    pass
            
            # Versuche, die Subdomain mit Socket zu erreichen
            try:
                import socket
                
                # Versuche, die Subdomain aufzulösen
                socket.gethostbyname(subdomain)
                
                return True
            except Exception:
                pass
            
            return False
        except Exception as e:
            log_error(e, "SUBDOMAIN_REACHABILITY_CHECK_ERROR", {"subdomain": subdomain})
            return False
    
    @handle_exception
    def scan_ports(self, host, ports=None):
        """
        Scannt Ports eines Hosts.
        
        Args:
            host: Der zu scannende Host.
            ports: Die zu scannenden Ports.
        
        Returns:
            Ein Dictionary mit den Scan-Ergebnissen.
        """
        # Überprüfe, ob der Host gültig ist
        if not host:
            logger.error("Kein Host angegeben.")
            return {"success": False, "error": "No host specified"}
        
        # Setze die Standard-Ports, falls keine angegeben wurden
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 1433, 3306, 3389, 5632, 5900, 8080]
        
        # Initialisiere die Ergebnisse
        results = {
            "success": False,
            "host": host,
            "timestamp": get_timestamp(),
            "open_ports": []
        }
        
        try:
            # Importiere das Socket-Modul
            import socket
            
            # Scanne die Ports
            for port in ports:
                try:
                    # Erstelle einen Socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    
                    # Versuche, eine Verbindung herzustellen
                    result = sock.connect_ex((host, port))
                    
                    # Schließe den Socket
                    sock.close()
                    
                    # Überprüfe, ob der Port offen ist
                    if result == 0:
                        # Bestimme den Dienst
                        service = self._get_service_name(port)
                        
                        # Füge den Port zu den offenen Ports hinzu
                        results["open_ports"].append({
                            "port": port,
                            "service": service
                        })
                except Exception as e:
                    logger.debug(f"Fehler beim Scannen von Port {port}: {e}")
            
            # Setze den Erfolg basierend auf den gefundenen offenen Ports
            results["success"] = len(results["open_ports"]) > 0
            
            return results
        except Exception as e:
            log_error(e, "PORT_SCANNING_ERROR", {"host": host})
            return {"success": False, "error": str(e), "host": host}
    
    def _get_service_name(self, port):
        """
        Gibt den Dienstnamen für einen Port zurück.
        
        Args:
            port: Der Port.
        
        Returns:
            Der Dienstname.
        """
        # Definiere häufige Ports und ihre Dienste
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            115: "SFTP",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            194: "IRC",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5632: "PCAnywhere",
            5900: "VNC",
            8080: "HTTP-Proxy"
        }
        
        # Gib den Dienstnamen zurück, falls bekannt
        return common_ports.get(port, "Unknown")


# Beispielverwendung
if __name__ == "__main__":
    # Erstelle eine Target Discovery
    discovery = TargetDiscovery()
    
    # Analysiere eine URL
    url = "https://example.com"
    results = discovery.analyze_url(url)
    
    print(f"Analyseergebnisse: {json.dumps(results, indent=2)}")
    
    # Crawle eine Website
    crawl_results = discovery.crawl(url, max_depth=1, max_urls=10)
    
    print(f"Crawling-Ergebnisse: {json.dumps(crawl_results, indent=2)}")
    
    # Scanne Subdomains
    subdomain_results = discovery.scan_subdomains("example.com")
    
    print(f"Subdomain-Scan-Ergebnisse: {json.dumps(subdomain_results, indent=2)}")
    
    # Scanne Ports
    port_results = discovery.scan_ports("example.com")
    
    print(f"Port-Scan-Ergebnisse: {json.dumps(port_results, indent=2)}")
