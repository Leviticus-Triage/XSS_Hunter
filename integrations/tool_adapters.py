#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Tool Integration Module
=================================================

Dieses Modul implementiert Adapter für verschiedene externe Tools, die für
Bug Bounty und XSS-Hunting nützlich sind. Es bietet eine einheitliche
Schnittstelle für die Integration dieser Tools in das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.1.0
"""

import logging
import os
import sys
import json
from typing import Any, Dict, List, Optional, Union

from adapter_layer import ToolAdapter

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.ToolIntegration")


class GospiderAdapter(ToolAdapter):
    """Adapter für Gospider, einen schnellen Web-Spider geschrieben in Go."""

    def __init__(self):
        """Initialisiert den Gospider-Adapter."""
        super().__init__()
        self._tool_name = "gospider"
        self._tool_description = "Fast web spider written in Go"
        self._tool_version = "1.0.0"
        self._required_dependencies = ["go"]

    def _install_tool(self) -> bool:
        """Installiert Gospider."""
        try:
            logger.info("Installiere Gospider...")
            # Installiere Gospider mit Go
            cmd = ["go", "install", "github.com/jaeles-project/gospider@latest"]
            result = self.execute_command(cmd)
            return result["success"]
        except Exception as e:
            logger.error(f"Fehler bei der Installation von Gospider: {e}")
            return False

    def crawl(self, url: str, depth: int = 3, timeout: int = 300, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Führt einen Crawl mit Gospider durch.

        Args:
            url: Die zu crawlende URL.
            depth: Die maximale Tiefe des Crawls.
            timeout: Timeout in Sekunden.
            output_file: Optionaler Pfad für die Ausgabedatei.

        Returns:
            Ein Dictionary mit den Ergebnissen des Crawls.
        """
        if self._fallback_mode:
            logger.warning("Gospider läuft im Fallback-Modus, verwende einfachen HTTP-Client")
            return self._fallback_crawl(url, depth, timeout, output_file)

        # Erstelle den Befehl
        cmd = [self._tool_path, "-s", url, "-d", str(depth), "-t", str(timeout)]
        
        # Füge Output-Datei hinzu, wenn angegeben
        if output_file:
            cmd.extend(["-o", output_file])

        # Führe den Befehl aus
        result = self.execute_command(cmd, timeout=timeout)
        
        # Verarbeite die Ausgabe
        if result["success"]:
            # Extrahiere URLs aus der Ausgabe
            urls = []
            for line in result["stdout"].splitlines():
                if line.startswith("[url]"):
                    url = line.split("[url]")[1].strip()
                    urls.append(url)
            
            result["urls"] = urls
            result["count"] = len(urls)
            
        return result

    def _fallback_crawl(self, url: str, depth: int = 3, timeout: int = 300, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Führt einen einfachen Crawl mit Requests durch (Fallback).

        Args:
            url: Die zu crawlende URL.
            depth: Die maximale Tiefe des Crawls (wird ignoriert).
            timeout: Timeout in Sekunden.
            output_file: Optionaler Pfad für die Ausgabedatei.

        Returns:
            Ein Dictionary mit den Ergebnissen des Crawls.
        """
        try:
            import requests
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin, urlparse
            
            # Initialisiere das Ergebnis
            result = {
                "success": False,
                "stdout": "",
                "stderr": "",
                "returncode": 0,
                "command": f"fallback_crawl({url})",
                "fallback": True,
                "urls": [],
                "count": 0
            }
            
            # Setze Header
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            
            # Führe den Request aus
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            
            # Parse die HTML
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Extrahiere alle Links
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                full_url = urljoin(base_url, href)
                result["urls"].append(full_url)
            
            # Aktualisiere das Ergebnis
            result["success"] = True
            result["count"] = len(result["urls"])
            result["stdout"] = f"Found {result['count']} URLs"
            
            # Schreibe in Ausgabedatei, wenn angegeben
            if output_file:
                with open(output_file, "w") as f:
                    for url in result["urls"]:
                        f.write(f"[url] {url}\n")
            
            return result
            
        except Exception as e:
            logger.error(f"Fehler beim Fallback-Crawl: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
                "command": f"fallback_crawl({url})",
                "fallback": True,
                "urls": [],
                "count": 0
            }


class SubfinderAdapter(ToolAdapter):
    """Adapter für Subfinder, ein Tool zur Subdomain-Erkennung."""

    def __init__(self):
        """Initialisiert den Subfinder-Adapter."""
        super().__init__()
        self._tool_name = "subfinder"
        self._tool_description = "Subdomain discovery tool"
        self._tool_version = "1.0.0"
        self._required_dependencies = ["go"]

    def _install_tool(self) -> bool:
        """Installiert Subfinder."""
        try:
            logger.info("Installiere Subfinder...")
            # Installiere Subfinder mit Go
            cmd = ["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"]
            result = self.execute_command(cmd)
            return result["success"]
        except Exception as e:
            logger.error(f"Fehler bei der Installation von Subfinder: {e}")
            return False

    def find_subdomains(self, domain: str, timeout: int = 300, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Sucht nach Subdomains für eine Domain.

        Args:
            domain: Die zu untersuchende Domain.
            timeout: Timeout in Sekunden.
            output_file: Optionaler Pfad für die Ausgabedatei.

        Returns:
            Ein Dictionary mit den gefundenen Subdomains.
        """
        if self._fallback_mode:
            logger.warning("Subfinder läuft im Fallback-Modus, verwende einfache DNS-Abfrage")
            return self._fallback_find_subdomains(domain, timeout, output_file)

        # Erstelle den Befehl
        cmd = [self._tool_path, "-d", domain]
        
        # Füge Output-Datei hinzu, wenn angegeben
        if output_file:
            cmd.extend(["-o", output_file])

        # Führe den Befehl aus
        result = self.execute_command(cmd, timeout=timeout)
        
        # Verarbeite die Ausgabe
        if result["success"]:
            # Extrahiere Subdomains aus der Ausgabe
            subdomains = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
            
            result["subdomains"] = subdomains
            result["count"] = len(subdomains)
            
        return result

    def _fallback_find_subdomains(self, domain: str, timeout: int = 300, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Führt eine einfache DNS-Abfrage durch (Fallback).

        Args:
            domain: Die zu untersuchende Domain.
            timeout: Timeout in Sekunden.
            output_file: Optionaler Pfad für die Ausgabedatei.

        Returns:
            Ein Dictionary mit den gefundenen Subdomains.
        """
        try:
            import dns.resolver
            import dns.zone
            
            # Initialisiere das Ergebnis
            result = {
                "success": False,
                "stdout": "",
                "stderr": "",
                "returncode": 0,
                "command": f"fallback_find_subdomains({domain})",
                "fallback": True,
                "subdomains": [],
                "count": 0
            }
            
            # Versuche einen Zone Transfer (selten erfolgreich, aber einen Versuch wert)
            try:
                nameservers = dns.resolver.resolve(domain, 'NS')
                for ns in nameservers:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain, timeout=timeout))
                        for name, node in zone.nodes.items():
                            subdomain = f"{name}.{domain}"
                            if subdomain not in result["subdomains"] and str(name) != '@':
                                result["subdomains"].append(subdomain)
                    except:
                        pass
            except:
                pass
            
            # Versuche einige gängige Subdomains
            common_subdomains = ["www", "mail", "ftp", "webmail", "login", "admin", "test", "dev", "staging"]
            for sub in common_subdomains:
                try:
                    subdomain = f"{sub}.{domain}"
                    dns.resolver.resolve(subdomain, 'A')
                    if subdomain not in result["subdomains"]:
                        result["subdomains"].append(subdomain)
                except:
                    pass
            
            # Aktualisiere das Ergebnis
            result["success"] = True
            result["count"] = len(result["subdomains"])
            result["stdout"] = f"Found {result['count']} subdomains"
            
            # Schreibe in Ausgabedatei, wenn angegeben
            if output_file:
                with open(output_file, "w") as f:
                    for subdomain in result["subdomains"]:
                        f.write(f"{subdomain}\n")
            
            return result
            
        except Exception as e:
            logger.error(f"Fehler beim Fallback-Subdomain-Scan: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
                "command": f"fallback_find_subdomains({domain})",
                "fallback": True,
                "subdomains": [],
                "count": 0
            }


class NucleiAdapter(ToolAdapter):
    """Adapter für Nuclei, ein Template-basiertes Vulnerability-Scanning-Tool."""

    def __init__(self):
        """Initialisiert den Nuclei-Adapter."""
        super().__init__()
        self._tool_name = "nuclei"
        self._tool_description = "Template-based vulnerability scanner"
        self._tool_version = "1.0.0"
        self._required_dependencies = ["go"]

    def _install_tool(self) -> bool:
        """Installiert Nuclei."""
        try:
            logger.info("Installiere Nuclei...")
            # Installiere Nuclei mit Go
            cmd = ["go", "install", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"]
            result = self.execute_command(cmd)
            return result["success"]
        except Exception as e:
            logger.error(f"Fehler bei der Installation von Nuclei: {e}")
            return False

    def scan(self, target: str, templates: Optional[List[str]] = None, severity: Optional[List[str]] = None, 
             timeout: int = 300, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Führt einen Vulnerability-Scan mit Nuclei durch.

        Args:
            target: Die Ziel-URL oder -Datei.
            templates: Optionale Liste von Template-Namen.
            severity: Optionale Liste von Schweregraden (info, low, medium, high, critical).
            timeout: Timeout in Sekunden.
            output_file: Optionaler Pfad für die Ausgabedatei.

        Returns:
            Ein Dictionary mit den Scan-Ergebnissen.
        """
        if self._fallback_mode:
            logger.warning("Nuclei läuft im Fallback-Modus, verwende einfachen HTTP-Scan")
            return self._fallback_scan(target, templates, severity, timeout, output_file)

        # Erstelle den Befehl
        cmd = [self._tool_path, "-u", target, "-silent"]
        
        # Füge Templates hinzu, wenn angegeben
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        
        # Füge Schweregrade hinzu, wenn angegeben
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        # Füge Output-Datei hinzu, wenn angegeben
        if output_file:
            cmd.extend(["-o", output_file])

        # Führe den Befehl aus
        result = self.execute_command(cmd, timeout=timeout)
        
        # Verarbeite die Ausgabe
        if result["success"]:
            # Extrahiere Findings aus der Ausgabe
            findings = []
            for line in result["stdout"].splitlines():
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except:
                        pass
            
            result["findings"] = findings
            result["count"] = len(findings)
            
        return result

    def _fallback_scan(self, target: str, templates: Optional[List[str]] = None, severity: Optional[List[str]] = None, 
                      timeout: int = 300, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Führt einen einfachen HTTP-Scan durch (Fallback).

        Args:
            target: Die Ziel-URL oder -Datei.
            templates: Optionale Liste von Template-Namen (wird ignoriert).
            severity: Optionale Liste von Schweregraden (wird ignoriert).
            timeout: Timeout in Sekunden.
            output_file: Optionaler Pfad für die Ausgabedatei.

        Returns:
            Ein Dictionary mit den Scan-Ergebnissen.
        """
        try:
            import requests
            
            # Initialisiere das Ergebnis
            result = {
                "success": False,
                "stdout": "",
                "stderr": "",
                "returncode": 0,
                "command": f"fallback_scan({target})",
                "fallback": True,
                "findings": [],
                "count": 0
            }
            
            # Setze Header
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            
            # Führe den Request aus
            response = requests.get(target, headers=headers, timeout=timeout)
            
            # Prüfe auf einfache Sicherheitsprobleme
            findings = []
            
            # Prüfe auf fehlende Security-Header
            security_headers = {
                "Strict-Transport-Security": "HSTS nicht konfiguriert",
                "Content-Security-Policy": "CSP nicht konfiguriert",
                "X-Content-Type-Options": "X-Content-Type-Options nicht konfiguriert",
                "X-Frame-Options": "X-Frame-Options nicht konfiguriert",
                "X-XSS-Protection": "X-XSS-Protection nicht konfiguriert"
            }
            
            for header, message in security_headers.items():
                if header not in response.headers:
                    findings.append({
                        "template": "security-headers",
                        "info": {
                            "name": f"Fehlender {header} Header",
                            "severity": "low",
                            "description": message
                        },
                        "host": target,
                        "matched": header
                    })
            
            # Aktualisiere das Ergebnis
            result["success"] = True
            result["findings"] = findings
            result["count"] = len(findings)
            result["stdout"] = f"Found {result['count']} potential issues"
            
            # Schreibe in Ausgabedatei, wenn angegeben
            if output_file:
                with open(output_file, "w") as f:
                    json.dump(findings, f, indent=2)
            
            return result
            
        except Exception as e:
            logger.error(f"Fehler beim Fallback-Scan: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
                "command": f"fallback_scan({target})",
                "fallback": True,
                "findings": [],
                "count": 0
            }


class DalfoxAdapter(ToolAdapter):
    """Adapter für Dalfox, ein Tool für XSS-Scanning und -Exploitation."""

    def __init__(self):
        """Initialisiert den Dalfox-Adapter."""
        super().__init__()
        self._tool_name = "dalfox"
        self._tool_description = "Parameter Analysis and XSS Scanning tool"
        self._tool_version = "1.0.0"
        self._required_dependencies = ["go"]

    def _install_tool(self) -> bool:
        """Installiert Dalfox."""
        try:
            logger.info("Installiere Dalfox...")
            # Installiere Dalfox mit Go
            cmd = ["go", "install", "github.com/hahwul/dalfox/v2@latest"]
            result = self.execute_command(cmd)
            return result["success"]
        except Exception as e:
            logger.error(f"Fehler bei der Installation von Dalfox: {e}")
            return False

    def scan(self, target: str, param: Optional[str] = None, timeout: int = 300, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Führt einen XSS-Scan mit Dalfox durch.

        Args:
            target: Die Ziel-URL.
            param: Optionaler Parameter-Name für gezieltes Scanning.
            timeout: Timeout in Sekunden.
            output_file: Optionaler Pfad für die Ausgabedatei.

        Returns:
            Ein Dictionary mit den Scan-Ergebnissen.
        """
        if self._fallback_mode:
            logger.warning("Dalfox läuft im Fallback-Modus, verwende einfachen XSS-Scan")
            return self._fallback_scan(target, param, timeout, output_file)

        # Erstelle den Befehl
        cmd = [self._tool_path, "url", target, "--silence"]
        
        # Füge Parameter hinzu, wenn angegeben
        if param:
            cmd.extend(["--param", param])
        
        # Füge Output-Datei hinzu, wenn angegeben
        if output_file:
            cmd.extend(["--output", output_file])

        # Führe den Befehl aus
        result = self.execute_command(cmd, timeout=timeout)
        
        # Verarbeite die Ausgabe
        if result["success"]:
            # Extrahiere Findings aus der Ausgabe
            vulnerabilities = []
            for line in result["stdout"].splitlines():
                if "[V]" in line:  # Vulnerability gefunden
                    vulnerabilities.append(line.strip())
            
            result["vulnerabilities"] = vulnerabilities
            result["count"] = len(vulnerabilities)
            
        return result

    def _fallback_scan(self, target: str, param: Optional[str] = None, timeout: int = 300, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Führt einen einfachen XSS-Scan durch (Fallback).

        Args:
            target: Die Ziel-URL.
            param: Optionaler Parameter-Name für gezieltes Scanning.
            timeout: Timeout in Sekunden.
            output_file: Optionaler Pfad für die Ausgabedatei.

        Returns:
            Ein Dictionary mit den Scan-Ergebnissen.
        """
        try:
            import requests
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            
            # Initialisiere das Ergebnis
            result = {
                "success": False,
                "stdout": "",
                "stderr": "",
                "returncode": 0,
                "command": f"fallback_scan({target})",
                "fallback": True,
                "vulnerabilities": [],
                "count": 0
            }
            
            # Parse die URL
            parsed_url = urlparse(target)
            query_params = parse_qs(parsed_url.query)
            
            # Wenn kein Parameter angegeben ist, teste alle
            test_params = [param] if param else query_params.keys()
            
            # Setze Header
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            
            # XSS-Payloads für den Test
            test_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>"
            ]
            
            # Teste jeden Parameter
            for p in test_params:
                if p not in query_params:
                    continue
                    
                for payload in test_payloads:
                    # Erstelle eine neue Query mit dem Payload
                    new_query = query_params.copy()
                    new_query[p] = [payload]
                    
                    # Erstelle die neue URL
                    new_url_parts = list(parsed_url)
                    new_url_parts[4] = urlencode(new_query, doseq=True)
                    new_url = urlunparse(new_url_parts)
                    
                    # Führe den Request aus
                    try:
                        response = requests.get(new_url, headers=headers, timeout=timeout)
                        
                        # Prüfe, ob der Payload im Response enthalten ist
                        if payload in response.text:
                            vulnerability = f"[V] XSS in Parameter {p} mit Payload {payload}"
                            result["vulnerabilities"].append(vulnerability)
                    except:
                        pass
            
            # Aktualisiere das Ergebnis
            result["success"] = True
            result["count"] = len(result["vulnerabilities"])
            result["stdout"] = f"Found {result['count']} potential XSS vulnerabilities"
            
            # Schreibe in Ausgabedatei, wenn angegeben
            if output_file:
                with open(output_file, "w") as f:
                    for vuln in result["vulnerabilities"]:
                        f.write(f"{vuln}\n")
            
            return result
            
        except Exception as e:
            logger.error(f"Fehler beim Fallback-XSS-Scan: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
                "command": f"fallback_scan({target})",
                "fallback": True,
                "vulnerabilities": [],
                "count": 0
            }


class FFuFAdapter(ToolAdapter):
    """Adapter für FFuF, ein Tool für Web-Fuzzing."""

    def __init__(self):
        """Initialisiert den FFuF-Adapter."""
        super().__init__()
        self._tool_name = "ffuf"
        self._tool_description = "Fast web fuzzer"
        self._tool_version = "1.0.0"
        self._required_dependencies = ["go"]

    def _install_tool(self) -> bool:
        """Installiert FFuF."""
        try:
            logger.info("Installiere FFuF...")
            # Installiere FFuF mit Go
            cmd = ["go", "install", "github.com/ffuf/ffuf@latest"]
            result = self.execute_command(cmd)
            return result["success"]
        except Exception as e:
            logger.error(f"Fehler bei der Installation von FFuF: {e}")
            return False

    def fuzz(self, url: str, wordlist: str, param: str = "FUZZ", timeout: int = 300, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Führt einen Fuzzing-Scan mit FFuF durch.

        Args:
            url: Die Ziel-URL mit FUZZ-Platzhalter.
            wordlist: Pfad zur Wordlist-Datei.
            param: Der zu verwendende Parameter (Standard: FUZZ).
            timeout: Timeout in Sekunden.
            output_file: Optionaler Pfad für die Ausgabedatei.

        Returns:
            Ein Dictionary mit den Fuzzing-Ergebnissen.
        """
        if self._fallback_mode:
            logger.warning("FFuF läuft im Fallback-Modus, verwende einfaches Fuzzing")
            return self._fallback_fuzz(url, wordlist, param, timeout, output_file)

        # Erstelle den Befehl
        cmd = [self._tool_path, "-u", url, "-w", wordlist, "-v"]
        
        # Füge Output-Datei hinzu, wenn angegeben
        if output_file:
            cmd.extend(["-o", output_file, "-of", "json"])

        # Führe den Befehl aus
        result = self.execute_command(cmd, timeout=timeout)
        
        # Verarbeite die Ausgabe
        if result["success"]:
            # Extrahiere Findings aus der Ausgabe
            findings = []
            for line in result["stdout"].splitlines():
                if "Status:" in line and "Length:" in line:
                    findings.append(line.strip())
            
            result["findings"] = findings
            result["count"] = len(findings)
            
        return result

    def _fallback_fuzz(self, url: str, wordlist: str, param: str = "FUZZ", timeout: int = 300, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Führt ein einfaches Fuzzing durch (Fallback).

        Args:
            url: Die Ziel-URL mit FUZZ-Platzhalter.
            wordlist: Pfad zur Wordlist-Datei.
            param: Der zu verwendende Parameter (Standard: FUZZ).
            timeout: Timeout in Sekunden.
            output_file: Optionaler Pfad für die Ausgabedatei.

        Returns:
            Ein Dictionary mit den Fuzzing-Ergebnissen.
        """
        try:
            import requests
            
            # Initialisiere das Ergebnis
            result = {
                "success": False,
                "stdout": "",
                "stderr": "",
                "returncode": 0,
                "command": f"fallback_fuzz({url}, {wordlist})",
                "fallback": True,
                "findings": [],
                "count": 0
            }
            
            # Prüfe, ob die Wordlist existiert
            if not os.path.isfile(wordlist):
                result["stderr"] = f"Wordlist {wordlist} nicht gefunden"
                return result
            
            # Setze Header
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            
            # Lese die Wordlist
            with open(wordlist, "r") as f:
                words = [line.strip() for line in f if line.strip()]
            
            # Begrenze die Anzahl der Wörter im Fallback-Modus
            max_words = 100
            if len(words) > max_words:
                logger.warning(f"Wordlist zu groß für Fallback-Modus, beschränke auf {max_words} Einträge")
                words = words[:max_words]
            
            # Führe das Fuzzing durch
            findings = []
            for word in words:
                try:
                    # Ersetze den Platzhalter in der URL
                    test_url = url.replace(param, word)
                    
                    # Führe den Request aus
                    response = requests.get(test_url, headers=headers, timeout=timeout/len(words))
                    
                    # Speichere das Ergebnis
                    finding = f"Status: {response.status_code} | Length: {len(response.text)} | Word: {word}"
                    findings.append(finding)
                except:
                    pass
            
            # Aktualisiere das Ergebnis
            result["success"] = True
            result["findings"] = findings
            result["count"] = len(findings)
            result["stdout"] = f"Tested {len(words)} words, found {result['count']} results"
            
            # Schreibe in Ausgabedatei, wenn angegeben
            if output_file:
                with open(output_file, "w") as f:
                    json.dump({"results": findings}, f, indent=2)
            
            return result
            
        except Exception as e:
            logger.error(f"Fehler beim Fallback-Fuzzing: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": 1,
                "command": f"fallback_fuzz({url}, {wordlist})",
                "fallback": True,
                "findings": [],
                "count": 0
            }
