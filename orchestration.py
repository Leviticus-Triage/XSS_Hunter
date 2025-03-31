#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Orchestration Module
=============================================

Diese Datei implementiert die Orchestrierung der verschiedenen Komponenten des XSS Hunter Frameworks.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import logging
import time
import json
from typing import Dict, List, Optional, Any, Tuple, Union

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.Orchestration")


class Orchestrator:
    """Klasse für die Orchestrierung der Framework-Komponenten."""

    def __init__(self, target_discovery=None, payload_manager=None, exploitation_engine=None, 
                 callback_server=None, xss_validator=None, vuln_classifier=None, 
                 report_generator=None, browser_screenshot=None):
        """
        Initialisiert den Orchestrator.

        Args:
            target_discovery: Die Komponente für die Zielentdeckung.
            payload_manager: Die Komponente für die Payload-Verwaltung.
            exploitation_engine: Die Komponente für die Exploitation.
            callback_server: Die Komponente für den Callback-Server.
            xss_validator: Die Komponente für die XSS-Validierung.
            vuln_classifier: Die Komponente für die Schwachstellenklassifizierung.
            report_generator: Die Komponente für die Berichterstellung.
            browser_screenshot: Die Komponente für die Screenshot-Erstellung.
        """
        self.target_discovery = target_discovery
        self.payload_manager = payload_manager
        self.exploitation_engine = exploitation_engine
        self.callback_server = callback_server
        self.xss_validator = xss_validator
        self.vuln_classifier = vuln_classifier
        self.report_generator = report_generator
        self.browser_screenshot = browser_screenshot
        
        logger.info("Orchestrator initialisiert")

    def run_scan(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Führt einen Scan durch.

        Args:
            config: Die Konfiguration für den Scan.

        Returns:
            Ein Dictionary mit den Ergebnissen des Scans.
        """
        try:
            logger.info(f"Starte Scan für URL: {config.get('url')}")
            
            # Extrahiere die Konfigurationsparameter
            url = config.get("url")
            depth = config.get("depth", 3)
            timeout = config.get("timeout", 30)
            user_agent = config.get("user_agent")
            cookies = config.get("cookies")
            headers = config.get("headers")
            proxy = config.get("proxy")
            threads = config.get("threads", 10)
            output_file = config.get("output_file")
            
            # Validiere die URL
            if not url:
                return {
                    "success": False,
                    "error": "Keine URL angegeben",
                    "vulnerabilities": []
                }
                
            # Starte die Zielentdeckung
            logger.info("Starte Zielentdeckung...")
            target_config = {
                "url": url,
                "depth": depth,
                "timeout": timeout,
                "user_agent": user_agent,
                "cookies": cookies,
                "headers": headers,
                "proxy": proxy,
                "threads": threads
            }
            
            targets = self.target_discovery.discover_targets(target_config)
            
            if not targets["success"]:
                return {
                    "success": False,
                    "error": f"Fehler bei der Zielentdeckung: {targets['error']}",
                    "vulnerabilities": []
                }
                
            logger.info(f"{len(targets['targets'])} Ziele entdeckt")
            
            # Generiere Payloads
            logger.info("Generiere Payloads...")
            payloads = self.payload_manager.get_payloads()
            
            if not payloads["success"]:
                return {
                    "success": False,
                    "error": f"Fehler bei der Payload-Generierung: {payloads['error']}",
                    "vulnerabilities": []
                }
                
            logger.info(f"{len(payloads['payloads'])} Payloads generiert")
            
            # Teste die Ziele auf XSS-Schwachstellen
            logger.info("Teste Ziele auf XSS-Schwachstellen...")
            vulnerabilities = []
            
            for target in targets["targets"]:
                logger.debug(f"Teste Ziel: {target['url']}")
                
                for payload in payloads["payloads"]:
                    # Teste den Payload
                    test_result = self.xss_validator.test_payload(
                        url=target["url"],
                        parameter=target.get("parameter"),
                        payload=payload,
                        user_agent=user_agent,
                        cookies=cookies,
                        headers=headers,
                        proxy=proxy,
                        timeout=timeout
                    )
                    
                    if test_result["success"] and test_result["vulnerable"]:
                        # XSS-Schwachstelle gefunden
                        logger.info(f"XSS-Schwachstelle gefunden: {target['url']}, Parameter: {target.get('parameter')}")
                        
                        # Klassifiziere die Schwachstelle
                        classification = self.vuln_classifier.classify_vulnerability(
                            url=target["url"],
                            parameter=target.get("parameter"),
                            payload=payload,
                            response=test_result.get("response", "")
                        )
                        
                        # Erstelle einen Screenshot, wenn möglich
                        screenshot = None
                        if self.browser_screenshot:
                            screenshot = self.browser_screenshot.capture_xss(
                                url=test_result["exploit_url"],
                                payload=payload,
                                context={
                                    "parameter": target.get("parameter"),
                                    "vulnerability_type": classification.get("type", "XSS")
                                }
                            )
                        
                        # Füge die Schwachstelle zur Liste hinzu
                        vulnerability = {
                            "url": target["url"],
                            "parameter": target.get("parameter"),
                            "payload": payload,
                            "type": classification.get("type", "XSS"),
                            "severity": classification.get("severity", "high"),
                            "description": classification.get("description", "Cross-Site Scripting (XSS) Vulnerability"),
                            "exploit_url": test_result["exploit_url"],
                            "screenshot": screenshot,
                            "timestamp": int(time.time())
                        }
                        
                        vulnerabilities.append(vulnerability)
                        
                        # Breche die Payload-Schleife ab, wenn eine Schwachstelle gefunden wurde
                        break
            
            logger.info(f"{len(vulnerabilities)} Schwachstellen gefunden")
            
            # Speichere die Ergebnisse, wenn gewünscht
            if output_file:
                try:
                    with open(output_file, "w") as f:
                        json.dump(vulnerabilities, f, indent=2)
                    logger.info(f"Ergebnisse in {output_file} gespeichert")
                except Exception as e:
                    logger.error(f"Fehler beim Speichern der Ergebnisse: {e}")
            
            return {
                "success": True,
                "vulnerabilities": vulnerabilities,
                "target_count": len(targets["targets"]),
                "payload_count": len(payloads["payloads"])
            }
            
        except Exception as e:
            logger.error(f"Fehler beim Scan: {e}")
            return {
                "success": False,
                "error": str(e),
                "vulnerabilities": []
            }

    def run_exploitation(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Führt eine Exploitation durch.

        Args:
            config: Die Konfiguration für die Exploitation.

        Returns:
            Ein Dictionary mit den Ergebnissen der Exploitation.
        """
        try:
            logger.info(f"Starte Exploitation für URL: {config.get('url')}, Parameter: {config.get('param')}")
            
            # Extrahiere die Konfigurationsparameter
            url = config.get("url")
            param = config.get("param")
            exploit_type = config.get("exploit_type")
            payload = config.get("payload")
            user_agent = config.get("user_agent")
            cookies = config.get("cookies")
            headers = config.get("headers")
            proxy = config.get("proxy")
            timeout = config.get("timeout", 30)
            output_file = config.get("output_file")
            
            # Validiere die Parameter
            if not url:
                return {
                    "success": False,
                    "error": "Keine URL angegeben"
                }
                
            if not param:
                return {
                    "success": False,
                    "error": "Kein Parameter angegeben"
                }
                
            if not exploit_type:
                return {
                    "success": False,
                    "error": "Kein Exploit-Typ angegeben"
                }
                
            # Generiere einen Payload, wenn keiner angegeben ist
            if not payload:
                logger.info("Generiere Payload...")
                payload_result = self.payload_manager.generate_payload_for_context(
                    context="html",
                    exploit_type=exploit_type
                )
                
                if not payload_result["success"]:
                    return {
                        "success": False,
                        "error": f"Fehler bei der Payload-Generierung: {payload_result['error']}"
                    }
                    
                payload = payload_result["payload"]
                
            logger.info(f"Verwende Payload: {payload}")
            
            # Führe die Exploitation durch
            logger.info("Führe Exploitation durch...")
            exploit_config = {
                "url": url,
                "parameter": param,
                "payload": payload,
                "exploit_type": exploit_type,
                "user_agent": user_agent,
                "cookies": cookies,
                "headers": headers,
                "proxy": proxy,
                "timeout": timeout
            }
            
            exploit_result = self.exploitation_engine.exploit(exploit_config)
            
            if not exploit_result["success"]:
                return {
                    "success": False,
                    "error": f"Fehler bei der Exploitation: {exploit_result['error']}"
                }
                
            logger.info("Exploitation erfolgreich")
            
            # Speichere die Ergebnisse, wenn gewünscht
            if output_file:
                try:
                    with open(output_file, "w") as f:
                        json.dump(exploit_result, f, indent=2)
                    logger.info(f"Ergebnisse in {output_file} gespeichert")
                except Exception as e:
                    logger.error(f"Fehler beim Speichern der Ergebnisse: {e}")
            
            return {
                "success": True,
                "message": "Exploitation erfolgreich",
                "exploit_url": exploit_result["exploit_url"],
                "payload": payload,
                "exploit_type": exploit_type,
                "callback_url": exploit_result.get("callback_url")
            }
            
        except Exception as e:
            logger.error(f"Fehler bei der Exploitation: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def run_payload_generation(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Führt eine Payload-Generierung durch.

        Args:
            config: Die Konfiguration für die Payload-Generierung.

        Returns:
            Ein Dictionary mit den generierten Payloads.
        """
        try:
            logger.info("Starte Payload-Generierung")
            
            # Extrahiere die Konfigurationsparameter
            context = config.get("context", "html")
            use_ml = config.get("use_ml", False)
            custom_template = config.get("custom_template")
            bypass_waf = config.get("bypass_waf", False)
            output_file = config.get("output_file")
            
            # Generiere die Payloads
            logger.info(f"Generiere Payloads für Kontext: {context}")
            
            payload_config = {
                "context": context,
                "use_ml": use_ml,
                "custom_template": custom_template,
                "bypass_waf": bypass_waf
            }
            
            payload_result = self.payload_manager.generate_payloads(payload_config)
            
            if not payload_result["success"]:
                return {
                    "success": False,
                    "error": f"Fehler bei der Payload-Generierung: {payload_result['error']}",
                    "payloads": []
                }
                
            logger.info(f"{len(payload_result['payloads'])} Payloads generiert")
            
            # Speichere die Ergebnisse, wenn gewünscht
            if output_file:
                try:
                    with open(output_file, "w") as f:
                        json.dump(payload_result["payloads"], f, indent=2)
                    logger.info(f"Payloads in {output_file} gespeichert")
                except Exception as e:
                    logger.error(f"Fehler beim Speichern der Payloads: {e}")
            
            return {
                "success": True,
                "payloads": payload_result["payloads"],
                "context": context,
                "use_ml": use_ml,
                "bypass_waf": bypass_waf
            }
            
        except Exception as e:
            logger.error(f"Fehler bei der Payload-Generierung: {e}")
            return {
                "success": False,
                "error": str(e),
                "payloads": []
            }

    def run_report_generation(self, vulnerabilities: List[Dict[str, Any]], output_file: str, 
                             format: str = "html", config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Führt eine Berichterstellung durch.

        Args:
            vulnerabilities: Die Liste der Schwachstellen.
            output_file: Der Pfad zur Ausgabedatei.
            format: Das Format des Berichts.
            config: Zusätzliche Konfigurationsoptionen.

        Returns:
            Ein Dictionary mit den Ergebnissen der Berichterstellung.
        """
        try:
            logger.info(f"Starte Berichterstellung im Format: {format}")
            
            if not vulnerabilities:
                return {
                    "success": False,
                    "error": "Keine Schwachstellen angegeben",
                    "report_file": None
                }
                
            if not output_file:
                return {
                    "success": False,
                    "error": "Keine Ausgabedatei angegeben",
                    "report_file": None
                }
                
            # Erstelle den Bericht
            logger.info(f"Erstelle Bericht für {len(vulnerabilities)} Schwachstellen")
            
            report_result = self.report_generator.generate_report(
                vulnerabilities=vulnerabilities,
                output_file=output_file,
                format=format,
                config=config
            )
            
            if not report_result["success"]:
                return {
                    "success": False,
                    "error": f"Fehler bei der Berichterstellung: {report_result['error']}",
                    "report_file": None
                }
                
            logger.info(f"Bericht erstellt: {report_result['report_file']}")
            
            return {
                "success": True,
                "report_file": report_result["report_file"],
                "format": format,
                "vulnerability_count": len(vulnerabilities)
            }
            
        except Exception as e:
            logger.error(f"Fehler bei der Berichterstellung: {e}")
            return {
                "success": False,
                "error": str(e),
                "report_file": None
            }


# Beispiel für die Verwendung
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(level=logging.INFO)
    
    # Erstelle Mock-Objekte für die Komponenten
    class MockTargetDiscovery:
        def discover_targets(self, config):
            return {
                "success": True,
                "targets": [
                    {"url": "https://example.com/search", "parameter": "q"},
                    {"url": "https://example.com/login", "parameter": "username"}
                ]
            }
    
    class MockPayloadManager:
        def get_payloads(self):
            return {
                "success": True,
                "payloads": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>"
                ]
            }
        
        def generate_payload_for_context(self, context, exploit_type):
            return {
                "success": True,
                "payload": "<script>alert('XSS')</script>"
            }
        
        def generate_payloads(self, config):
            return {
                "success": True,
                "payloads": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>"
                ]
            }
    
    class MockExploitationEngine:
        def exploit(self, config):
            return {
                "success": True,
                "exploit_url": f"{config['url']}?{config['parameter']}={config['payload']}",
                "callback_url": "https://example.com/callback"
            }
    
    class MockXSSValidator:
        def test_payload(self, url, parameter, payload, **kwargs):
            return {
                "success": True,
                "vulnerable": True,
                "exploit_url": f"{url}?{parameter}={payload}"
            }
    
    class MockVulnClassifier:
        def classify_vulnerability(self, url, parameter, payload, response):
            return {
                "type": "Reflected XSS",
                "severity": "high",
                "description": "Cross-Site Scripting (XSS) Vulnerability"
            }
    
    class MockReportGenerator:
        def generate_report(self, vulnerabilities, output_file, format, config=None):
            return {
                "success": True,
                "report_file": output_file
            }
    
    class MockBrowserScreenshot:
        def capture_xss(self, url, payload, context=None):
            return f"screenshots/xss_{int(time.time())}.png"
    
    # Erstelle den Orchestrator
    orchestrator = Orchestrator(
        target_discovery=MockTargetDiscovery(),
        payload_manager=MockPayloadManager(),
        exploitation_engine=MockExploitationEngine(),
        xss_validator=MockXSSValidator(),
        vuln_classifier=MockVulnClassifier(),
        report_generator=MockReportGenerator(),
        browser_screenshot=MockBrowserScreenshot()
    )
    
    # Teste den Scan
    scan_config = {
        "url": "https://example.com",
        "depth": 3,
        "timeout": 30
    }
    
    scan_result = orchestrator.run_scan(scan_config)
    print(f"Scan-Ergebnis: {scan_result}")
    
    # Teste die Exploitation
    exploit_config = {
        "url": "https://example.com/search",
        "param": "q",
        "exploit_type": "data_theft"
    }
    
    exploit_result = orchestrator.run_exploitation(exploit_config)
    print(f"Exploitation-Ergebnis: {exploit_result}")
    
    # Teste die Payload-Generierung
    payload_config = {
        "context": "html",
        "use_ml": True,
        "bypass_waf": True
    }
    
    payload_result = orchestrator.run_payload_generation(payload_config)
    print(f"Payload-Generierung-Ergebnis: {payload_result}")
    
    # Teste die Berichterstellung
    vulnerabilities = [
        {
            "url": "https://example.com/search",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "type": "Reflected XSS",
            "severity": "high",
            "description": "Cross-Site Scripting (XSS) Vulnerability",
            "exploit_url": "https://example.com/search?q=<script>alert(1)</script>",
            "screenshot": "screenshots/xss_1234567890.png",
            "timestamp": int(time.time())
        }
    ]
    
    report_result = orchestrator.run_report_generation(
        vulnerabilities=vulnerabilities,
        output_file="report.html",
        format="html"
    )
    print(f"Berichterstellung-Ergebnis: {report_result}")
