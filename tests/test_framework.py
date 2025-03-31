#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Test Script
======================================

Dieses Skript testet die Funktionalität des XSS Hunter Pro Frameworks.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import json
import logging
import time
import argparse
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.TestScript")

# Versuche, die Module zu importieren
try:
    from modules.payload_manager import PayloadManager
    PAYLOAD_MANAGER_AVAILABLE = True
except ImportError:
    logger.warning("PayloadManager konnte nicht importiert werden.")
    PAYLOAD_MANAGER_AVAILABLE = False

try:
    from modules.report_generator import ReportGenerator
    REPORT_GENERATOR_AVAILABLE = True
except ImportError:
    logger.warning("ReportGenerator konnte nicht importiert werden.")
    REPORT_GENERATOR_AVAILABLE = False

try:
    from modules.target_discovery import TargetDiscovery
    TARGET_DISCOVERY_AVAILABLE = True
except ImportError:
    logger.warning("TargetDiscovery konnte nicht importiert werden.")
    TARGET_DISCOVERY_AVAILABLE = False

try:
    from modules.vuln_categorization import VulnerabilityCategorization
    VULN_CATEGORIZATION_AVAILABLE = True
except ImportError:
    logger.warning("VulnerabilityCategorization konnte nicht importiert werden.")
    VULN_CATEGORIZATION_AVAILABLE = False

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


class TestFramework:
    """
    Klasse zum Testen des XSS Hunter Pro Frameworks.
    """
    
    def __init__(self):
        """
        Initialisiert den Test-Framework.
        """
        self.test_results = {
            "payload_manager": {"status": "not_tested", "details": []},
            "report_generator": {"status": "not_tested", "details": []},
            "target_discovery": {"status": "not_tested", "details": []},
            "vuln_categorization": {"status": "not_tested", "details": []},
            "integration": {"status": "not_tested", "details": []}
        }
    
    def run_all_tests(self):
        """
        Führt alle Tests aus.
        
        Returns:
            Die Testergebnisse.
        """
        logger.info("Starte alle Tests...")
        
        # Teste den PayloadManager
        self.test_payload_manager()
        
        # Teste den ReportGenerator
        self.test_report_generator()
        
        # Teste die TargetDiscovery
        self.test_target_discovery()
        
        # Teste die VulnerabilityCategorization
        self.test_vuln_categorization()
        
        # Teste die Integration
        self.test_integration()
        
        # Zeige die Testergebnisse an
        self.show_test_results()
        
        return self.test_results
    
    def test_payload_manager(self):
        """
        Testet den PayloadManager.
        
        Returns:
            Die Testergebnisse für den PayloadManager.
        """
        logger.info("Teste PayloadManager...")
        
        if not PAYLOAD_MANAGER_AVAILABLE:
            self.test_results["payload_manager"]["status"] = "failed"
            self.test_results["payload_manager"]["details"].append("PayloadManager konnte nicht importiert werden.")
            return self.test_results["payload_manager"]
        
        try:
            # Erstelle einen PayloadManager
            payload_manager = PayloadManager()
            
            # Teste das Laden von Payloads
            payloads = payload_manager.load_payloads()
            
            if not payloads:
                self.test_results["payload_manager"]["status"] = "failed"
                self.test_results["payload_manager"]["details"].append("Keine Payloads geladen.")
                return self.test_results["payload_manager"]
            
            self.test_results["payload_manager"]["details"].append(f"{len(payloads)} Payloads geladen.")
            
            # Teste das Generieren von Payloads
            payload = payload_manager.generate_payload("basic")
            
            if not payload:
                self.test_results["payload_manager"]["status"] = "failed"
                self.test_results["payload_manager"]["details"].append("Konnte keinen Payload generieren.")
                return self.test_results["payload_manager"]
            
            self.test_results["payload_manager"]["details"].append(f"Payload generiert: {payload}")
            
            # Teste das Generieren von Payload-Variationen
            variations = payload_manager.generate_variations(payload)
            
            if not variations:
                self.test_results["payload_manager"]["status"] = "failed"
                self.test_results["payload_manager"]["details"].append("Konnte keine Payload-Variationen generieren.")
                return self.test_results["payload_manager"]
            
            self.test_results["payload_manager"]["details"].append(f"{len(variations)} Payload-Variationen generiert.")
            
            # Teste das Optimieren von Payloads
            optimized_payload = payload_manager.optimize_payload(payload, "html")
            
            if not optimized_payload:
                self.test_results["payload_manager"]["details"].append("Konnte keinen optimierten Payload generieren.")
            else:
                self.test_results["payload_manager"]["details"].append(f"Optimierter Payload generiert: {optimized_payload}")
            
            # Teste erfolgreich
            self.test_results["payload_manager"]["status"] = "passed"
            
            return self.test_results["payload_manager"]
        except Exception as e:
            self.test_results["payload_manager"]["status"] = "failed"
            self.test_results["payload_manager"]["details"].append(f"Fehler: {str(e)}")
            
            return self.test_results["payload_manager"]
    
    def test_report_generator(self):
        """
        Testet den ReportGenerator.
        
        Returns:
            Die Testergebnisse für den ReportGenerator.
        """
        logger.info("Teste ReportGenerator...")
        
        if not REPORT_GENERATOR_AVAILABLE:
            self.test_results["report_generator"]["status"] = "failed"
            self.test_results["report_generator"]["details"].append("ReportGenerator konnte nicht importiert werden.")
            return self.test_results["report_generator"]
        
        try:
            # Erstelle einen ReportGenerator
            report_generator = ReportGenerator()
            
            # Erstelle einige Beispiel-Schwachstellen
            vulnerabilities = [
                {
                    "title": "Reflected XSS in Search Parameter",
                    "url": "https://example.com/search?q=test",
                    "param": "q",
                    "payload": "<script>alert('XSS')</script>",
                    "severity": "high",
                    "context": "html",
                    "description": "The search parameter is vulnerable to reflected XSS."
                },
                {
                    "title": "Stored XSS in Comment Field",
                    "url": "https://example.com/post/1",
                    "param": "comment",
                    "payload": "<img src=x onerror=alert('XSS')>",
                    "severity": "medium",
                    "context": "html",
                    "description": "The comment field is vulnerable to stored XSS."
                }
            ]
            
            # Teste das Generieren eines HTML-Berichts
            html_report = report_generator.generate_report(vulnerabilities, "html")
            
            if not html_report:
                self.test_results["report_generator"]["status"] = "failed"
                self.test_results["report_generator"]["details"].append("Konnte keinen HTML-Bericht generieren.")
                return self.test_results["report_generator"]
            
            self.test_results["report_generator"]["details"].append(f"HTML-Bericht generiert: {html_report}")
            
            # Teste das Generieren eines JSON-Berichts
            json_report = report_generator.generate_report(vulnerabilities, "json")
            
            if not json_report:
                self.test_results["report_generator"]["status"] = "failed"
                self.test_results["report_generator"]["details"].append("Konnte keinen JSON-Bericht generieren.")
                return self.test_results["report_generator"]
            
            self.test_results["report_generator"]["details"].append(f"JSON-Bericht generiert: {json_report}")
            
            # Teste das Generieren eines Text-Berichts
            text_report = report_generator.generate_report(vulnerabilities, "txt")
            
            if not text_report:
                self.test_results["report_generator"]["status"] = "failed"
                self.test_results["report_generator"]["details"].append("Konnte keinen Text-Bericht generieren.")
                return self.test_results["report_generator"]
            
            self.test_results["report_generator"]["details"].append(f"Text-Bericht generiert: {text_report}")
            
            # Teste erfolgreich
            self.test_results["report_generator"]["status"] = "passed"
            
            return self.test_results["report_generator"]
        except Exception as e:
            self.test_results["report_generator"]["status"] = "failed"
            self.test_results["report_generator"]["details"].append(f"Fehler: {str(e)}")
            
            return self.test_results["report_generator"]
    
    def test_target_discovery(self):
        """
        Testet die TargetDiscovery.
        
        Returns:
            Die Testergebnisse für die TargetDiscovery.
        """
        logger.info("Teste TargetDiscovery...")
        
        if not TARGET_DISCOVERY_AVAILABLE:
            self.test_results["target_discovery"]["status"] = "failed"
            self.test_results["target_discovery"]["details"].append("TargetDiscovery konnte nicht importiert werden.")
            return self.test_results["target_discovery"]
        
        try:
            # Erstelle eine TargetDiscovery
            target_discovery = TargetDiscovery()
            
            # Teste die URL-Analyse (ohne tatsächliche Anfrage)
            # Simuliere die Analyseergebnisse
            analysis_results = {
                "success": True,
                "url": "https://example.com",
                "parameters": [{"name": "q", "source": "url"}],
                "forms": [{"action": "https://example.com/search", "method": "GET", "inputs": [{"name": "q", "type": "text"}]}],
                "links": ["https://example.com/about", "https://example.com/contact"],
                "javascript": [{"type": "inline", "content": "console.log('Hello, World!');"}],
                "potential_vulnerabilities": [{"type": "url_parameter", "url": "https://example.com", "param": "q", "reason": "URL-Parameter können anfällig für Reflected XSS sein."}]
            }
            
            # Überprüfe, ob die TargetDiscovery-Klasse die erwarteten Methoden hat
            if not hasattr(target_discovery, "analyze_url"):
                self.test_results["target_discovery"]["status"] = "failed"
                self.test_results["target_discovery"]["details"].append("TargetDiscovery hat keine analyze_url-Methode.")
                return self.test_results["target_discovery"]
            
            self.test_results["target_discovery"]["details"].append("TargetDiscovery hat die analyze_url-Methode.")
            
            if not hasattr(target_discovery, "crawl"):
                self.test_results["target_discovery"]["status"] = "failed"
                self.test_results["target_discovery"]["details"].append("TargetDiscovery hat keine crawl-Methode.")
                return self.test_results["target_discovery"]
            
            self.test_results["target_discovery"]["details"].append("TargetDiscovery hat die crawl-Methode.")
            
            if not hasattr(target_discovery, "scan_subdomains"):
                self.test_results["target_discovery"]["status"] = "failed"
                self.test_results["target_discovery"]["details"].append("TargetDiscovery hat keine scan_subdomains-Methode.")
                return self.test_results["target_discovery"]
            
            self.test_results["target_discovery"]["details"].append("TargetDiscovery hat die scan_subdomains-Methode.")
            
            # Teste erfolgreich
            self.test_results["target_discovery"]["status"] = "passed"
            
            return self.test_results["target_discovery"]
        except Exception as e:
            self.test_results["target_discovery"]["status"] = "failed"
            self.test_results["target_discovery"]["details"].append(f"Fehler: {str(e)}")
            
            return self.test_results["target_discovery"]
    
    def test_vuln_categorization(self):
        """
        Testet die VulnerabilityCategorization.
        
        Returns:
            Die Testergebnisse für die VulnerabilityCategorization.
        """
        logger.info("Teste VulnerabilityCategorization...")
        
        if not VULN_CATEGORIZATION_AVAILABLE:
            self.test_results["vuln_categorization"]["status"] = "failed"
            self.test_results["vuln_categorization"]["details"].append("VulnerabilityCategorization konnte nicht importiert werden.")
            return self.test_results["vuln_categorization"]
        
        try:
            # Erstelle eine VulnerabilityCategorization
            vuln_categorization = VulnerabilityCategorization()
            
            # Erstelle eine Beispiel-Schwachstelle
            vulnerability = {
                "url": "https://example.com/search?q=test",
                "param": "q",
                "payload": "<script>alert('XSS')</script>",
                "description": "Die Suchanfrage wird ohne Bereinigung in die Antwort eingefügt."
            }
            
            # Teste die Kategorisierung
            categorized = vuln_categorization.categorize_vulnerability(vulnerability)
            
            if not categorized:
                self.test_results["vuln_categorization"]["status"] = "failed"
                self.test_results["vuln_categorization"]["details"].append("Konnte die Schwachstelle nicht kategorisieren.")
                return self.test_results["vuln_categorization"]
            
            self.test_results["vuln_categorization"]["details"].append("Schwachstelle kategorisiert.")
            
            # Überprüfe, ob die Kategorisierung die erwarteten Felder enthält
            expected_fields = ["xss_type", "xss_context", "cvss_score", "cvss_vector", "cvss_severity", "impacts", "mitigations"]
            
            for field in expected_fields:
                if field not in categorized:
                    self.test_results["vuln_categorization"]["status"] = "failed"
                    self.test_results["vuln_categorization"]["details"].append(f"Kategorisierung enthält nicht das Feld '{field}'.")
                    return self.test_results["vuln_categorization"]
            
            self.test_results["vuln_categorization"]["details"].append("Kategorisierung enthält alle erwarteten Felder.")
            
            # Teste die Kategorisierung mehrerer Schwachstellen
            vulnerabilities = [
                {
                    "url": "https://example.com/search?q=test",
                    "param": "q",
                    "payload": "<script>alert('XSS')</script>",
                    "description": "Die Suchanfrage wird ohne Bereinigung in die Antwort eingefügt."
                },
                {
                    "url": "https://example.com/post/1",
                    "param": "comment",
                    "payload": "<img src=x onerror=alert('XSS')>",
                    "description": "Der Kommentar wird ohne Bereinigung in der Datenbank gespeichert und später angezeigt."
                }
            ]
            
            categorized_vulnerabilities = vuln_categorization.categorize_vulnerabilities(vulnerabilities)
            
            if not categorized_vulnerabilities or len(categorized_vulnerabilities) != len(vulnerabilities):
                self.test_results["vuln_categorization"]["status"] = "failed"
                self.test_results["vuln_categorization"]["details"].append("Konnte nicht alle Schwachstellen kategorisieren.")
                return self.test_results["vuln_categorization"]
            
            self.test_results["vuln_categorization"]["details"].append("Alle Schwachstellen kategorisiert.")
            
            # Teste die Statistiken
            statistics = vuln_categorization.get_vulnerability_statistics(categorized_vulnerabilities)
            
            if not statistics:
                self.test_results["vuln_categorization"]["status"] = "failed"
                self.test_results["vuln_categorization"]["details"].append("Konnte keine Statistiken erstellen.")
                return self.test_results["vuln_categorization"]
            
            self.test_results["vuln_categorization"]["details"].append("Statistiken erstellt.")
            
            # Teste die Empfehlungen
            recommendations = vuln_categorization.get_vulnerability_recommendations(categorized_vulnerabilities)
            
            if not recommendations:
                self.test_results["vuln_categorization"]["status"] = "failed"
                self.test_results["vuln_categorization"]["details"].append("Konnte keine Empfehlungen erstellen.")
                return self.test_results["vuln_categorization"]
            
            self.test_results["vuln_categorization"]["details"].append("Empfehlungen erstellt.")
            
            # Teste erfolgreich
            self.test_results["vuln_categorization"]["status"] = "passed"
            
            return self.test_results["vuln_categorization"]
        except Exception as e:
            self.test_results["vuln_categorization"]["status"] = "failed"
            self.test_results["vuln_categorization"]["details"].append(f"Fehler: {str(e)}")
            
            return self.test_results["vuln_categorization"]
    
    def test_integration(self):
        """
        Testet die Integration der Module.
        
        Returns:
            Die Testergebnisse für die Integration.
        """
        logger.info("Teste Integration...")
        
        # Überprüfe, ob alle Module verfügbar sind
        if not PAYLOAD_MANAGER_AVAILABLE or not REPORT_GENERATOR_AVAILABLE or not TARGET_DISCOVERY_AVAILABLE or not VULN_CATEGORIZATION_AVAILABLE:
            self.test_results["integration"]["status"] = "failed"
            self.test_results["integration"]["details"].append("Nicht alle Module sind verfügbar.")
            return self.test_results["integration"]
        
        try:
            # Erstelle die Module
            payload_manager = PayloadManager()
            report_generator = ReportGenerator()
            target_discovery = TargetDiscovery()
            vuln_categorization = VulnerabilityCategorization()
            
            # Simuliere einen vollständigen Workflow
            
            # 1. Generiere einen Payload
            payload = payload_manager.generate_payload("basic")
            
            if not payload:
                self.test_results["integration"]["status"] = "failed"
                self.test_results["integration"]["details"].append("Konnte keinen Payload generieren.")
                return self.test_results["integration"]
            
            self.test_results["integration"]["details"].append(f"Payload generiert: {payload}")
            
            # 2. Simuliere die Entdeckung einer Schwachstelle
            vulnerability = {
                "url": "https://example.com/search?q=test",
                "param": "q",
                "payload": payload,
                "description": "Die Suchanfrage wird ohne Bereinigung in die Antwort eingefügt."
            }
            
            self.test_results["integration"]["details"].append("Schwachstelle simuliert.")
            
            # 3. Kategorisiere die Schwachstelle
            categorized = vuln_categorization.categorize_vulnerability(vulnerability)
            
            if not categorized:
                self.test_results["integration"]["status"] = "failed"
                self.test_results["integration"]["details"].append("Konnte die Schwachstelle nicht kategorisieren.")
                return self.test_results["integration"]
            
            self.test_results["integration"]["details"].append("Schwachstelle kategorisiert.")
            
            # 4. Generiere einen Bericht
            report = report_generator.generate_report([categorized], "json")
            
            if not report:
                self.test_results["integration"]["status"] = "failed"
                self.test_results["integration"]["details"].append("Konnte keinen Bericht generieren.")
                return self.test_results["integration"]
            
            self.test_results["integration"]["details"].append(f"Bericht generiert: {report}")
            
            # Teste erfolgreich
            self.test_results["integration"]["status"] = "passed"
            
            return self.test_results["integration"]
        except Exception as e:
            self.test_results["integration"]["status"] = "failed"
            self.test_results["integration"]["details"].append(f"Fehler: {str(e)}")
            
            return self.test_results["integration"]
    
    def show_test_results(self):
        """
        Zeigt die Testergebnisse an.
        """
        logger.info("Testergebnisse:")
        
        for module, results in self.test_results.items():
            status = results["status"]
            details = results["details"]
            
            if status == "passed":
                logger.info(f"✅ {module}: PASSED")
            elif status == "failed":
                logger.error(f"❌ {module}: FAILED")
            else:
                logger.warning(f"⚠️ {module}: {status}")
            
            for detail in details:
                logger.info(f"  - {detail}")
    
    def get_summary(self):
        """
        Gibt eine Zusammenfassung der Testergebnisse zurück.
        
        Returns:
            Eine Zusammenfassung der Testergebnisse.
        """
        passed = sum(1 for results in self.test_results.values() if results["status"] == "passed")
        failed = sum(1 for results in self.test_results.values() if results["status"] == "failed")
        not_tested = sum(1 for results in self.test_results.values() if results["status"] == "not_tested")
        
        return {
            "total": len(self.test_results),
            "passed": passed,
            "failed": failed,
            "not_tested": not_tested,
            "success_rate": passed / len(self.test_results) if len(self.test_results) > 0 else 0
        }


def main():
    """
    Hauptfunktion.
    """
    # Parse die Kommandozeilenargumente
    parser = argparse.ArgumentParser(description="XSS Hunter Pro Framework - Test Script")
    parser.add_argument("--module", choices=["payload_manager", "report_generator", "target_discovery", "vuln_categorization", "integration", "all"], default="all", help="Das zu testende Modul")
    parser.add_argument("--verbose", action="store_true", help="Ausführliche Ausgabe")
    
    args = parser.parse_args()
    
    # Setze das Logging-Level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Erstelle den Test-Framework
    test_framework = TestFramework()
    
    # Führe die Tests aus
    if args.module == "all":
        test_framework.run_all_tests()
    elif args.module == "payload_manager":
        test_framework.test_payload_manager()
    elif args.module == "report_generator":
        test_framework.test_report_generator()
    elif args.module == "target_discovery":
        test_framework.test_target_discovery()
    elif args.module == "vuln_categorization":
        test_framework.test_vuln_categorization()
    elif args.module == "integration":
        test_framework.test_integration()
    
    # Zeige die Testergebnisse an
    test_framework.show_test_results()
    
    # Zeige die Zusammenfassung an
    summary = test_framework.get_summary()
    
    logger.info(f"Zusammenfassung: {summary['passed']}/{summary['total']} Tests bestanden ({summary['success_rate'] * 100:.2f}%)")
    
    # Beende mit dem entsprechenden Exit-Code
    if summary["failed"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
