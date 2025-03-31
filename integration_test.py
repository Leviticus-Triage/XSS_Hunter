#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Integration Test
=============================================

Dieses Modul implementiert Integrationstests für das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import logging
import unittest
import json
import time
import tempfile
import shutil
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguration für Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("XSSHunterPro.IntegrationTest")

# Füge das Hauptverzeichnis zum Pfad hinzu
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

# Importiere die zu testenden Module
try:
    from modules import payload_manager, callback_server, exploitation, report_generator, target_discovery, vuln_categorization
    from integrations import webcrawler, fuzzing, subdomain_discovery, vulnerability_scanner, tool_adapters
    import utils, logger as log_module, error_handler, orchestration, plugin_system, ml_payload_optimizer
except ImportError as e:
    logger.error(f"Fehler beim Importieren der Module: {e}")
    sys.exit(1)


class IntegrationTestCase(unittest.TestCase):
    """
    Basis-Testklasse für Integrationstests.
    """

    def setUp(self):
        """
        Wird vor jedem Test ausgeführt.
        """
        # Erstelle ein temporäres Verzeichnis
        self.temp_dir = tempfile.mkdtemp()
        
        # Erstelle eine Testkonfiguration
        self.config = {
            "general": {
                "debug_mode": True,
                "log_level": "DEBUG",
                "log_file": os.path.join(self.temp_dir, "test.log"),
                "temp_dir": self.temp_dir,
                "output_dir": os.path.join(self.temp_dir, "output"),
                "max_threads": 2,
                "timeout": 5,
                "user_agent": "XSSHunterPro-Test/1.0",
                "proxy": None
            },
            "scanning": {
                "default_depth": 1,
                "max_depth": 2,
                "max_urls": 10,
                "respect_robots_txt": False,
                "crawl_same_domain_only": True,
                "exclude_patterns": [],
                "include_patterns": [],
                "scan_forms": True,
                "scan_headers": True,
                "scan_cookies": True,
                "scan_url_parameters": True
            },
            "exploitation": {
                "default_exploit_type": "alert",
                "callback_server": {
                    "host": "127.0.0.1",
                    "port": 8080,
                    "path": "/callback",
                    "auto_start": False
                },
                "screenshot": {
                    "enabled": False,
                    "delay": 1000,
                    "format": "png",
                    "quality": 80
                }
            },
            "payloads": {
                "use_ml": False,
                "ml_model": "default",
                "payloads_dir": "payloads",
                "custom_payloads_file": "payloads/custom.json"
            },
            "reporting": {
                "default_format": "json",
                "include_screenshots": False,
                "include_payloads": True,
                "include_requests": True,
                "include_responses": False,
                "template_dir": "templates",
                "default_template": "default"
            },
            "integrations": {
                "enabled": False,
                "tools": {}
            }
        }
        
        # Erstelle die Ausgabeverzeichnisse
        os.makedirs(self.config["general"]["output_dir"], exist_ok=True)
        
        # Initialisiere den Logger
        log_module.init_logger(self.config["general"]["log_level"], self.config["general"]["log_file"])
        
        logger.info("Test-Setup abgeschlossen")

    def tearDown(self):
        """
        Wird nach jedem Test ausgeführt.
        """
        # Lösche das temporäre Verzeichnis
        shutil.rmtree(self.temp_dir)
        
        logger.info("Test-Teardown abgeschlossen")


class PayloadIntegrationTest(IntegrationTestCase):
    """
    Integrationstests für das Payload-Management.
    """

    def test_payload_generation(self):
        """
        Testet die Generierung von Payloads.
        """
        # Erstelle den Payload-Manager
        manager = payload_manager.PayloadManager(self.config["payloads"])
        
        # Generiere Payloads für verschiedene Kontexte
        html_payloads = manager.generate_payloads("html", "alert", 5)
        js_payloads = manager.generate_payloads("javascript", "alert", 5)
        url_payloads = manager.generate_payloads("url", "alert", 5)
        
        # Überprüfe die Ergebnisse
        self.assertIsInstance(html_payloads, list)
        self.assertIsInstance(js_payloads, list)
        self.assertIsInstance(url_payloads, list)
        
        self.assertGreater(len(html_payloads), 0)
        self.assertGreater(len(js_payloads), 0)
        self.assertGreater(len(url_payloads), 0)
        
        # Überprüfe, ob die Payloads für den richtigen Kontext generiert wurden
        for payload in html_payloads:
            self.assertIn("<", payload)
        
        for payload in js_payloads:
            self.assertIn("alert", payload)
        
        for payload in url_payloads:
            self.assertIn("javascript", payload)


class ScanningIntegrationTest(IntegrationTestCase):
    """
    Integrationstests für das Scanning.
    """

    def test_target_discovery(self):
        """
        Testet die Zielentdeckung.
        """
        # Erstelle den Target-Discovery-Manager
        discovery = target_discovery.TargetDiscovery(self.config["scanning"])
        
        # Entdecke Ziele für eine Test-URL
        targets = discovery.discover_targets("https://example.com")
        
        # Überprüfe die Ergebnisse
        self.assertIsInstance(targets, list)
        
        # Da wir keine echte Verbindung herstellen, sollte die Liste leer sein oder nur die Basis-URL enthalten
        self.assertLessEqual(len(targets), 1)


class ExploitationIntegrationTest(IntegrationTestCase):
    """
    Integrationstests für die Exploitation.
    """

    def test_exploit_generation(self):
        """
        Testet die Generierung von Exploits.
        """
        # Erstelle den Exploitation-Manager
        exploit_manager = exploitation.ExploitationEngine(self.config["exploitation"])
        
        # Generiere einen Exploit
        exploit = exploit_manager.generate_exploit("https://example.com", "q", "alert")
        
        # Überprüfe die Ergebnisse
        self.assertIsInstance(exploit, dict)
        self.assertIn("payload", exploit)
        self.assertIn("url", exploit)
        self.assertIn("parameter", exploit)
        self.assertIn("type", exploit)


class ReportingIntegrationTest(IntegrationTestCase):
    """
    Integrationstests für die Berichterstellung.
    """

    def test_report_generation(self):
        """
        Testet die Generierung von Berichten.
        """
        # Erstelle den Report-Generator
        report_gen = report_generator.ReportGenerator(self.config["reporting"])
        
        # Erstelle Testdaten
        data = {
            "url": "https://example.com",
            "duration": 10,
            "vulnerabilities": [
                {
                    "url": "https://example.com/search",
                    "parameter": "q",
                    "type": "Reflected XSS",
                    "severity": "High",
                    "description": "Reflected XSS in search parameter",
                    "payload": "<script>alert(1)</script>"
                }
            ]
        }
        
        # Generiere einen Bericht
        report_file = os.path.join(self.config["general"]["output_dir"], "test_report.json")
        result = report_gen.generate_report(data, report_file, "json")
        
        # Überprüfe die Ergebnisse
        self.assertTrue(os.path.exists(report_file))
        
        # Lade den Bericht
        with open(report_file, "r") as f:
            report_data = json.load(f)
        
        # Überprüfe den Inhalt
        self.assertEqual(report_data["url"], "https://example.com")
        self.assertEqual(len(report_data["vulnerabilities"]), 1)
        self.assertEqual(report_data["vulnerabilities"][0]["type"], "Reflected XSS")


class IntegrationModulesTest(IntegrationTestCase):
    """
    Integrationstests für die Integrationsmodule.
    """

    def test_webcrawler_integration(self):
        """
        Testet die Webcrawler-Integration.
        """
        # Erstelle die Webcrawler-Integration
        crawler = webcrawler.WebCrawlerIntegration()
        
        # Überprüfe die Verfügbarkeit
        availability = crawler.check_availability()
        
        # Da wir keine echten Tools installiert haben, sollte die Verfügbarkeit ein leeres Dictionary sein
        self.assertIsInstance(availability, dict)


class FullIntegrationTest(IntegrationTestCase):
    """
    Vollständige Integrationstests für das gesamte Framework.
    """

    def test_orchestration(self):
        """
        Testet die Orchestrierung des gesamten Frameworks.
        """
        # Erstelle den Orchestrator
        orchestrator = orchestration.Orchestrator(self.config)
        
        # Führe einen Scan aus (ohne echte Verbindung)
        results = orchestrator.run_scan("https://example.com", depth=1, max_urls=5)
        
        # Überprüfe die Ergebnisse
        self.assertIsInstance(results, dict)
        self.assertIn("url", results)
        self.assertEqual(results["url"], "https://example.com")


def run_tests():
    """
    Führt alle Integrationstests aus.
    """
    # Erstelle die Test-Suite
    suite = unittest.TestSuite()
    
    # Füge die Tests hinzu
    suite.addTest(unittest.makeSuite(PayloadIntegrationTest))
    suite.addTest(unittest.makeSuite(ScanningIntegrationTest))
    suite.addTest(unittest.makeSuite(ExploitationIntegrationTest))
    suite.addTest(unittest.makeSuite(ReportingIntegrationTest))
    suite.addTest(unittest.makeSuite(IntegrationModulesTest))
    suite.addTest(unittest.makeSuite(FullIntegrationTest))
    
    # Führe die Tests aus
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Gib den Exit-Code zurück
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
