#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Unit Tests
=============================================

Dieses Modul implementiert Unit-Tests für das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import unittest
import json
import tempfile
import shutil
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Füge das Hauptverzeichnis zum Pfad hinzu
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

# Importiere die zu testenden Module
try:
    from modules import payload_manager, callback_server, exploitation, report_generator
    from modules import target_discovery, vuln_categorization
    import utils, logger as log_module, error_handler
except ImportError as e:
    print(f"Fehler beim Importieren der Module: {e}")
    sys.exit(1)


class UtilsTest(unittest.TestCase):
    """
    Tests für das Utils-Modul.
    """

    def test_random_string_generation(self):
        """
        Testet die Generierung zufälliger Zeichenketten.
        """
        # Teste die Länge
        self.assertEqual(len(utils.generate_random_string(10)), 10)
        self.assertEqual(len(utils.generate_random_string(20)), 20)
        
        # Teste die Zeichensätze
        random_string = utils.generate_random_string(100, False)
        self.assertTrue(all(c in string.ascii_letters + string.digits for c in random_string))
        
        random_string_special = utils.generate_random_string(100, True)
        self.assertTrue(any(c in string.punctuation for c in random_string_special))

    def test_url_functions(self):
        """
        Testet die URL-Funktionen.
        """
        # Teste die URL-Validierung
        self.assertTrue(utils.is_valid_url("https://example.com"))
        self.assertTrue(utils.is_valid_url("http://example.com/path?query=value"))
        self.assertFalse(utils.is_valid_url("example.com"))
        self.assertFalse(utils.is_valid_url("ftp://example.com"))
        
        # Teste die URL-Parsing-Funktionen
        self.assertEqual(utils.get_domain_from_url("https://example.com/path"), "example.com")
        self.assertEqual(utils.get_path_from_url("https://example.com/path"), "/path")
        self.assertEqual(utils.get_query_from_url("https://example.com/path?query=value"), "query=value")
        self.assertEqual(utils.get_query_params("https://example.com/path?query=value&param=test"), {"query": "value", "param": "test"})
        
        # Teste die URL-Manipulation
        self.assertEqual(utils.add_query_param("https://example.com", "param", "value"), "https://example.com?param=value")
        self.assertEqual(utils.add_query_param("https://example.com?query=value", "param", "test"), "https://example.com?query=value&param=test")
        self.assertEqual(utils.remove_query_param("https://example.com?query=value&param=test", "param"), "https://example.com?query=value")

    def test_encoding_functions(self):
        """
        Testet die Kodierungsfunktionen.
        """
        # Teste Base64-Kodierung
        self.assertEqual(utils.decode_base64(utils.encode_base64("test")), "test")
        
        # Teste URL-Kodierung
        self.assertEqual(utils.url_decode(utils.url_encode("test test")), "test test")
        
        # Teste HTML-Kodierung
        self.assertEqual(utils.html_decode(utils.html_encode("<test>")), "<test>")
        
        # Teste JavaScript-Kodierung
        self.assertEqual(utils.js_decode(utils.js_encode("<test>")), "<test>")

    def test_hash_functions(self):
        """
        Testet die Hash-Funktionen.
        """
        # Teste verschiedene Hash-Algorithmen
        self.assertEqual(len(utils.hash_string("test", "md5")), 32)
        self.assertEqual(len(utils.hash_string("test", "sha1")), 40)
        self.assertEqual(len(utils.hash_string("test", "sha256")), 64)
        self.assertEqual(len(utils.hash_string("test", "sha512")), 128)
        
        # Teste ungültigen Algorithmus
        with self.assertRaises(ValueError):
            utils.hash_string("test", "invalid")


class PayloadManagerTest(unittest.TestCase):
    """
    Tests für den Payload-Manager.
    """

    def setUp(self):
        """
        Wird vor jedem Test ausgeführt.
        """
        # Erstelle ein temporäres Verzeichnis
        self.temp_dir = tempfile.mkdtemp()
        
        # Erstelle eine Testkonfiguration
        self.config = {
            "use_ml": False,
            "ml_model": "default",
            "payloads_dir": os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads"),
            "custom_payloads_file": os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads", "custom.json")
        }
        
        # Erstelle den Payload-Manager
        self.manager = payload_manager.PayloadManager(self.config)

    def tearDown(self):
        """
        Wird nach jedem Test ausgeführt.
        """
        # Lösche das temporäre Verzeichnis
        shutil.rmtree(self.temp_dir)

    def test_payload_generation(self):
        """
        Testet die Generierung von Payloads.
        """
        # Generiere Payloads für verschiedene Kontexte
        html_payloads = self.manager.generate_payloads("html", "alert", 5)
        js_payloads = self.manager.generate_payloads("javascript", "alert", 5)
        url_payloads = self.manager.generate_payloads("url", "alert", 5)
        
        # Überprüfe die Ergebnisse
        self.assertIsInstance(html_payloads, list)
        self.assertIsInstance(js_payloads, list)
        self.assertIsInstance(url_payloads, list)
        
        self.assertLessEqual(len(html_payloads), 5)
        self.assertLessEqual(len(js_payloads), 5)
        self.assertLessEqual(len(url_payloads), 5)

    def test_custom_payloads(self):
        """
        Testet die Verwendung benutzerdefinierter Payloads.
        """
        # Erstelle eine temporäre Payload-Datei
        payload_file = os.path.join(self.temp_dir, "custom.json")
        
        with open(payload_file, "w") as f:
            json.dump({
                "custom_payloads": [
                    {
                        "name": "Test Payload",
                        "description": "Test payload for unit tests",
                        "context": "html",
                        "payload": "<script>alert('Test')</script>",
                        "type": "alert",
                        "severity": "low",
                        "bypass_waf": False,
                        "tags": ["test"]
                    }
                ]
            }, f)
        
        # Aktualisiere die Konfiguration
        self.config["custom_payloads_file"] = payload_file
        
        # Erstelle einen neuen Payload-Manager
        manager = payload_manager.PayloadManager(self.config)
        
        # Generiere Payloads
        payloads = manager.generate_payloads("html", "alert", 5, use_custom=True)
        
        # Überprüfe die Ergebnisse
        self.assertIn("<script>alert('Test')</script>", payloads)


class ExploitationTest(unittest.TestCase):
    """
    Tests für die Exploitation-Engine.
    """

    def setUp(self):
        """
        Wird vor jedem Test ausgeführt.
        """
        # Erstelle eine Testkonfiguration
        self.config = {
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
        }
        
        # Erstelle die Exploitation-Engine
        self.engine = exploitation.ExploitationEngine(self.config)

    def test_exploit_generation(self):
        """
        Testet die Generierung von Exploits.
        """
        # Generiere einen Exploit
        exploit = self.engine.generate_exploit("https://example.com", "q", "alert")
        
        # Überprüfe die Ergebnisse
        self.assertIsInstance(exploit, dict)
        self.assertIn("payload", exploit)
        self.assertIn("url", exploit)
        self.assertIn("parameter", exploit)
        self.assertIn("type", exploit)
        
        # Überprüfe die Werte
        self.assertEqual(exploit["url"], "https://example.com")
        self.assertEqual(exploit["parameter"], "q")
        self.assertEqual(exploit["type"], "alert")

    def test_exploit_execution(self):
        """
        Testet die Ausführung von Exploits.
        """
        # Erstelle einen Mock-Exploit
        exploit = {
            "url": "https://example.com",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "type": "alert"
        }
        
        # Führe den Exploit aus (ohne tatsächliche Ausführung)
        result = self.engine.execute_exploit(exploit, dry_run=True)
        
        # Überprüfe die Ergebnisse
        self.assertIsInstance(result, dict)
        self.assertIn("success", result)
        self.assertIn("url", result)
        self.assertIn("payload", result)
        
        # Überprüfe die Werte
        self.assertEqual(result["url"], "https://example.com?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        self.assertEqual(result["payload"], "<script>alert(1)</script>")


class ReportGeneratorTest(unittest.TestCase):
    """
    Tests für den Report-Generator.
    """

    def setUp(self):
        """
        Wird vor jedem Test ausgeführt.
        """
        # Erstelle ein temporäres Verzeichnis
        self.temp_dir = tempfile.mkdtemp()
        
        # Erstelle eine Testkonfiguration
        self.config = {
            "default_format": "json",
            "include_screenshots": False,
            "include_payloads": True,
            "include_requests": True,
            "include_responses": False,
            "template_dir": os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules", "templates"),
            "default_template": "default"
        }
        
        # Erstelle den Report-Generator
        self.generator = report_generator.ReportGenerator(self.config)
        
        # Erstelle Testdaten
        self.data = {
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

    def tearDown(self):
        """
        Wird nach jedem Test ausgeführt.
        """
        # Lösche das temporäre Verzeichnis
        shutil.rmtree(self.temp_dir)

    def test_json_report_generation(self):
        """
        Testet die Generierung von JSON-Berichten.
        """
        # Generiere einen JSON-Bericht
        report_file = os.path.join(self.temp_dir, "report.json")
        result = self.generator.generate_report(self.data, report_file, "json")
        
        # Überprüfe die Ergebnisse
        self.assertTrue(os.path.exists(report_file))
        
        # Lade den Bericht
        with open(report_file, "r") as f:
            report_data = json.load(f)
        
        # Überprüfe den Inhalt
        self.assertEqual(report_data["url"], "https://example.com")
        self.assertEqual(len(report_data["vulnerabilities"]), 1)
        self.assertEqual(report_data["vulnerabilities"][0]["type"], "Reflected XSS")

    def test_txt_report_generation(self):
        """
        Testet die Generierung von TXT-Berichten.
        """
        # Generiere einen TXT-Bericht
        report_file = os.path.join(self.temp_dir, "report.txt")
        result = self.generator.generate_report(self.data, report_file, "txt")
        
        # Überprüfe die Ergebnisse
        self.assertTrue(os.path.exists(report_file))
        
        # Lade den Bericht
        with open(report_file, "r") as f:
            report_text = f.read()
        
        # Überprüfe den Inhalt
        self.assertIn("https://example.com", report_text)
        self.assertIn("Reflected XSS", report_text)
        self.assertIn("<script>alert(1)</script>", report_text)


def run_tests():
    """
    Führt alle Unit-Tests aus.
    """
    # Erstelle die Test-Suite
    suite = unittest.TestSuite()
    
    # Füge die Tests hinzu
    suite.addTest(unittest.makeSuite(UtilsTest))
    suite.addTest(unittest.makeSuite(PayloadManagerTest))
    suite.addTest(unittest.makeSuite(ExploitationTest))
    suite.addTest(unittest.makeSuite(ReportGeneratorTest))
    
    # Führe die Tests aus
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Gib den Exit-Code zurück
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
