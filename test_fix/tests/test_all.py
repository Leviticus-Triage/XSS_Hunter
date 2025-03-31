#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Test Suite
=============================================

Diese Datei implementiert Tests für das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import unittest
import logging
import json
import time
from unittest.mock import MagicMock, patch

# Füge das Hauptverzeichnis zum Pfad hinzu
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Importiere die zu testenden Module
import utils
from modules.payload_manager import PayloadManager
from modules.exploitation import ExploitationEngine
from modules.report_generator import ReportGenerator
from modules.target_discovery import TargetDiscovery
from modules.vuln_categorization import VulnCategorization
from modules.callback_server import CallbackServer

# Konfiguriere Logging
logging.basicConfig(level=logging.ERROR)


class TestUtils(unittest.TestCase):
    """Tests für die Utilities."""

    def test_generate_random_string(self):
        """Testet die Generierung zufälliger Strings."""
        # Teste die Länge
        self.assertEqual(len(utils.generate_random_string(10)), 10)
        self.assertEqual(len(utils.generate_random_string(20)), 20)
        
        # Teste, dass zwei Aufrufe unterschiedliche Strings erzeugen
        self.assertNotEqual(utils.generate_random_string(10), utils.generate_random_string(10))
        
        # Teste mit Sonderzeichen
        special_string = utils.generate_random_string(100, include_special=True)
        has_special = any(c in special_string for c in "!@#$%^&*()_+-=[]{}|;:,.<>?")
        self.assertTrue(has_special)

    def test_hash_string(self):
        """Testet das Hashen von Strings."""
        # Teste SHA-256 (Standard)
        self.assertEqual(utils.hash_string("test"), "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        
        # Teste MD5
        self.assertEqual(utils.hash_string("test", "md5"), "098f6bcd4621d373cade4e832627b4f6")
        
        # Teste SHA-1
        self.assertEqual(utils.hash_string("test", "sha1"), "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3")

    def test_url_functions(self):
        """Testet URL-bezogene Funktionen."""
        # Teste URL-Kodierung und -Dekodierung
        test_string = "test test"
        encoded = utils.url_encode(test_string)
        self.assertEqual(encoded, "test+test")
        self.assertEqual(utils.url_decode(encoded), test_string)
        
        # Teste URL-Validierung
        self.assertTrue(utils.is_valid_url("https://example.com"))
        self.assertTrue(utils.is_valid_url("http://example.com/path?query=value"))
        self.assertFalse(utils.is_valid_url("example.com"))
        self.assertFalse(utils.is_valid_url("not a url"))
        
        # Teste Domain-Extraktion
        self.assertEqual(utils.extract_domain("https://example.com/path"), "example.com")
        self.assertEqual(utils.extract_domain("http://sub.example.com:8080/path"), "sub.example.com:8080")
        
        # Teste Pfad-Extraktion
        self.assertEqual(utils.extract_path("https://example.com/path"), "/path")
        self.assertEqual(utils.extract_path("http://example.com"), "")
        
        # Teste Query-Parameter-Extraktion
        params = utils.extract_query_params("https://example.com/path?a=1&b=2&c=3")
        self.assertEqual(params, {"a": ["1"], "b": ["2"], "c": ["3"]})
        
        # Teste URL-Erstellung
        self.assertEqual(
            utils.build_url("https://example.com", "/path", {"a": 1, "b": 2}),
            "https://example.com/path?a=1&b=2"
        )


class TestPayloadManager(unittest.TestCase):
    """Tests für den Payload-Manager."""

    def setUp(self):
        """Richtet die Testumgebung ein."""
        self.manager = PayloadManager()

    def test_generate_payload(self):
        """Testet die Generierung von Payloads."""
        # Teste die Generierung eines HTML-Payloads
        result = self.manager.generate_payload("html")
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["payload"])
        self.assertEqual(result["context"], "html")
        
        # Teste die Generierung eines JavaScript-Payloads
        result = self.manager.generate_payload("javascript")
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["payload"])
        self.assertEqual(result["context"], "javascript")
        
        # Teste die Generierung eines Payloads für einen bestimmten Exploit-Typ
        result = self.manager.generate_payload("html", "data_theft")
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["payload"])
        self.assertEqual(result["context"], "html")
        self.assertEqual(result["exploit_type"], "data_theft")
        
        # Teste, dass der Payload für den Exploit-Typ passt
        self.assertIn("document.cookie", result["payload"].lower())

    def test_add_payload(self):
        """Testet das Hinzufügen von Payloads."""
        # Teste das Hinzufügen eines Payloads
        initial_count = len(self.manager.payloads["html"])
        self.assertTrue(self.manager.add_payload("<script>test</script>", "html"))
        self.assertEqual(len(self.manager.payloads["html"]), initial_count + 1)
        self.assertIn("<script>test</script>", self.manager.payloads["html"])
        
        # Teste das Hinzufügen eines Payloads mit ungültigem Kontext
        self.assertFalse(self.manager.add_payload("<script>test</script>", "invalid_context"))
        
        # Teste das Hinzufügen eines leeren Payloads
        self.assertFalse(self.manager.add_payload("", "html"))


class TestExploitationEngine(unittest.TestCase):
    """Tests für die Exploitation-Engine."""

    def setUp(self):
        """Richtet die Testumgebung ein."""
        self.engine = ExploitationEngine()
        
        # Mock für den Payload-Manager
        self.mock_payload_manager = MagicMock()
        self.mock_payload_manager.generate_payload.return_value = {
            "success": True,
            "payload": "<script>alert(1)</script>",
            "context": "html",
            "exploit_type": "reflected_xss",
            "optimized": False,
            "probability": 0.5
        }
        
        self.engine.set_payload_manager(self.mock_payload_manager)

    @patch('requests.get')
    def test_exploit_get(self, mock_get):
        """Testet die GET-Exploitation."""
        # Mock für die HTTP-Antwort
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test <script>alert(1)</script></body></html>"
        mock_get.return_value = mock_response
        
        # Teste die Exploitation
        result = self.engine._exploit_get(
            url="https://example.com/search",
            param="q",
            payload="<script>alert(1)</script>"
        )
        
        # Überprüfe das Ergebnis
        self.assertTrue(result["success"])
        self.assertEqual(result["url"], "https://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        self.assertEqual(result["param"], "q")
        self.assertEqual(result["payload"], "<script>alert(1)</script>")
        self.assertEqual(result["response_code"], 200)
        self.assertTrue(result["payload_in_response"])
        
        # Überprüfe den Aufruf von requests.get
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args
        self.assertEqual(args[0], "https://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")

    @patch('requests.post')
    def test_exploit_post(self, mock_post):
        """Testet die POST-Exploitation."""
        # Mock für die HTTP-Antwort
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test <script>alert(1)</script></body></html>"
        mock_post.return_value = mock_response
        
        # Teste die Exploitation
        result = self.engine._exploit_post(
            url="https://example.com/search",
            param="q",
            payload="<script>alert(1)</script>",
            data={"other": "value"}
        )
        
        # Überprüfe das Ergebnis
        self.assertTrue(result["success"])
        self.assertEqual(result["url"], "https://example.com/search")
        self.assertEqual(result["param"], "q")
        self.assertEqual(result["payload"], "<script>alert(1)</script>")
        self.assertEqual(result["response_code"], 200)
        self.assertTrue(result["payload_in_response"])
        
        # Überprüfe den Aufruf von requests.post
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://example.com/search")
        self.assertEqual(kwargs["data"], {"q": "<script>alert(1)</script>", "other": "value"})


class TestReportGenerator(unittest.TestCase):
    """Tests für den Report-Generator."""

    def setUp(self):
        """Richtet die Testumgebung ein."""
        self.generator = ReportGenerator({
            "report_dir": "test_reports"
        })
        
        # Erstelle das Test-Verzeichnis
        os.makedirs("test_reports", exist_ok=True)
        
        # Beispiel-Schwachstellen
        self.vulnerabilities = [
            {
                "type": "Reflected XSS",
                "severity": "high",
                "url": "https://example.com/search",
                "param": "q",
                "payload": "<script>alert(1)</script>",
                "description": "Die Suchfunktion ist anfällig für Reflected XSS.",
                "impact": "Ein Angreifer kann beliebigen JavaScript-Code im Browser des Opfers ausführen.",
                "remediation": "Implementiere eine ordnungsgemäße Eingabevalidierung und Ausgabekodierung.",
                "cvss": "7.5"
            },
            {
                "type": "Stored XSS",
                "severity": "critical",
                "url": "https://example.com/comments",
                "param": "comment",
                "payload": "<img src=x onerror=alert(1)>",
                "description": "Die Kommentarfunktion ist anfällig für Stored XSS.",
                "impact": "Ein Angreifer kann beliebigen JavaScript-Code im Browser aller Benutzer ausführen, die die Seite besuchen.",
                "remediation": "Implementiere eine ordnungsgemäße Eingabevalidierung und Ausgabekodierung.",
                "cvss": "8.5"
            }
        ]

    def tearDown(self):
        """Räumt die Testumgebung auf."""
        # Lösche die generierten Berichte
        for file in os.listdir("test_reports"):
            os.remove(os.path.join("test_reports", file))
        
        # Lösche das Test-Verzeichnis
        os.rmdir("test_reports")

    def test_generate_html_report(self):
        """Testet die Generierung von HTML-Berichten."""
        # Teste die Generierung eines HTML-Berichts
        result = self.generator.generate_report(self.vulnerabilities, "html")
        
        # Überprüfe das Ergebnis
        self.assertTrue(result["success"])
        self.assertEqual(result["format"], "html")
        self.assertEqual(result["vulnerabilities_count"], 2)
        
        # Überprüfe, ob die Datei existiert
        self.assertTrue(os.path.exists(result["output_file"]))
        
        # Überprüfe den Inhalt der Datei
        with open(result["output_file"], "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("XSS Hunter Pro - Schwachstellenbericht", content)
            self.assertIn("Reflected XSS", content)
            self.assertIn("Stored XSS", content)
            self.assertIn("https://example.com/search", content)
            self.assertIn("https://example.com/comments", content)
            self.assertIn("<script>alert(1)</script>", content)
            self.assertIn("<img src=x onerror=alert(1)>", content)

    def test_generate_json_report(self):
        """Testet die Generierung von JSON-Berichten."""
        # Teste die Generierung eines JSON-Berichts
        result = self.generator.generate_report(self.vulnerabilities, "json")
        
        # Überprüfe das Ergebnis
        self.assertTrue(result["success"])
        self.assertEqual(result["format"], "json")
        self.assertEqual(result["vulnerabilities_count"], 2)
        
        # Überprüfe, ob die Datei existiert
        self.assertTrue(os.path.exists(result["output_file"]))
        
        # Überprüfe den Inhalt der Datei
        with open(result["output_file"], "r", encoding="utf-8") as f:
            content = json.load(f)
            self.assertEqual(len(content["vulnerabilities"]), 2)
            self.assertEqual(content["vulnerabilities"][0]["type"], "Reflected XSS")
            self.assertEqual(content["vulnerabilities"][1]["type"], "Stored XSS")
            self.assertEqual(content["vulnerabilities"][0]["url"], "https://example.com/search")
            self.assertEqual(content["vulnerabilities"][1]["url"], "https://example.com/comments")
            self.assertEqual(content["vulnerabilities"][0]["payload"], "<script>alert(1)</script>")
            self.assertEqual(content["vulnerabilities"][1]["payload"], "<img src=x onerror=alert(1)>")

    def test_generate_markdown_report(self):
        """Testet die Generierung von Markdown-Berichten."""
        # Teste die Generierung eines Markdown-Berichts
        result = self.generator.generate_report(self.vulnerabilities, "markdown")
        
        # Überprüfe das Ergebnis
        self.assertTrue(result["success"])
        self.assertEqual(result["format"], "markdown")
        self.assertEqual(result["vulnerabilities_count"], 2)
        
        # Überprüfe, ob die Datei existiert
        self.assertTrue(os.path.exists(result["output_file"]))
        
        # Überprüfe den Inhalt der Datei
        with open(result["output_file"], "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("# XSS Hunter Pro - Schwachstellenbericht", content)
            self.assertIn("### 1. Reflected XSS", content)
            self.assertIn("### 2. Stored XSS", content)
            self.assertIn("https://example.com/search", content)
            self.assertIn("https://example.com/comments", content)
            self.assertIn("<script>alert(1)</script>", content)
            self.assertIn("<img src=x onerror=alert(1)>", content)


class TestVulnCategorization(unittest.TestCase):
    """Tests für die Schwachstellenkategorisierung."""

    def setUp(self):
        """Richtet die Testumgebung ein."""
        self.categorization = VulnCategorization()

    def test_categorize(self):
        """Testet die Kategorisierung von Schwachstellen."""
        # Teste die Kategorisierung einer Reflected XSS-Schwachstelle
        vulnerability = {
            "url": "https://example.com/search",
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "response": "<html><body>Test <script>alert(1)</script></body></html>",
            "test_type": "reflected"
        }
        
        result = self.categorization.categorize(vulnerability)
        
        # Überprüfe das Ergebnis
        self.assertEqual(result["type"], "Reflected XSS")
        self.assertEqual(result["type_key"], "reflected_xss")
        self.assertEqual(result["url"], "https://example.com/search")
        self.assertEqual(result["param"], "q")
        self.assertEqual(result["payload"], "<script>alert(1)</script>")
        self.assertIn("severity", result)
        self.assertIn("cvss", result)
        self.assertIn("description", result)
        self.assertIn("impact", result)
        self.assertIn("remediation", result)
        
        # Teste die Kategorisierung einer Stored XSS-Schwachstelle
        vulnerability = {
            "url": "https://example.com/comments",
            "param": "comment",
            "payload": "<img src=x onerror=alert(1)>",
            "response": "<html><body>Test <img src=x onerror=alert(1)></body></html>",
            "test_type": "stored"
        }
        
        result = self.categorization.categorize(vulnerability)
        
        # Überprüfe das Ergebnis
        self.assertEqual(result["type"], "Stored XSS")
        self.assertEqual(result["type_key"], "stored_xss")
        self.assertEqual(result["url"], "https://example.com/comments")
        self.assertEqual(result["param"], "comment")
        self.assertEqual(result["payload"], "<img src=x onerror=alert(1)>")
        self.assertIn("severity", result)
        self.assertIn("cvss", result)
        self.assertIn("description", result)
        self.assertIn("impact", result)
        self.assertIn("remediation", result)

    def test_get_vulnerability_types(self):
        """Testet das Abrufen der verfügbaren Schwachstellentypen."""
        types = self.categorization.get_vulnerability_types()
        
        # Überprüfe das Ergebnis
        self.assertIsInstance(types, dict)
        self.assertIn("reflected_xss", types)
        self.assertIn("stored_xss", types)
        self.assertIn("dom_xss", types)
        self.assertIn("blind_xss", types)
        
        # Überprüfe die Struktur eines Typs
        reflected_xss = types["reflected_xss"]
        self.assertIn("name", reflected_xss)
        self.assertIn("description", reflected_xss)
        self.assertIn("impact", reflected_xss)
        self.assertIn("remediation", reflected_xss)
        self.assertIn("cvss_base", reflected_xss)
        self.assertIn("severity", reflected_xss)


class TestCallbackServer(unittest.TestCase):
    """Tests für den Callback-Server."""

    def setUp(self):
        """Richtet die Testumgebung ein."""
        self.server = CallbackServer({
            "port": 8080,
            "host": "127.0.0.1",
            "path": "/callback"
        })

    def test_get_callback_url(self):
        """Testet das Abrufen der Callback-URL."""
        # Teste das Abrufen der Callback-URL
        url = self.server.get_callback_url("test")
        
        # Überprüfe das Ergebnis
        self.assertEqual(url, "http://127.0.0.1:8080/callback/test")
        
        # Teste das Abrufen der Callback-URL mit einem anderen Pfad
        url = self.server.get_callback_url("another")
        
        # Überprüfe das Ergebnis
        self.assertEqual(url, "http://127.0.0.1:8080/callback/another")

    def test_add_callback(self):
        """Testet das Hinzufügen von Callbacks."""
        # Teste das Hinzufügen eines Callbacks
        callback_data = {
            "type": "test",
            "data": "test_data",
            "timestamp": time.time()
        }
        
        self.server.add_callback(callback_data)
        
        # Überprüfe das Ergebnis
        callbacks = self.server.get_callbacks()
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(callbacks[0]["type"], "test")
        self.assertEqual(callbacks[0]["data"], "test_data")
        
        # Teste das Hinzufügen eines weiteren Callbacks
        callback_data = {
            "type": "another",
            "data": "another_data",
            "timestamp": time.time()
        }
        
        self.server.add_callback(callback_data)
        
        # Überprüfe das Ergebnis
        callbacks = self.server.get_callbacks()
        self.assertEqual(len(callbacks), 2)
        self.assertEqual(callbacks[1]["type"], "another")
        self.assertEqual(callbacks[1]["data"], "another_data")


if __name__ == "__main__":
    unittest.main()
