#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Enhanced Report Generator
=============================================

Dieses Modul implementiert einen erweiterten Berichtsgenerator für das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import logging
import json
import datetime
import base64
import jinja2
import markdown
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.EnhancedReportGenerator")


class EnhancedReportGenerator:
    """
    Erweiterter Berichtsgenerator für das XSS Hunter Framework.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialisiert den erweiterten Berichtsgenerator.

        Args:
            config: Die Konfiguration.
        """
        # Setze die Standardkonfiguration
        self.config = {
            "template_dir": "templates",
            "default_template": "default",
            "output_dir": "reports",
            "include_screenshots": True,
            "include_payloads": True,
            "include_requests": True,
            "include_responses": False,
            "max_screenshot_width": 800,
            "max_screenshot_height": 600,
            "chart_dpi": 100,
            "chart_format": "png"
        }
        
        # Überschreibe die Standardkonfiguration mit der übergebenen Konfiguration
        if config:
            self.config.update(config)
        
        # Initialisiere die Jinja2-Umgebung
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.config["template_dir"]),
            autoescape=jinja2.select_autoescape(["html", "xml"])
        )
        
        # Registriere benutzerdefinierte Filter
        self.jinja_env.filters["to_json"] = lambda obj: json.dumps(obj, indent=2)
        self.jinja_env.filters["to_markdown"] = lambda text: markdown.markdown(text)
        self.jinja_env.filters["to_base64"] = lambda data: base64.b64encode(data.encode("utf-8")).decode("utf-8")
        self.jinja_env.filters["format_date"] = lambda timestamp: datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def generate_report(self, data: Dict[str, Any], output_file: str = None, report_format: str = "html", template: str = None) -> str:
        """
        Generiert einen Bericht.

        Args:
            data: Die Daten für den Bericht.
            output_file: Die Ausgabedatei.
            report_format: Das Format des Berichts.
            template: Die zu verwendende Vorlage.

        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        # Bestimme die Vorlage
        if template is None:
            template = self.config["default_template"]
        
        # Bestimme das Format
        if report_format not in ["html", "json", "txt", "md", "pdf"]:
            logger.warning(f"Ungültiges Format: {report_format}, verwende HTML")
            report_format = "html"
        
        # Bestimme die Ausgabedatei
        if output_file is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.config["output_dir"], f"report_{timestamp}.{report_format}")
        
        # Erstelle das Verzeichnis, wenn es nicht existiert
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        # Generiere den Bericht
        if report_format == "html":
            return self._generate_html_report(data, output_file, template)
        elif report_format == "json":
            return self._generate_json_report(data, output_file)
        elif report_format == "txt":
            return self._generate_txt_report(data, output_file)
        elif report_format == "md":
            return self._generate_md_report(data, output_file, template)
        elif report_format == "pdf":
            return self._generate_pdf_report(data, output_file, template)
        
        # Fallback
        return self._generate_html_report(data, output_file, template)

    def _generate_html_report(self, data: Dict[str, Any], output_file: str, template: str) -> str:
        """
        Generiert einen HTML-Bericht.

        Args:
            data: Die Daten für den Bericht.
            output_file: Die Ausgabedatei.
            template: Die zu verwendende Vorlage.

        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Generiere die Diagramme
            charts = self._generate_charts(data)
            
            # Lade die Vorlage
            template_file = f"{template}_html.jinja2"
            template_obj = self.jinja_env.get_template(template_file)
            
            # Rendere die Vorlage
            html = template_obj.render(
                data=data,
                charts=charts,
                config=self.config,
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                version="0.2.0"
            )
            
            # Speichere den Bericht
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html)
            
            logger.info(f"HTML-Bericht generiert: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Fehler beim Generieren des HTML-Berichts: {e}")
            return ""

    def _generate_json_report(self, data: Dict[str, Any], output_file: str) -> str:
        """
        Generiert einen JSON-Bericht.

        Args:
            data: Die Daten für den Bericht.
            output_file: Die Ausgabedatei.

        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Speichere den Bericht
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"JSON-Bericht generiert: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Fehler beim Generieren des JSON-Berichts: {e}")
            return ""

    def _generate_txt_report(self, data: Dict[str, Any], output_file: str) -> str:
        """
        Generiert einen TXT-Bericht.

        Args:
            data: Die Daten für den Bericht.
            output_file: Die Ausgabedatei.

        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Erstelle den Bericht
            lines = [
                "XSS Hunter Pro Framework - Bericht",
                "===================================",
                "",
                f"Erstellt am: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Version: 0.2.0",
                "",
                "Zusammenfassung:",
                f"- Gescannte URL: {data.get('url', 'N/A')}",
                f"- Anzahl der gefundenen Schwachstellen: {len(data.get('vulnerabilities', []))}",
                f"- Scan-Dauer: {data.get('duration', 0)} Sekunden",
                "",
                "Gefundene Schwachstellen:",
                ""
            ]
            
            # Füge die Schwachstellen hinzu
            for i, vuln in enumerate(data.get("vulnerabilities", []), 1):
                lines.extend([
                    f"Schwachstelle #{i}:",
                    f"- URL: {vuln.get('url', 'N/A')}",
                    f"- Parameter: {vuln.get('parameter', 'N/A')}",
                    f"- Typ: {vuln.get('type', 'N/A')}",
                    f"- Schweregrad: {vuln.get('severity', 'N/A')}",
                    f"- Beschreibung: {vuln.get('description', 'N/A')}",
                    f"- Payload: {vuln.get('payload', 'N/A')}",
                    ""
                ])
            
            # Speichere den Bericht
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            
            logger.info(f"TXT-Bericht generiert: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Fehler beim Generieren des TXT-Berichts: {e}")
            return ""

    def _generate_md_report(self, data: Dict[str, Any], output_file: str, template: str) -> str:
        """
        Generiert einen Markdown-Bericht.

        Args:
            data: Die Daten für den Bericht.
            output_file: Die Ausgabedatei.
            template: Die zu verwendende Vorlage.

        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Lade die Vorlage
            template_file = f"{template}_md.jinja2"
            template_obj = self.jinja_env.get_template(template_file)
            
            # Rendere die Vorlage
            md = template_obj.render(
                data=data,
                config=self.config,
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                version="0.2.0"
            )
            
            # Speichere den Bericht
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(md)
            
            logger.info(f"Markdown-Bericht generiert: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Fehler beim Generieren des Markdown-Berichts: {e}")
            return ""

    def _generate_pdf_report(self, data: Dict[str, Any], output_file: str, template: str) -> str:
        """
        Generiert einen PDF-Bericht.

        Args:
            data: Die Daten für den Bericht.
            output_file: Die Ausgabedatei.
            template: Die zu verwendende Vorlage.

        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Generiere zuerst einen HTML-Bericht
            html_file = output_file.replace(".pdf", ".html")
            self._generate_html_report(data, html_file, template)
            
            # Konvertiere HTML zu PDF
            try:
                import weasyprint
                
                # Lade die HTML-Datei
                with open(html_file, "r", encoding="utf-8") as f:
                    html = f.read()
                
                # Konvertiere zu PDF
                pdf = weasyprint.HTML(string=html).write_pdf()
                
                # Speichere die PDF-Datei
                with open(output_file, "wb") as f:
                    f.write(pdf)
                
                # Lösche die temporäre HTML-Datei
                os.remove(html_file)
                
                logger.info(f"PDF-Bericht generiert: {output_file}")
                return output_file
                
            except ImportError:
                logger.warning("weasyprint nicht installiert, verwende HTML-Bericht")
                return html_file
            
        except Exception as e:
            logger.error(f"Fehler beim Generieren des PDF-Berichts: {e}")
            return ""

    def _generate_charts(self, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generiert Diagramme für den Bericht.

        Args:
            data: Die Daten für den Bericht.

        Returns:
            Ein Dictionary mit den generierten Diagrammen.
        """
        charts = {}
        
        try:
            # Erstelle ein temporäres Verzeichnis für die Diagramme
            charts_dir = os.path.join(self.config["output_dir"], "charts")
            os.makedirs(charts_dir, exist_ok=True)
            
            # Generiere ein Diagramm für die Schweregrade
            severity_chart = self._generate_severity_chart(data, charts_dir)
            if severity_chart:
                charts["severity"] = severity_chart
            
            # Generiere ein Diagramm für die Schwachstellentypen
            type_chart = self._generate_type_chart(data, charts_dir)
            if type_chart:
                charts["type"] = type_chart
            
            return charts
            
        except Exception as e:
            logger.error(f"Fehler beim Generieren der Diagramme: {e}")
            return {}

    def _generate_severity_chart(self, data: Dict[str, Any], charts_dir: str) -> str:
        """
        Generiert ein Diagramm für die Schweregrade.

        Args:
            data: Die Daten für den Bericht.
            charts_dir: Das Verzeichnis für die Diagramme.

        Returns:
            Der Pfad zum generierten Diagramm.
        """
        try:
            # Zähle die Schweregrade
            severities = {}
            for vuln in data.get("vulnerabilities", []):
                severity = vuln.get("severity", "Unknown")
                severities[severity] = severities.get(severity, 0) + 1
            
            # Erstelle das Diagramm
            plt.figure(figsize=(8, 6))
            
            # Sortiere die Schweregrade
            sorted_severities = sorted(severities.items(), key=lambda x: {
                "Critical": 0,
                "High": 1,
                "Medium": 2,
                "Low": 3,
                "Info": 4,
                "Unknown": 5
            }.get(x[0], 6))
            
            # Erstelle die Daten für das Diagramm
            labels = [s[0] for s in sorted_severities]
            values = [s[1] for s in sorted_severities]
            colors = {
                "Critical": "darkred",
                "High": "red",
                "Medium": "orange",
                "Low": "yellow",
                "Info": "green",
                "Unknown": "gray"
            }
            chart_colors = [colors.get(s, "gray") for s in labels]
            
            # Erstelle das Diagramm
            plt.bar(labels, values, color=chart_colors)
            plt.title("Verteilung der Schweregrade")
            plt.xlabel("Schweregrad")
            plt.ylabel("Anzahl")
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            # Speichere das Diagramm
            chart_file = os.path.join(charts_dir, "severity_chart.png")
            plt.savefig(chart_file, dpi=self.config["chart_dpi"], format=self.config["chart_format"])
            plt.close()
            
            return chart_file
            
        except Exception as e:
            logger.error(f"Fehler beim Generieren des Schweregraddiagramms: {e}")
            return ""

    def _generate_type_chart(self, data: Dict[str, Any], charts_dir: str) -> str:
        """
        Generiert ein Diagramm für die Schwachstellentypen.

        Args:
            data: Die Daten für den Bericht.
            charts_dir: Das Verzeichnis für die Diagramme.

        Returns:
            Der Pfad zum generierten Diagramm.
        """
        try:
            # Zähle die Schwachstellentypen
            types = {}
            for vuln in data.get("vulnerabilities", []):
                vuln_type = vuln.get("type", "Unknown")
                types[vuln_type] = types.get(vuln_type, 0) + 1
            
            # Erstelle das Diagramm
            plt.figure(figsize=(8, 6))
            
            # Erstelle die Daten für das Diagramm
            labels = list(types.keys())
            values = list(types.values())
            
            # Erstelle das Diagramm
            plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=90)
            plt.title("Verteilung der Schwachstellentypen")
            plt.axis("equal")
            plt.tight_layout()
            
            # Speichere das Diagramm
            chart_file = os.path.join(charts_dir, "type_chart.png")
            plt.savefig(chart_file, dpi=self.config["chart_dpi"], format=self.config["chart_format"])
            plt.close()
            
            return chart_file
            
        except Exception as e:
            logger.error(f"Fehler beim Generieren des Typendiagramms: {e}")
            return ""


# Beispiel für die Verwendung
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(level=logging.INFO)
    
    # Erstelle den erweiterten Berichtsgenerator
    generator = EnhancedReportGenerator()
    
    # Erstelle Beispieldaten
    data = {
        "url": "https://example.com",
        "duration": 120,
        "vulnerabilities": [
            {
                "url": "https://example.com/search",
                "parameter": "q",
                "type": "Reflected XSS",
                "severity": "High",
                "description": "Reflected XSS in search parameter",
                "payload": "<script>alert(1)</script>"
            },
            {
                "url": "https://example.com/profile",
                "parameter": "bio",
                "type": "Stored XSS",
                "severity": "Critical",
                "description": "Stored XSS in user bio",
                "payload": "<img src=x onerror=alert(1)>"
            },
            {
                "url": "https://example.com/redirect",
                "parameter": "url",
                "type": "DOM-based XSS",
                "severity": "Medium",
                "description": "DOM-based XSS in redirect parameter",
                "payload": "javascript:alert(1)"
            }
        ]
    }
    
    # Generiere einen HTML-Bericht
    html_report = generator.generate_report(data, report_format="html")
    print(f"HTML-Bericht generiert: {html_report}")
    
    # Generiere einen JSON-Bericht
    json_report = generator.generate_report(data, report_format="json")
    print(f"JSON-Bericht generiert: {json_report}")
    
    # Generiere einen TXT-Bericht
    txt_report = generator.generate_report(data, report_format="txt")
    print(f"TXT-Bericht generiert: {txt_report}")
    
    # Generiere einen Markdown-Bericht
    md_report = generator.generate_report(data, report_format="md")
    print(f"Markdown-Bericht generiert: {md_report}")
    
    # Generiere einen PDF-Bericht
    pdf_report = generator.generate_report(data, report_format="pdf")
    print(f"PDF-Bericht generiert: {pdf_report}")
