#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Modules - Report Generator
====================================================

Dieses Modul implementiert die Berichterstellung für XSS-Schwachstellen.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import json
import logging
import time
import datetime
import re
import base64
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.ReportGenerator")

# Versuche, den Error Handler zu importieren
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

# Versuche, die Utility-Funktionen zu importieren
try:
    from utils import (
        is_valid_url, load_json_file, save_json_file, get_timestamp, format_timestamp
    )
except ImportError:
    logger.warning("Utils-Modul konnte nicht importiert werden. Verwende einfache Implementierungen.")
    
    # Einfache Implementierungen der benötigten Funktionen
    def is_valid_url(url):
        return bool(url and url.startswith(("http://", "https://")))
    
    def load_json_file(file_path):
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Fehler beim Laden der JSON-Datei: {e}")
            return {}
    
    def save_json_file(data, file_path):
        try:
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Fehler beim Speichern der JSON-Datei: {e}")
            return False
    
    def get_timestamp():
        return int(time.time())
    
    def format_timestamp(timestamp, format="%Y-%m-%d %H:%M:%S"):
        return time.strftime(format, time.localtime(timestamp))

# Versuche, Jinja2 zu importieren
try:
    import jinja2
    JINJA2_AVAILABLE = True
except ImportError:
    logger.warning("Jinja2 konnte nicht importiert werden. HTML-Berichte werden eingeschränkt sein.")
    JINJA2_AVAILABLE = False

# Versuche, Markdown zu importieren
try:
    import markdown
    MARKDOWN_AVAILABLE = True
except ImportError:
    logger.warning("Markdown konnte nicht importiert werden. Versuche lokale Implementierung zu laden.")
    try:
        # Versuche, die lokale Markdown-Implementierung zu importieren
        from markdown import markdown
        MARKDOWN_AVAILABLE = True
        logger.info("Lokale Markdown-Implementierung erfolgreich geladen.")
    except ImportError:
        logger.warning("Markdown konnte nicht importiert werden. Markdown-Berichte werden eingeschränkt sein.")
        MARKDOWN_AVAILABLE = False


class ReportGenerator:
    """
    Generator für Berichte über XSS-Schwachstellen.
    """
    
    def __init__(self, reports_dir="reports", templates_dir="templates"):
        """
        Initialisiert den Report-Generator.
        
        Args:
            reports_dir: Das Verzeichnis für die Berichte.
            templates_dir: Das Verzeichnis mit den Berichtsvorlagen.
        """
        self.reports_dir = reports_dir
        self.templates_dir = templates_dir
        
        # Erstelle die Verzeichnisse, falls sie nicht existieren
        os.makedirs(reports_dir, exist_ok=True)
        os.makedirs(templates_dir, exist_ok=True)
        
        # Initialisiere Jinja2, falls verfügbar
        if JINJA2_AVAILABLE:
            self.jinja_env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(templates_dir),
                autoescape=jinja2.select_autoescape(['html', 'xml'])
            )
        else:
            self.jinja_env = None
    
    @handle_exception
    def generate_report(self, vulnerabilities, report_format="html", output_file=None, include_screenshots=True):
        """
        Generiert einen Bericht über XSS-Schwachstellen.
        
        Args:
            vulnerabilities: Die gefundenen Schwachstellen.
            report_format: Das Format des Berichts (html, json, markdown, txt).
            output_file: Die Ausgabedatei.
            include_screenshots: Ob Screenshots in den Bericht aufgenommen werden sollen.
        
        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        # Überprüfe, ob Schwachstellen vorhanden sind
        if not vulnerabilities:
            logger.warning("Keine Schwachstellen zum Berichten vorhanden.")
            return None
        
        # Normalisiere das Berichtsformat
        report_format = report_format.lower()
        
        # Überprüfe, ob das Berichtsformat unterstützt wird
        if report_format not in ["html", "json", "markdown", "txt"]:
            logger.warning(f"Nicht unterstütztes Berichtsformat: {report_format}")
            report_format = "html"
        
        # Erstelle den Dateinamen, falls keiner angegeben wurde
        if not output_file:
            timestamp = format_timestamp(get_timestamp(), "%Y%m%d_%H%M%S")
            output_file = os.path.join(self.reports_dir, f"xss_report_{timestamp}.{report_format}")
        
        # Generiere den Bericht basierend auf dem Format
        if report_format == "html":
            return self._generate_html_report(vulnerabilities, output_file, include_screenshots)
        elif report_format == "json":
            return self._generate_json_report(vulnerabilities, output_file)
        elif report_format == "markdown":
            return self._generate_markdown_report(vulnerabilities, output_file, include_screenshots)
        elif report_format == "txt":
            return self._generate_text_report(vulnerabilities, output_file)
        else:
            logger.error(f"Nicht unterstütztes Berichtsformat: {report_format}")
            return None
    
    def _generate_html_report(self, vulnerabilities, output_file, include_screenshots=True):
        """
        Generiert einen HTML-Bericht.
        
        Args:
            vulnerabilities: Die gefundenen Schwachstellen.
            output_file: Die Ausgabedatei.
            include_screenshots: Ob Screenshots in den Bericht aufgenommen werden sollen.
        
        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Überprüfe, ob Jinja2 verfügbar ist
            if not JINJA2_AVAILABLE:
                logger.warning("Jinja2 ist nicht verfügbar. Verwende einfache HTML-Generierung.")
                return self._generate_simple_html_report(vulnerabilities, output_file, include_screenshots)
            
            # Lade die HTML-Vorlage
            template_file = os.path.join(self.templates_dir, "report_template.html")
            
            if not os.path.isfile(template_file):
                logger.warning(f"HTML-Vorlage nicht gefunden: {template_file}")
                logger.info("Erstelle Standard-HTML-Vorlage...")
                
                # Erstelle die Standard-HTML-Vorlage
                self._create_default_html_template()
            
            # Lade die Vorlage
            template = self.jinja_env.get_template("report_template.html")
            
            # Bereite die Daten für die Vorlage vor
            data = {
                "title": "XSS Vulnerability Report",
                "timestamp": format_timestamp(get_timestamp()),
                "vulnerabilities": vulnerabilities,
                "include_screenshots": include_screenshots,
                "summary": {
                    "total": len(vulnerabilities),
                    "high": sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high"),
                    "medium": sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "medium"),
                    "low": sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "low")
                }
            }
            
            # Rendere die Vorlage
            html = template.render(**data)
            
            # Speichere den HTML-Bericht
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html)
            
            logger.info(f"HTML-Bericht wurde erstellt: {output_file}")
            
            return output_file
        except Exception as e:
            log_error(e, "HTML_REPORT_GENERATION_ERROR", {"output_file": output_file})
            return self._generate_simple_html_report(vulnerabilities, output_file, include_screenshots)
    
    def _generate_simple_html_report(self, vulnerabilities, output_file, include_screenshots=True):
        """
        Generiert einen einfachen HTML-Bericht ohne Jinja2.
        
        Args:
            vulnerabilities: Die gefundenen Schwachstellen.
            output_file: Die Ausgabedatei.
            include_screenshots: Ob Screenshots in den Bericht aufgenommen werden sollen.
        
        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Erstelle den HTML-Bericht
            html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Vulnerability Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background-color: #3498db;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .vulnerability {
            background-color: #fff;
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        .high {
            border-left: 5px solid #e74c3c;
        }
        .medium {
            border-left: 5px solid #f39c12;
        }
        .low {
            border-left: 5px solid #3498db;
        }
        .info {
            border-left: 5px solid #2ecc71;
        }
        .details {
            margin-top: 10px;
        }
        .details table {
            width: 100%;
            border-collapse: collapse;
        }
        .details table, .details th, .details td {
            border: 1px solid #ddd;
            padding: 8px;
        }
        .details th {
            background-color: #f2f2f2;
            text-align: left;
        }
        .screenshot {
            max-width: 100%;
            margin-top: 10px;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            font-size: 0.8em;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XSS Vulnerability Report</h1>
            <p>Generated on: """ + format_timestamp(get_timestamp()) + """</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>Total vulnerabilities found: """ + str(len(vulnerabilities)) + """</p>
            <p>High severity: """ + str(sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high")) + """</p>
            <p>Medium severity: """ + str(sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "medium")) + """</p>
            <p>Low severity: """ + str(sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "low")) + """</p>
        </div>
        
        <h2>Vulnerabilities</h2>
"""
            
            # Füge die Schwachstellen hinzu
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get("severity", "info").lower()
                
                html += f"""
        <div class="vulnerability {severity}">
            <h3>#{i}: {vuln.get("title", "XSS Vulnerability")}</h3>
            <div class="details">
                <table>
                    <tr>
                        <th>URL</th>
                        <td>{vuln.get("url", "N/A")}</td>
                    </tr>
                    <tr>
                        <th>Parameter</th>
                        <td>{vuln.get("param", "N/A")}</td>
                    </tr>
                    <tr>
                        <th>Payload</th>
                        <td>{vuln.get("payload", "N/A")}</td>
                    </tr>
                    <tr>
                        <th>Severity</th>
                        <td>{severity.capitalize()}</td>
                    </tr>
                    <tr>
                        <th>Context</th>
                        <td>{vuln.get("context", "N/A")}</td>
                    </tr>
                    <tr>
                        <th>Description</th>
                        <td>{vuln.get("description", "N/A")}</td>
                    </tr>
                </table>
"""
                
                # Füge Screenshots hinzu, falls vorhanden und gewünscht
                if include_screenshots and "screenshot" in vuln:
                    screenshot = vuln["screenshot"]
                    
                    if os.path.isfile(screenshot):
                        # Konvertiere das Bild in Base64
                        try:
                            with open(screenshot, "rb") as img_file:
                                img_data = base64.b64encode(img_file.read()).decode("utf-8")
                                
                                # Bestimme den MIME-Typ
                                mime_type = "image/png"
                                if screenshot.lower().endswith(".jpg") or screenshot.lower().endswith(".jpeg"):
                                    mime_type = "image/jpeg"
                                elif screenshot.lower().endswith(".gif"):
                                    mime_type = "image/gif"
                                
                                html += f"""
                <h4>Screenshot</h4>
                <img class="screenshot" src="data:{mime_type};base64,{img_data}" alt="Screenshot">
"""
                        except Exception as e:
                            log_error(e, "SCREENSHOT_EMBEDDING_ERROR", {"screenshot": screenshot})
                
                html += """
            </div>
        </div>
"""
            
            # Füge den Footer hinzu
            html += """
        <div class="footer">
            <p>Generated by XSS Hunter Pro Framework</p>
        </div>
    </div>
</body>
</html>
"""
            
            # Speichere den HTML-Bericht
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html)
            
            logger.info(f"Einfacher HTML-Bericht wurde erstellt: {output_file}")
            
            return output_file
        except Exception as e:
            log_error(e, "SIMPLE_HTML_REPORT_GENERATION_ERROR", {"output_file": output_file})
            return None
    
    def _generate_json_report(self, vulnerabilities, output_file):
        """
        Generiert einen JSON-Bericht.
        
        Args:
            vulnerabilities: Die gefundenen Schwachstellen.
            output_file: Die Ausgabedatei.
        
        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Erstelle den JSON-Bericht
            report = {
                "title": "XSS Vulnerability Report",
                "timestamp": get_timestamp(),
                "formatted_timestamp": format_timestamp(get_timestamp()),
                "vulnerabilities": vulnerabilities,
                "summary": {
                    "total": len(vulnerabilities),
                    "high": sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high"),
                    "medium": sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "medium"),
                    "low": sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "low")
                }
            }
            
            # Speichere den JSON-Bericht
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"JSON-Bericht wurde erstellt: {output_file}")
            
            return output_file
        except Exception as e:
            log_error(e, "JSON_REPORT_GENERATION_ERROR", {"output_file": output_file})
            return None
    
    def _generate_markdown_report(self, vulnerabilities, output_file, include_screenshots=True):
        """
        Generiert einen Markdown-Bericht.
        
        Args:
            vulnerabilities: Die gefundenen Schwachstellen.
            output_file: Die Ausgabedatei.
            include_screenshots: Ob Screenshots in den Bericht aufgenommen werden sollen.
        
        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Erstelle den Markdown-Bericht
            markdown_text = f"""# XSS Vulnerability Report

Generated on: {format_timestamp(get_timestamp())}

## Summary

- Total vulnerabilities found: {len(vulnerabilities)}
- High severity: {sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high")}
- Medium severity: {sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "medium")}
- Low severity: {sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "low")}

## Vulnerabilities

"""
            
            # Füge die Schwachstellen hinzu
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get("severity", "info").lower()
                
                markdown_text += f"""### #{i}: {vuln.get("title", "XSS Vulnerability")}

- **URL**: {vuln.get("url", "N/A")}
- **Parameter**: {vuln.get("param", "N/A")}
- **Payload**: `{vuln.get("payload", "N/A")}`
- **Severity**: {severity.capitalize()}
- **Context**: {vuln.get("context", "N/A")}

**Description**:
{vuln.get("description", "N/A")}

"""
                
                # Füge Screenshots hinzu, falls vorhanden und gewünscht
                if include_screenshots and "screenshot" in vuln:
                    screenshot = vuln["screenshot"]
                    
                    if os.path.isfile(screenshot):
                        # Verwende relativen Pfad für das Bild
                        rel_path = os.path.relpath(screenshot, os.path.dirname(output_file))
                        markdown_text += f"""**Screenshot**:
![Screenshot]({rel_path})

"""
            
            # Füge den Footer hinzu
            markdown_text += """---
Generated by XSS Hunter Pro Framework
"""
            
            # Speichere den Markdown-Bericht
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(markdown_text)
            
            logger.info(f"Markdown-Bericht wurde erstellt: {output_file}")
            
            # Konvertiere Markdown zu HTML, falls Markdown verfügbar ist
            if MARKDOWN_AVAILABLE:
                html_output_file = output_file.replace(".markdown", ".html").replace(".md", ".html")
                
                with open(html_output_file, "w", encoding="utf-8") as f:
                    html = markdown.markdown(markdown_text)
                    
                    # Füge HTML-Header und -Footer hinzu
                    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Vulnerability Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        img {{
            max-width: 100%;
        }}
    </style>
</head>
<body>
    <div class="container">
        {html}
    </div>
</body>
</html>
"""
                    
                    f.write(html)
                
                logger.info(f"HTML-Version des Markdown-Berichts wurde erstellt: {html_output_file}")
            
            return output_file
        except Exception as e:
            log_error(e, "MARKDOWN_REPORT_GENERATION_ERROR", {"output_file": output_file})
            return None
    
    def _generate_text_report(self, vulnerabilities, output_file):
        """
        Generiert einen Textbericht.
        
        Args:
            vulnerabilities: Die gefundenen Schwachstellen.
            output_file: Die Ausgabedatei.
        
        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Erstelle den Textbericht
            text = f"""XSS Vulnerability Report
======================

Generated on: {format_timestamp(get_timestamp())}

Summary
-------
Total vulnerabilities found: {len(vulnerabilities)}
High severity: {sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high")}
Medium severity: {sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "medium")}
Low severity: {sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "low")}

Vulnerabilities
--------------
"""
            
            # Füge die Schwachstellen hinzu
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get("severity", "info").lower()
                
                text += f"""
#{i}: {vuln.get("title", "XSS Vulnerability")}
{'=' * (len(str(i)) + 2 + len(vuln.get("title", "XSS Vulnerability")))}
URL: {vuln.get("url", "N/A")}
Parameter: {vuln.get("param", "N/A")}
Payload: {vuln.get("payload", "N/A")}
Severity: {severity.capitalize()}
Context: {vuln.get("context", "N/A")}

Description:
{vuln.get("description", "N/A")}

"""
            
            # Füge den Footer hinzu
            text += """
---
Generated by XSS Hunter Pro Framework
"""
            
            # Speichere den Textbericht
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(text)
            
            logger.info(f"Textbericht wurde erstellt: {output_file}")
            
            return output_file
        except Exception as e:
            log_error(e, "TEXT_REPORT_GENERATION_ERROR", {"output_file": output_file})
            return None
    
    def _create_default_html_template(self):
        """
        Erstellt die Standard-HTML-Vorlage.
        
        Returns:
            True, wenn die Vorlage erfolgreich erstellt wurde, sonst False.
        """
        try:
            # Erstelle das Verzeichnis, falls es nicht existiert
            os.makedirs(self.templates_dir, exist_ok=True)
            
            # Erstelle die HTML-Vorlage
            template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background-color: #3498db;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .vulnerability {
            background-color: #fff;
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        .high {
            border-left: 5px solid #e74c3c;
        }
        .medium {
            border-left: 5px solid #f39c12;
        }
        .low {
            border-left: 5px solid #3498db;
        }
        .info {
            border-left: 5px solid #2ecc71;
        }
        .details {
            margin-top: 10px;
        }
        .details table {
            width: 100%;
            border-collapse: collapse;
        }
        .details table, .details th, .details td {
            border: 1px solid #ddd;
            padding: 8px;
        }
        .details th {
            background-color: #f2f2f2;
            text-align: left;
        }
        .screenshot {
            max-width: 100%;
            margin-top: 10px;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            font-size: 0.8em;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ title }}</h1>
            <p>Generated on: {{ timestamp }}</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>Total vulnerabilities found: {{ summary.total }}</p>
            <p>High severity: {{ summary.high }}</p>
            <p>Medium severity: {{ summary.medium }}</p>
            <p>Low severity: {{ summary.low }}</p>
        </div>
        
        <h2>Vulnerabilities</h2>
        
        {% for vuln in vulnerabilities %}
        <div class="vulnerability {{ vuln.severity|default('info')|lower }}">
            <h3>#{{ loop.index }}: {{ vuln.title|default('XSS Vulnerability') }}</h3>
            <div class="details">
                <table>
                    <tr>
                        <th>URL</th>
                        <td>{{ vuln.url|default('N/A') }}</td>
                    </tr>
                    <tr>
                        <th>Parameter</th>
                        <td>{{ vuln.param|default('N/A') }}</td>
                    </tr>
                    <tr>
                        <th>Payload</th>
                        <td>{{ vuln.payload|default('N/A') }}</td>
                    </tr>
                    <tr>
                        <th>Severity</th>
                        <td>{{ vuln.severity|default('Info')|capitalize }}</td>
                    </tr>
                    <tr>
                        <th>Context</th>
                        <td>{{ vuln.context|default('N/A') }}</td>
                    </tr>
                    <tr>
                        <th>Description</th>
                        <td>{{ vuln.description|default('N/A') }}</td>
                    </tr>
                </table>
                
                {% if include_screenshots and vuln.screenshot %}
                <h4>Screenshot</h4>
                <img class="screenshot" src="{{ vuln.screenshot }}" alt="Screenshot">
                {% endif %}
            </div>
        </div>
        {% endfor %}
        
        <div class="footer">
            <p>Generated by XSS Hunter Pro Framework</p>
        </div>
    </div>
</body>
</html>
"""
            
            # Speichere die Vorlage
            template_file = os.path.join(self.templates_dir, "report_template.html")
            
            with open(template_file, "w", encoding="utf-8") as f:
                f.write(template)
            
            logger.info(f"Standard-HTML-Vorlage wurde erstellt: {template_file}")
            
            return True
        except Exception as e:
            log_error(e, "HTML_TEMPLATE_CREATION_ERROR")
            return False
    
    @handle_exception
    def load_vulnerabilities(self, file_path):
        """
        Lädt Schwachstellen aus einer Datei.
        
        Args:
            file_path: Der Pfad zur Datei.
        
        Returns:
            Die geladenen Schwachstellen.
        """
        try:
            # Überprüfe, ob die Datei existiert
            if not os.path.isfile(file_path):
                logger.error(f"Datei nicht gefunden: {file_path}")
                return []
            
            # Bestimme das Dateiformat
            if file_path.lower().endswith(".json"):
                # Lade die JSON-Datei
                data = load_json_file(file_path)
                
                # Extrahiere die Schwachstellen
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and "vulnerabilities" in data:
                    return data["vulnerabilities"]
                else:
                    logger.error(f"Ungültiges JSON-Format: {file_path}")
                    return []
            else:
                logger.error(f"Nicht unterstütztes Dateiformat: {file_path}")
                return []
        except Exception as e:
            log_error(e, "VULNERABILITIES_LOADING_ERROR", {"file_path": file_path})
            return []
    
    @handle_exception
    def save_vulnerabilities(self, vulnerabilities, file_path):
        """
        Speichert Schwachstellen in einer Datei.
        
        Args:
            vulnerabilities: Die zu speichernden Schwachstellen.
            file_path: Der Pfad zur Datei.
        
        Returns:
            True, wenn die Schwachstellen erfolgreich gespeichert wurden, sonst False.
        """
        try:
            # Überprüfe, ob Schwachstellen vorhanden sind
            if not vulnerabilities:
                logger.warning("Keine Schwachstellen zum Speichern vorhanden.")
                return False
            
            # Bestimme das Dateiformat
            if file_path.lower().endswith(".json"):
                # Erstelle die Daten
                data = {
                    "title": "XSS Vulnerability Report",
                    "timestamp": get_timestamp(),
                    "formatted_timestamp": format_timestamp(get_timestamp()),
                    "vulnerabilities": vulnerabilities
                }
                
                # Speichere die JSON-Datei
                return save_json_file(data, file_path)
            else:
                logger.error(f"Nicht unterstütztes Dateiformat: {file_path}")
                return False
        except Exception as e:
            log_error(e, "VULNERABILITIES_SAVING_ERROR", {"file_path": file_path})
            return False
    
    @handle_exception
    def merge_reports(self, report_files, output_file, report_format="html"):
        """
        Führt mehrere Berichte zusammen.
        
        Args:
            report_files: Die zusammenzuführenden Berichtsdateien.
            output_file: Die Ausgabedatei.
            report_format: Das Format des zusammengeführten Berichts.
        
        Returns:
            Der Pfad zur generierten Berichtsdatei.
        """
        try:
            # Überprüfe, ob Berichtsdateien vorhanden sind
            if not report_files:
                logger.warning("Keine Berichtsdateien zum Zusammenführen vorhanden.")
                return None
            
            # Lade die Schwachstellen aus den Berichtsdateien
            all_vulnerabilities = []
            
            for file_path in report_files:
                vulnerabilities = self.load_vulnerabilities(file_path)
                all_vulnerabilities.extend(vulnerabilities)
            
            # Überprüfe, ob Schwachstellen geladen wurden
            if not all_vulnerabilities:
                logger.warning("Keine Schwachstellen aus den Berichtsdateien geladen.")
                return None
            
            # Generiere den zusammengeführten Bericht
            return self.generate_report(all_vulnerabilities, report_format, output_file)
        except Exception as e:
            log_error(e, "REPORTS_MERGING_ERROR", {"report_files": report_files, "output_file": output_file})
            return None


# Beispielverwendung
if __name__ == "__main__":
    # Erstelle einen Report-Generator
    generator = ReportGenerator()
    
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
    
    # Generiere Berichte in verschiedenen Formaten
    html_report = generator.generate_report(vulnerabilities, "html")
    json_report = generator.generate_report(vulnerabilities, "json")
    markdown_report = generator.generate_report(vulnerabilities, "markdown")
    text_report = generator.generate_report(vulnerabilities, "txt")
    
    print(f"HTML-Bericht: {html_report}")
    print(f"JSON-Bericht: {json_report}")
    print(f"Markdown-Bericht: {markdown_report}")
    print(f"Text-Bericht: {text_report}")
