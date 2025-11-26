# XSS Hunter Pro Framework - Dokumentation

## Übersicht

Das XSS Hunter Pro Framework ist ein umfassendes Tool für professionelles XSS Bug Bounty Hunting. Es bietet eine vollständige Lösung für die Erkennung, Ausnutzung, Validierung und Dokumentation von Cross-Site Scripting (XSS) Schwachstellen.

## Funktionen

- **Vollständige Exploitations-Engine**: Unterstützt verschiedene Exploit-Typen wie Datendiebstahl, Keylogger, DOM-Manipulation und Cookie-Diebstahl
- **ML-basierte Payload-Optimierung**: Verwendet maschinelles Lernen zur Optimierung von Payloads für verschiedene Kontexte
- **Umfassende Schwachstellenkategorisierung**: Klassifiziert Schwachstellen nach Typ, Schweregrad und Auswirkung
- **Professionelle Berichterstellung**: Erstellt detaillierte Berichte in verschiedenen Formaten (HTML, JSON, Markdown)
- **Screenshot-Funktionalität**: Erstellt automatisch Screenshots von erfolgreichen XSS-Exploits
- **Verbesserte Befehlszeilenparameter**: Bietet eine umfangreiche Kommandozeilenschnittstelle für alle Funktionen

## Installation

```bash
# Klonen des Repositories
git clone https://github.com/Leviticus-Triage/XSS_Hunter.git
cd XSS_Hunter

# Installation der Abhängigkeiten
pip install -r requirements.txt
```

## Verwendung

Das Framework bietet vier Hauptbetriebsmodi:

### 1. Scan-Modus

Scannt eine Website nach XSS-Schwachstellen:

```bash
python main.py scan --url https://example.com --depth 3
```

### 2. Exploit-Modus

Nutzt eine bekannte XSS-Schwachstelle aus:

```bash
python main.py exploit --url https://example.com/search --param q --exploit-type data_theft
```

### 3. Payload-Modus

Generiert optimierte XSS-Payloads:

```bash
python main.py payload --payload-context javascript --use-ml
```

### 4. Report-Modus

Erstellt Berichte aus gefundenen Schwachstellen:

```bash
python main.py report --report-file vulnerabilities.json --report-format html
```

## Erweiterte Konfiguration

Das Framework kann über die Konfigurationsdatei `config.json` angepasst werden:

```json
{
  "general": {
    "debug": false,
    "log_level": "INFO",
    "log_file": "xsshunterpro.log",
    "timeout": 30
  },
  "tools": {
    "gospider": {
      "type": "command_line",
      "description": "Fast web spider written in Go"
    },
    "subfinder": {
      "type": "command_line",
      "description": "Subdomain discovery tool"
    }
  },
  "screenshot": {
    "enabled": true,
    "browser_type": "chrome",
    "headless": true,
    "width": 1366,
    "height": 768,
    "timeout": 30,
    "screenshot_dir": "screenshots"
  },
  "payloads": {
    "use_ml_optimization": true,
    "payload_files": [
      "payloads/basic.json",
      "payloads/advanced.json",
      "payloads/dom.json",
      "payloads/waf_bypass.json"
    ]
  },
  "reporting": {
    "report_dir": "reports",
    "formats": ["html", "json", "markdown"],
    "include_screenshots": true,
    "include_payloads": true,
    "include_request_response": true
  },
  "exploitation": {
    "callback_server": {
      "enabled": true,
      "host": "0.0.0.0",
      "port": 8080,
      "external_url": ""
    },
    "exploit_types": [
      "data_theft",
      "keylogger",
      "dom_manipulation",
      "cookie_stealing"
    ]
  }
}
```

## Architektur

Das Framework besteht aus mehreren Komponenten:

- **Adapter-Schicht**: Bietet eine einheitliche Schnittstelle für externe Tools
- **Integrations-Module**: Integriert verschiedene Werkzeuge für Web-Crawling, Fuzzing, Subdomain-Discovery und Vulnerability-Scanning
- **Orchestrator**: Koordiniert die Interaktionen zwischen den Komponenten
- **Payload-Manager**: Verwaltet und optimiert XSS-Payloads
- **Exploitation-Engine**: Führt XSS-Exploits aus
- **Callback-Server**: Empfängt Callbacks von erfolgreichen XSS-Exploits
- **Report-Generator**: Erstellt detaillierte Berichte
- **Screenshot-Manager**: Erstellt Screenshots von erfolgreichen XSS-Exploits

## Erweiterbarkeit

Das Framework ist modular aufgebaut und kann leicht erweitert werden:

- **Neue Tools**: Können über die Adapter-Schicht integriert werden
- **Neue Payloads**: Können in den Payload-Dateien hinzugefügt werden
- **Neue Exploit-Typen**: Können in der Exploitation-Engine implementiert werden
- **Neue Report-Formate**: Können im Report-Generator hinzugefügt werden

## Lizenz

MIT

## Autor

Anonymous
