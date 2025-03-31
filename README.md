# XSS Hunter Pro Framework - Dokumentation

## Übersicht

Das XSS Hunter Pro Framework ist ein umfassendes Tool zur Erkennung und Ausnutzung von Cross-Site-Scripting (XSS) Schwachstellen in Webanwendungen. 
Es bietet fortschrittliche Funktionen wie maschinelles Lernen zur Payload-Generierung, WAF-Erkennung und -Umgehung, sowie detaillierte Validierung von gefundenen Schwachstellen.


Status aktuell: 

under heavy dev --- BETA 
Also net rumheulen sondern mitcoden ;)


## Installation

### Voraussetzungen

- Python 3.8 oder höher
- pip (Python-Paketmanager)

### Abhängigkeiten installieren

```bash
pip install -r requirements.txt
```

Die Datei `requirements.txt` enthält folgende Abhängigkeiten:

```
requests>=2.25.1
beautifulsoup4>=4.9.3
colorama>=0.4.4
jinja2>=3.0.1
urllib3>=1.26.5
selenium>=4.0.0
pillow>=8.2.0
```

## Verwendung

Das Framework bietet verschiedene Modi für unterschiedliche Anwendungsfälle:

### Scan-Modus

Der Scan-Modus durchsucht eine Webseite nach XSS-Schwachstellen.

```bash
python main.py --mode scan --url https://example.com --depth 2 --xss-types all --screenshot --use-ml
```

### Exploit-Modus

Der Exploit-Modus nutzt eine bekannte XSS-Schwachstelle aus.

```bash
python main.py --mode exploit --url https://example.com --param q --exploit-type reflected_xss --verify
```

### Payload-Modus

Der Payload-Modus generiert XSS-Payloads für verschiedene Kontexte.

```bash
python main.py --mode payload --context html --complexity 3 --size 10
```

### Report-Modus

Der Report-Modus erstellt Berichte aus vorhandenen Scan-Ergebnissen.

```bash
python main.py --mode report --input ./output/results/vulnerabilities.json --format html
```

## Kommandozeilenargumente

Das Framework unterstützt folgende Kommandozeilenargumente:

### Allgemeine Argumente

| Argument | Beschreibung | Standardwert |
|----------|--------------|--------------|
| `--help`, `-h` | Zeigt die Hilfe an | - |
| `--version` | Zeigt die Version an | - |
| `--mode` | Betriebsmodus (scan, exploit, payload, report) | scan |
| `--verbose` | Ausführliche Ausgabe | False |
| `--output-dir` | Ausgabeverzeichnis | ./output |
| `--debug` | Debug-Modus aktivieren | False |

### Scan-Modus Argumente

| Argument | Beschreibung | Standardwert |
|----------|--------------|--------------|
| `--url` | Ziel-URL | - |
| `--depth` | Crawling-Tiefe | 1 |
| `--threads` | Anzahl der Threads | 5 |
| `--timeout` | Timeout in Sekunden | 10 |
| `--user-agent` | User-Agent-String | Mozilla/5.0... |
| `--cookies` | Cookies (Format: name1=value1;name2=value2) | - |
| `--headers` | HTTP-Header (Format: name1:value1;name2:value2) | - |
| `--proxy` | Proxy-URL | - |
| `--scan-type` | Scan-Typ (full, quick, passive) | full |
| `--exclude` | Auszuschließende URLs (Regex) | - |
| `--include` | Einzuschließende URLs (Regex) | - |
| `--follow-redirects` | Weiterleitungen folgen | False |
| `--max-redirects` | Maximale Anzahl von Weiterleitungen | 3 |
| `--auth` | Authentifizierungsdaten (Format: username:password) | - |
| `--auth-type` | Authentifizierungstyp (basic, digest, ntlm) | basic |
| `--xss-types` | XSS-Typen (all, reflected, stored, dom) | all |
| `--payloads-file` | Pfad zur Payloads-Datei | ./data/xss_payloads.json |
| `--callback-server` | Callback-Server starten | False |
| `--callback-port` | Port für den Callback-Server | 8090 |
| `--screenshot` | Screenshots erstellen | False |
| `--browser` | Browser für Screenshots (chrome, firefox, edge) | chrome |
| `--use-ml` | Maschinelles Lernen verwenden | False |

### Exploit-Modus Argumente

| Argument | Beschreibung | Standardwert |
|----------|--------------|--------------|
| `--url` | Ziel-URL | - |
| `--param` | Zu testender Parameter | - |
| `--exploit-type` | Exploit-Typ (reflected_xss, stored_xss, dom_xss) | reflected_xss |
| `--verify` | Exploit verifizieren | False |

### Payload-Modus Argumente

| Argument | Beschreibung | Standardwert |
|----------|--------------|--------------|
| `--payload-context` | Payload-Kontext (html, js, attr) | html |
| `--complexity` | Payload-Komplexität (1-3) | 1 |
| `--size` | Anzahl der zu generierenden Payloads | 10 |
| `--use-ml` | Maschinelles Lernen verwenden | False |

### Report-Modus Argumente

| Argument | Beschreibung | Standardwert |
|----------|--------------|--------------|
| `--report-file` | Pfad zur Ergebnisdatei | ./output/results/vulnerabilities.json |
| `--report-format` | Berichtsformat (html, json, txt) | html |

## Fehlerbehebung

### Bekannte Probleme und Lösungen

#### 1. Fehlende Module

**Problem:** Meldungen wie "Modul konnte nicht importiert werden"

**Lösung:** Stellen Sie sicher, dass alle Abhängigkeiten installiert sind:

```bash
pip install -r requirements.txt
```

Für Browser-Automatisierung (Screenshots):

```bash
pip install selenium webdriver-manager
```

#### 2. WAF-Erkennung und -Umgehung

**Problem:** WAF blockiert Anfragen

**Lösung:** Verwenden Sie die WAF-Bypass-Funktionen:

```bash
python main.py --mode scan --url https://example.com --waf-bypass
```

#### 3. Falsch-positive XSS-Funde

**Problem:** Framework meldet XSS-Schwachstellen, die nicht ausnutzbar sind

**Lösung:** Erhöhen Sie das Validierungslevel und aktivieren Sie die Verifizierung:

```bash
python main.py --mode scan --url https://example.com --verify-xss
```

#### 4. ML-Module-Fehler

**Problem:** Fehler bei der Verwendung des ML-Moduls

**Lösung:** Stellen Sie sicher, dass die erforderlichen ML-Abhängigkeiten installiert sind:

```bash
pip install numpy scikit-learn
```

#### 5. Callback-Server-Probleme

**Problem:** Callback-Server startet nicht oder ist nicht erreichbar

**Lösung:** Überprüfen Sie, ob der Port verfügbar ist und keine Firewall den Zugriff blockiert:

```bash
python main.py --mode scan --url https://example.com --callback-server --callback-port 8091
```

## Erweiterte Funktionen

### WAF-Erkennung und -Umgehung

Das Framework kann Web Application Firewalls (WAFs) erkennen und Techniken zur Umgehung anwenden:

```bash
python main.py --mode scan --url https://example.com --waf-detect --waf-bypass
```

### Maschinelles Lernen

Das Framework verwendet maschinelles Lernen zur Verbesserung der Payload-Generierung und Schwachstellenerkennung:

```bash
python main.py --mode scan --url https://example.com --use-ml
```

### XSS-Validierung

Das Framework bietet verschiedene Validierungsstufen für XSS-Schwachstellen:

```bash
python main.py --mode scan --url https://example.com --verify-xss --verify-level 3
```

Validierungsstufen:
- 0: Keine Validierung (alle Funde akzeptieren)
- 1: Einfache Validierung (Marker muss in der Antwort enthalten sein)
- 2: Standard-Validierung (Marker muss in der Antwort enthalten sein und Kontext muss bestimmt werden können)
- 3: Strenge Validierung (Marker muss in der Antwort enthalten sein, Kontext muss bestimmt werden können und Payload muss ausführbar sein)

### Callback-Server

Der Callback-Server ermöglicht die Erkennung von Blind-XSS und Out-of-Band-XSS:

```bash
python main.py --mode scan --url https://example.com --callback-server --callback-port 8090
```

## Beispielszenarien

### Szenario 1: Vollständiger Bug Bounty Workflow

```bash
# Schritt 1: Zielaufklärung
python main.py --mode scan --url https://example.com --depth 0 --scan-type passive

# Schritt 2: Schwachstellensuche
python main.py --mode scan --url https://example.com --depth 2 --xss-types all --use-ml --screenshot

# Schritt 3: Exploit verifizieren
python main.py --mode exploit --url https://example.com --param q --exploit-type reflected_xss --verify

# Schritt 4: Bericht erstellen
python main.py --mode report --report-file ./output/results/vulnerabilities.json --report-format html
```

### Szenario 2: Authentifizierter Scan

```bash
python main.py --mode scan --url https://example.com/dashboard --auth "username:password" --auth-type basic --cookies "session=abc123" --depth 2
```

### Szenario 3: DOM-basierte XSS-Suche

```bash
python main.py --mode scan --url https://example.com --xss-types dom --browser chrome --screenshot
```

## Modulstruktur

Das Framework besteht aus folgenden Hauptmodulen:

- `main.py`: Haupteinstiegspunkt und Kommandozeilenverarbeitung
- `modules/`: Kernmodule für Scanning und Validierung
  - `target_discovery.py`: Zielaufklärung und Crawling
  - `xss_validator.py`: XSS-Validierung
  - `dom_xss_detector.py`: DOM-basierte XSS-Erkennung
  - `stored_xss_detector.py`: Gespeicherte XSS-Erkennung
  - `report_generator.py`: Berichtserstellung
- `integrations/`: Integrationen mit externen Tools
  - `webcrawler.py`: Web-Crawler-Integration
  - `waf_scanner.py`: WAF-Erkennung und -Umgehung
  - `vulnerability_scanner.py`: Integration mit Vulnerability Scannern
  - `fuzzing.py`: Fuzzing-Tool-Integration
- `utils.py`: Hilfsfunktionen
- `ml_module.py`: Maschinelles Lernen
- `callback_server.py`: Callback-Server für Out-of-Band-Tests
- `exploit_verifier.py`: Exploit-Verifizierung

## Ausgabeformate

Das Framework kann Ergebnisse in verschiedenen Formaten ausgeben:

### JSON-Format

```json
{
  "scan_info": {
    "url": "https://example.com",
    "timestamp": "2025-03-31T08:00:00Z",
    "duration": 120
  },
  "vulnerabilities": [
    {
      "type": "reflected_xss",
      "url": "https://example.com/search",
      "parameter": "q",
      "payload": "<script>alert('XSS')</script>",
      "severity": "HIGH",
      "description": "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle im HTML-Kontext",
      "exploitation": "Um diese Schwachstelle auszunutzen...",
      "screenshot": "/path/to/screenshot.png",
      "verified": true
    }
  ]
}
```

### HTML-Bericht

Das Framework generiert detaillierte HTML-Berichte mit:
- Zusammenfassung der Ergebnisse
- Detaillierte Beschreibung jeder Schwachstelle
- Screenshots (falls aktiviert)
- Reproduktionsschritte
- Empfehlungen zur Behebung

## Best Practices

### Für Scanning

1. Beginnen Sie mit einem passiven Scan, um das Ziel zu verstehen:
   ```bash
   python main.py --mode scan --url https://example.com --scan-type passive
   ```

2. Führen Sie einen vollständigen Scan mit moderater Tiefe durch:
   ```bash
   python main.py --mode scan --url https://example.com --depth 2 --xss-types all
   ```

3. Aktivieren Sie ML für bessere Ergebnisse:
   ```bash
   python main.py --mode scan --url https://example.com --use-ml
   ```

4. Verifizieren Sie gefundene Schwachstellen:
   ```bash
   python main.py --mode exploit --url https://example.com --param q --verify
   ```

### Für Reporting

1. Generieren Sie detaillierte HTML-Berichte:
   ```bash
   python main.py --mode report --report-format html
   ```

2. Fügen Sie Screenshots hinzu:
   ```bash
   python main.py --mode scan --url https://example.com --screenshot
   ```

3. Exportieren Sie Ergebnisse für weitere Analyse:
   ```bash
   python main.py --mode report --report-format json
   ```

## Häufig gestellte Fragen (FAQ)

### Allgemeine Fragen

**F: Wie kann ich die Scan-Geschwindigkeit erhöhen?**

A: Erhöhen Sie die Anzahl der Threads und reduzieren Sie die Crawling-Tiefe:
```bash
python main.py --mode scan --url https://example.com --threads 10 --depth 1
```

**F: Wie kann ich falsch-positive Ergebnisse reduzieren?**

A: Aktivieren Sie die strenge Validierung und Verifizierung:
```bash
python main.py --mode scan --url https://example.com --verify-xss --verify-level 3
```

**F: Wie kann ich WAFs umgehen?**

A: Verwenden Sie die WAF-Bypass-Funktionen:
```bash
python main.py --mode scan --url https://example.com --waf-bypass
```

**F: Wie kann ich authentifizierte Scans durchführen?**

A: Verwenden Sie die Authentifizierungsparameter:
```bash
python main.py --mode scan --url https://example.com --auth "username:password" --cookies "session=abc123"
```

**F: Wie kann ich DOM-basierte XSS erkennen?**

A: Verwenden Sie den DOM-XSS-Modus mit Browser-Automatisierung:
```bash
python main.py --mode scan --url https://example.com --xss-types dom --browser chrome
```

### Technische Fragen

**F: Welche Python-Version wird unterstützt?**

A: Python 3.8 oder höher wird empfohlen.

**F: Kann ich das Framework in CI/CD-Pipelines integrieren?**

A: Ja, verwenden Sie den nicht-interaktiven Modus:
```bash
python main.py --mode scan --url https://example.com --output-dir ./reports --report-format json --no-interactive
```

**F: Wie kann ich benutzerdefinierte Payloads verwenden?**

A: Erstellen Sie eine eigene Payloads-Datei und verwenden Sie den Parameter `--payloads-file`:
```bash
python main.py --mode scan --url https://example.com --payloads-file ./my_payloads.json
```

**F: Wie kann ich die Ergebnisse filtern?**

A: Verwenden Sie die Filter-Parameter im Report-Modus:
```bash
python main.py --mode report --report-file ./output/results/vulnerabilities.json --filter-severity HIGH,CRITICAL
```

**F: Wie kann ich das Framework erweitern?**

A: Das Framework ist modular aufgebaut. Sie können eigene Module in den entsprechenden Verzeichnissen hinzufügen und in `main.py` registrieren.

## Lizenz

MIT-Lizenz

## Kontakt

Bei Fragen oder Problemen erstellen Sie bitte ein Issue im GitHub-Repository.
