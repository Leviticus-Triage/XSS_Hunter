# XSS Bug Bounty Hunting Framework - Dokumentation

## Überblick

Das XSS Bug Bounty Hunting Framework ist ein leistungsstarkes Tool für Sicherheitsforscher und Bug Bounty Hunter, um Cross-Site Scripting (XSS) Schwachstellen in Webanwendungen zu identifizieren, zu validieren und zu dokumentieren. Das Framework bietet eine umfassende Lösung für den gesamten Bug Bounty Workflow, von der Zielidentifikation bis zur Berichterstellung.

## Funktionen

- **Automatisierte Schwachstellensuche**: Scannt Websites nach XSS-Schwachstellen mit verschiedenen Payloads
- **Schwachstellenklassifizierung**: Bewertet gefundene Schwachstellen nach Schweregrad (leicht, mittel, kritisch, katastrophal)
- **Detaillierte Beschreibungen**: Liefert ausführliche Informationen zu jeder gefundenen Schwachstelle
- **Exploitation-Anleitungen**: Bietet konkrete Anleitungen zur Ausnutzung der gefundenen Schwachstellen
- **Automatische Screenshots**: Erstellt automatisch Screenshots von gefundenen Schwachstellen
- **Berichterstellung**: Generiert detaillierte HTML-Reports und JSON-Dateien für die Dokumentation
- **Debugging-URLs**: Erstellt direkte Links zum Testen und Verifizieren von Schwachstellen
- **Moderne Benutzeroberfläche**: Zeigt Fortschritt und Ergebnisse in einer übersichtlichen, dynamischen Anzeige

## Installation

### Voraussetzungen

- Python 3.8 oder höher
- pip (Python-Paketmanager)

### Installation der Abhängigkeiten

```bash
pip install colorama requests beautifulsoup4 jinja2
```

## Verwendung

### Grundlegende Befehle

#### Scan-Modus

Der Scan-Modus ist der Hauptmodus des Frameworks und wird verwendet, um Websites nach XSS-Schwachstellen zu scannen.

```bash
python main.py --mode scan --url https://example.com -d 2
```

Parameter:
- `--url`: Die zu scannende URL
- `-d, --depth`: Die Tiefe des Crawlings (Standard: 1)
- `--use-ml`: Verwendet Machine Learning für die Erkennung (optional)
- `--threads`: Anzahl der gleichzeitigen Threads (Standard: 5)
- `--timeout`: Timeout für HTTP-Anfragen in Sekunden (Standard: 30)
- `--user-agent`: Benutzerdefinierter User-Agent (optional)
- `--cookies`: Cookies für authentifizierte Scans (optional)
- `--headers`: Zusätzliche HTTP-Header (optional)

#### Exploit-Modus

Der Exploit-Modus wird verwendet, um eine bestimmte XSS-Schwachstelle zu testen und auszunutzen.

```bash
python main.py --mode exploit --url https://example.com --param q --exploit-type reflected_xss
```

Parameter:
- `--url`: Die URL mit der Schwachstelle
- `--param`: Der anfällige Parameter
- `--exploit-type`: Art der Schwachstelle (reflected_xss, stored_xss, dom_xss)
- `--payload`: Benutzerdefinierter Payload (optional)
- `--cookies`: Cookies für authentifizierte Exploits (optional)

#### Payload-Modus

Der Payload-Modus wird verwendet, um XSS-Payloads zu generieren und zu testen.

```bash
python main.py --mode payload --generate 10 --output payloads.txt
```

Parameter:
- `--generate`: Anzahl der zu generierenden Payloads
- `--output`: Ausgabedatei für die generierten Payloads
- `--type`: Art der Payloads (standard, obfuscated, advanced)
- `--custom`: Benutzerdefinierte Payload-Vorlage (optional)

#### Report-Modus

Der Report-Modus wird verwendet, um Berichte aus vorhandenen Scan-Ergebnissen zu generieren.

```bash
python main.py --mode report --input vulnerabilities.json --output-format html
```

Parameter:
- `--input`: Eingabedatei mit den Schwachstellendaten
- `--output-format`: Format des Berichts (html, pdf, markdown)
- `--template`: Benutzerdefinierte Berichtsvorlage (optional)

### Beispiele

#### Vollständiger Bug Bounty Workflow

1. **Zielidentifikation und Aufklärung**:
   ```bash
   python main.py --mode scan --url https://example.com --subdomain-discovery
   ```

2. **Schwachstellensuche**:
   ```bash
   python main.py --mode scan --url https://example.com -d 3 --use-ml --threads 10
   ```

3. **Schwachstellenvalidierung**:
   ```bash
   python main.py --mode exploit --url https://example.com/search.php --param q --exploit-type reflected_xss
   ```

4. **Berichterstellung**:
   ```bash
   python main.py --mode report --input vulnerabilities_20250330_134950.json --output-format html
   ```

#### Authentifizierter Scan

```bash
python main.py --mode scan --url https://example.com -d 2 --cookies "session=abc123; auth=xyz789"
```

#### DOM-basierte XSS-Suche

```bash
python main.py --mode scan --url https://example.com --dom-based-only
```

## Ausgabeformate

### JSON-Format

Die Scan-Ergebnisse werden in einer JSON-Datei gespeichert, die folgende Struktur hat:

```json
{
  "scan_info": {
    "target": "https://example.com",
    "start_time": "2025-03-30 13:49:50",
    "end_time": "2025-03-30 13:50:05",
    "duration": "15s",
    "depth": 1,
    "threads": 5
  },
  "statistics": {
    "urls_found": 7,
    "parameters_found": 4,
    "vulnerabilities_found": 2
  },
  "vulnerabilities": [
    {
      "type": "REFLECTED_XSS",
      "url": "https://example.com/search.php",
      "parameter": "q70",
      "method": "GET",
      "payload": "<script>alert('Vc2Rc4Z3sOvU')</script>",
      "severity": "LOW",
      "debug_url": "https://example.com/search.php?q70=%3Cscript%3Ealert%28%27Vc2Rc4Z3sOvU%27%29%3C/script%3E",
      "screenshot": "/home/ubuntu/hunter_analysis/test_final/screenshots/xss_20250330_134950_Vc2Rc4Z3sOvU.png",
      "description": "Reflektierte Cross-Site-Scripting (XSS) Schwachstelle gefunden...",
      "exploitation": "Um diese Schwachstelle auszunutzen, senden Sie den Parameter 'q70' mit dem Payload..."
    }
  ]
}
```

### HTML-Report

Der HTML-Report enthält:
- Zusammenfassung des Scans
- Detaillierte Informationen zu jeder gefundenen Schwachstelle
- Screenshots der gefundenen Schwachstellen
- Exploitation-Anleitungen
- Empfehlungen zur Behebung

## Schweregrade

Das Framework klassifiziert gefundene Schwachstellen nach folgenden Schweregraden:

- **LOW**: Geringe Auswirkung, begrenzte Ausnutzbarkeit
- **MEDIUM**: Moderate Auswirkung, erfordert bestimmte Bedingungen
- **HIGH**: Hohe Auswirkung, leicht auszunutzen
- **CRITICAL**: Kritische Auswirkung, kann zu vollständiger Kompromittierung führen

## Tipps und Best Practices

1. **Beginnen Sie mit geringer Tiefe**: Starten Sie mit `-d 1` und erhöhen Sie schrittweise, um die Scan-Zeit zu optimieren.

2. **Authentifizierte Scans**: Verwenden Sie `--cookies` für authentifizierte Bereiche der Anwendung.

3. **Vermeiden Sie DoS**: Begrenzen Sie die Anzahl der Threads und setzen Sie angemessene Timeouts.

4. **Validieren Sie Ergebnisse**: Überprüfen Sie gefundene Schwachstellen manuell mit den Debug-URLs.

5. **Verantwortungsvolle Offenlegung**: Melden Sie gefundene Schwachstellen verantwortungsvoll an die Betreiber der Website.

## Fehlerbehebung

### Häufige Probleme

1. **Keine Schwachstellen gefunden**: Erhöhen Sie die Scan-Tiefe oder verwenden Sie `--use-ml` für bessere Erkennung.

2. **Timeout-Fehler**: Erhöhen Sie den Timeout-Wert mit `--timeout`.

3. **Falsch-positive Ergebnisse**: Überprüfen Sie die Ergebnisse manuell mit den Debug-URLs.

4. **Speicherprobleme**: Reduzieren Sie die Anzahl der Threads oder die Scan-Tiefe.

## Entwicklung und Erweiterung

Das Framework ist modular aufgebaut und kann leicht erweitert werden:

- **Neue Payloads**: Fügen Sie neue Payloads in `payloads.py` hinzu.
- **Neue Erkennungsmethoden**: Erweitern Sie `xss_validator.py`.
- **Neue Integrationen**: Fügen Sie neue Integrationen im `integrations`-Verzeichnis hinzu.
- **Benutzerdefinierte Berichtsvorlagen**: Erstellen Sie eigene Vorlagen im `templates`-Verzeichnis.

## Lizenz

MIT-Lizenz
