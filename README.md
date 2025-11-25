# Xss-Master
# xss-master 🔥  
### Automated Reflection-Based XSS Analyzer  
**Built for Pentesters. By TheCyberAryan.**

`xss-master` is a powerful, no-noise, reflection-based XSS analysis tool that works directly from:

- Raw **Burp Suite HTTP requests**
- **Plain URLs**
- **URLs + POST bodies**
- **Multiple requests at once**

It automatically extracts every parameter, fuzzes it with payloads, detects reflection, identifies the reflection context, and generates a clean JSON report — all while staying safe and non-exploitative.

---

## 🚀 Features

### ✔ Paste ANY of these:
- Full raw Burp requests (GET/POST/HTTP/2)
- Single URLs
- Multiple URLs
- URL + body
- JSON endpoints
- Multipart form uploads

### ✔ Auto-detect everything:
- URL  
- Method (GET/POST)  
- Query params  
- Form params  
- JSON params  
- Multipart params  
- Hidden fields  

### ✔ Fuzz ALL parameters
Not just “search-like” ones — **every parameter** is tested.

### ✔ Detects reflection in:
- Raw HTML  
- Attribute context  
- JavaScript string context  
- `<script>` blocks  
- URL-encoded  
- Double URL-encoded  
- Lowercased reflections  

### ✔ Category suggestions:
The tool tells you the type of payload that fits the reflection context.

Example:
- **JS context → JS breaker payloads**
- **Attribute context → onerror/onfocus payloads**
- **HTML context → basic payloads**

### ✔ Output is clean and useful
Only reflective payloads are printed.

No clutter.  
No giant logs.  
No useless text.

### ✔ Saves JSON report
All reflections → `xss_report.json`

---

## 🧩 Usage

### 1. Install dependency

```bash
pip install httpx --break-system-packages
