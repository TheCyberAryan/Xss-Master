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

### 1️⃣ Install dependency

```bash
pip install httpx --break-system-packages
```

## 📁 Payload Setup

Create a file named `payloads.txt`:

```
"><img src=x onerror=alert(1)>
"></script><svg/onload=alert(1)>
"><svg/onload=alert(document.cookie)>
";alert(1);// 
" autofocus onfocus=alert(1) x="
```

## 🚀 Running the Tool

```bash
python3 xss_scanner_v6.py
```

You will see:

```
Paste one or more raw Burp requests OR URLs, then press CTRL+D:
```

## 🎯 Supported Input Formats

### ✔ Single URL
```
https://example.com/search?keyword=hello
```

### ✔ Multiple URLs
```
https://example.com/search?q=hello
https://example.com/products?id=12
https://example.com/filter?type=shoes
```

### ✔ Full Burp Request
```
POST /search-products.php HTTP/2
Host: www.pickaleafproducts.com
Content-Type: application/x-www-form-urlencoded

keyword=aryan
```

## ⌨️ Finish Input

- CTRL + D → Linux/macOS  
- CTRL + Z then Enter → Windows

## 🧪 Example Output

```
--- Request #1: GET https://example.com/search?q=hello ---
[✔] R1 param=q loc=query
     payload: "><img src=x onerror=alert(1)>
     ctx: raw, attr_context
     hint: Attribute context (use " onxxx= payloads)

[+] JSON report saved to xss_report.json
```

## 📄 JSON Report Example

```json
{Example 
  "requests": [
    {
      "id": 1,
      "method": "GET",
      "url": "https://example.com/search?q=hello",
      "params": [
        {
          "name": "q",
          "location": "query",
          "reflections": [
            {
              "payload": "\"><img src=x onerror=alert(1)>",
              "contexts": ["raw", "attr_context"],
              "category": "Attribute context"
            }
          ]
        }
      ]
    }
  ]
}
```
