# CyberShield — Advanced Password Security Analyzer

A professional-grade, cyberpunk-themed password security analyzer built with **Flask** (Python) and vanilla **JavaScript**.

---

## 📁 Project Structure

```
cybershield/
├── app.py                  # Flask backend & API routes
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # Main UI (Jinja2 template)
├── static/
│   ├── css/
│   │   └── style.css       # Cyberpunk theme & layout
│   └── js/
│       └── main.js         # Frontend logic & API calls
└── utils/
    ├── __init__.py
    └── analyzer.py         # Password analysis engine
```

---

##  Installation & Setup

### 1. Prerequisites
- Python 3.10 or higher
- pip

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the App

```bash
python app.py
```

### 4. Open in Browser

```
http://127.0.0.1:5000
```

> **Why do I see 2 IPs in the terminal?**
> Flask shows `127.0.0.1:5000` (localhost) and your machine's local network IP (e.g. `192.168.x.x:5000`).
> Both work — use `127.0.0.1:5000` to open in your browser. The second IP lets other devices on your network access the app.

---

## 🚀 Features

| Feature | Description |
|---|---|
| **Live Strength Bar** | Updates as you type |
| **Security Score** | 0–100 score with animated ring |
| **Entropy Analysis** | Calculates bits of entropy |
| **Crack Time Estimate** | Based on 100B guesses/sec GPU benchmark |
| **Dictionary Risk** | Checks against common passwords + leet-speak |
| **Pattern Detection** | Repeated chars, keyboard walks, sequential patterns |
| **Security Rules** | 8 rules checked (length, charset, spaces, diversity) |
| **Recommendations** | Actionable tips to improve your password |
| **Password Generator** | Cryptographically secure random passwords |
| **Copy to Clipboard** | One-click copy for generated passwords |

---

## 🔌 API Endpoints

### `POST /api/analyze`
Analyze a password and get full security metrics.

**Request:**
```json
{ "password": "MyP@ssw0rd!" }
```

**Response:**
```json
{
  "score": 75,
  "strength": "Strong",
  "strength_color": "#00d97e",
  "password_length": 11,
  "threat": {
    "entropy_bits": 72.3,
    "entropy_level": "High",
    "crack_time_display": "Centuries",
    "dictionary_risk": false,
    "repeated_pattern": false,
    "sequential_chars": false,
    "keyboard_walk": false
  },
  "rules": {
    "min_length": true,
    "max_length": true,
    "has_upper": true,
    "has_lower": true,
    "has_digit": true,
    "has_special": true,
    "no_spaces": true,
    "diversity": true
  },
  "recommendations": ["Password meets all security standards. Excellent work!"],
  "passed_rules": 8,
  "total_rules": 8
}
```

---

### `GET /api/generate?length=20`
Generate a cryptographically secure strong password.

**Query Params:**

| Param | Default | Range | Description |
|---|---|---|---|
| `length` | `20` | `12–64` | Length of generated password |

**Response:**
```json
{
  "password": "Xk#9mQ!vRz@2Lp$eTnW8",
  "analysis": { ...same as /api/analyze... }
}
```

---

## 🔐 Scoring System

| Score | Strength | Color |
|---|---|---|
| 0 | No Input | Gray |
| 1–20 | Very Weak | 🔴 Red |
| 21–40 | Weak | 🟠 Orange |
| 41–60 | Moderate | 🟡 Yellow |
| 61–80 | Strong | 🟢 Green |
| 81–100 | Very Strong | 💎 Teal |

**Score is calculated from:**
- ✅ Length bonuses (8, 12, 16, 20+ chars)
- ✅ Character variety (upper, lower, digit, special)
- ✅ Entropy (40+ bits, 60+ bits)
- ✅ Character type diversity (3+ or 4 types)
- ❌ Penalties for spaces, repeated patterns, sequential chars, keyboard walks, dictionary matches

---

## 🛡️ Security Rules Checked

| Rule | Requirement |
|---|---|
| Min Length | At least 8 characters |
| Max Length | No more than 128 characters |
| Uppercase | At least one A–Z |
| Lowercase | At least one a–z |
| Digit | At least one 0–9 |
| Special Char | At least one `!@#$%^&*` etc. |
| No Spaces | Spaces are not allowed |
| Diversity | At least 3 character types used |

---

## 🧠 How Entropy is Calculated

```
entropy = password_length × log₂(charset_size)
```

| Charset | Size |
|---|---|
| Lowercase (a–z) | 26 |
| Uppercase (A–Z) | 26 |
| Digits (0–9) | 10 |
| Special chars | 32 |

Crack time is estimated at **100 billion guesses/second** (high-end GPU cluster).

---

##  Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3 + Flask |
| Frontend | HTML5, CSS3, Vanilla JS |
| Fonts | Orbitron, Share Tech Mono, Rajdhani (Google Fonts) |
| Crypto | Python `secrets` module |
| Styling | CSS custom properties, animations |

