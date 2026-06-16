"""
CyberShield Password Analysis Engine
Professional-grade password strength analysis with entropy, crack-time
estimation, pattern detection, and actionable recommendations.
"""

import math
import re
import secrets
import string
from dataclasses import dataclass, asdict
from typing import Optional


# ── COMMON / DICTIONARY PASSWORDS ─────────────────────────────────────────
COMMON_PASSWORDS: set[str] = {
    "password", "123456", "password1", "qwerty", "abc123", "letmein",
    "monkey", "master", "dragon", "admin", "welcome", "login", "pass",
    "test", "iloveyou", "sunshine", "princess", "shadow", "superman",
    "michael", "qwerty123", "111111", "123123", "1234", "12345",
    "123456789", "000000", "password123", "soccer", "baseball", "football",
    "basketball", "hockey", "batman", "trustno1", "charlie", "donald",
    "jessica", "jennifer", "hunter", "joshua", "george", "amanda",
    "access", "mustang", "cookie", "andrew", "robert", "thomas",
    "samsung", "tigger", "1234567", "12345678", "1234567890",
    "q1w2e3r4", "passw0rd", "p@ssword", "p@ssw0rd",
}

# Sequential keyboard rows / alphabet
SEQUENTIAL_PATTERNS = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "qazwsxedcrfvtgbyhnujmikolp",   # columns
]

# Crack speed: 100 billion guesses/second (high-end GPU cluster, bcrypt excluded)
GUESSES_PER_SECOND = 1e11


# ── DATA CLASSES ───────────────────────────────────────────────────────────
@dataclass
class CharsetInfo:
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_special: bool
    size: int


@dataclass
class ThreatInfo:
    entropy_bits: float
    entropy_level: str          # Low / Medium / High / Very High
    crack_time_seconds: float
    crack_time_display: str
    dictionary_risk: bool
    repeated_pattern: bool
    sequential_chars: bool
    keyboard_walk: bool


@dataclass
class RulesCheck:
    min_length: bool            # >= 8
    max_length: bool            # <= 128
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool
    no_spaces: bool
    diversity: bool             # at least 3 char types


@dataclass
class PasswordAnalysis:
    password_length: int
    score: int                  # 0-100
    strength: str               # Very Weak / Weak / Moderate / Strong / Very Strong
    strength_color: str         # hex colour for UI
    charset: CharsetInfo
    threat: ThreatInfo
    rules: RulesCheck
    recommendations: list[str]
    passed_rules: int           # count of passed rules
    total_rules: int


# ── HELPERS ───────────────────────────────────────────────────────────────
def _charset_info(pw: str) -> CharsetInfo:
    has_lower   = bool(re.search(r"[a-z]", pw))
    has_upper   = bool(re.search(r"[A-Z]", pw))
    has_digit   = bool(re.search(r"[0-9]", pw))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", pw))
    size = (
        (26 if has_lower   else 0) +
        (26 if has_upper   else 0) +
        (10 if has_digit   else 0) +
        (32 if has_special else 0)
    )
    return CharsetInfo(has_lower, has_upper, has_digit, has_special, size)


def _entropy(pw: str, charset_size: int) -> float:
    if not pw or charset_size == 0:
        return 0.0
    return round(len(pw) * math.log2(charset_size), 2)


def _crack_time_display(seconds: float) -> str:
    if seconds < 1e-6:
        return "Instant"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    if seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    if seconds < 2_592_000:
        return f"{seconds/86400:.1f} days"
    if seconds < 31_536_000:
        return f"{seconds/2_592_000:.1f} months"
    if seconds < 31_536_000 * 1_000:
        return f"{seconds/31_536_000:.0f} years"
    if seconds < 31_536_000 * 1_000_000:
        return "Centuries"
    return "Heat death of universe"


def _has_repeated_pattern(pw: str) -> bool:
    # 3+ consecutive identical chars
    if re.search(r"(.)\1{2,}", pw):
        return True
    # Repeated substring (length 2+) appearing 2+ times consecutively
    if re.search(r"(.{2,})\1{2,}", pw):
        return True
    return False


def _has_sequential(pw: str) -> bool:
    lower = pw.lower()
    for seq in SEQUENTIAL_PATTERNS:
        for i in range(len(seq) - 2):
            chunk = seq[i:i+3]
            rev   = chunk[::-1]
            if chunk in lower or rev in lower:
                return True
    return False


def _has_keyboard_walk(pw: str) -> bool:
    """
    Detect keyboard-walk patterns beyond simple rows —
    e.g. qwert, zxcvb, asdfg.
    """
    lower = pw.lower()
    walks = [
        "qwert", "werty", "ertyu", "rtyui", "tyuio", "yuiop",
        "asdfg", "sdfgh", "dfghj", "fghjk", "ghjkl",
        "zxcvb", "xcvbn", "cvbnm",
    ]
    for w in walks:
        if w in lower or w[::-1] in lower:
            return True
    return False


def _dictionary_risk(pw: str) -> bool:
    lower = pw.lower()
    # Exact match (case-insensitive)
    if lower in COMMON_PASSWORDS:
        return True
    # Strip non-alpha and check
    stripped = re.sub(r"[^a-z]", "", lower)
    if stripped in COMMON_PASSWORDS:
        return True
    # Common leet-speak substitutions
    leet_map = str.maketrans("@3!10$5", "aeilos5")
    de_leet = lower.translate(leet_map)
    if de_leet in COMMON_PASSWORDS or re.sub(r"[^a-z]", "", de_leet) in COMMON_PASSWORDS:
        return True
    return False


def _rules_check(pw: str, cs: CharsetInfo) -> RulesCheck:
    return RulesCheck(
        min_length  = len(pw) >= 8,
        max_length  = len(pw) <= 128,
        has_upper   = cs.has_upper,
        has_lower   = cs.has_lower,
        has_digit   = cs.has_digit,
        has_special = cs.has_special,
        no_spaces   = " " not in pw,
        diversity   = sum([cs.has_lower, cs.has_upper, cs.has_digit, cs.has_special]) >= 3,
    )


def _score(pw: str, cs: CharsetInfo, threat: ThreatInfo, rules: RulesCheck) -> int:
    s = 0
    n = len(pw)

    # ── Length bonus (max 30) ──────────────────────
    if n >= 8:   s += 10
    if n >= 12:  s += 8
    if n >= 16:  s += 7
    if n >= 20:  s += 5

    # ── Character variety (max 40) ─────────────────
    if cs.has_lower:   s += 10
    if cs.has_upper:   s += 10
    if cs.has_digit:   s += 10
    if cs.has_special: s += 10

    # ── Entropy bonus (max 20) ─────────────────────
    if threat.entropy_bits >= 40: s += 10
    if threat.entropy_bits >= 60: s += 10

    # ── Diversity bonus (max 10) ───────────────────
    types = sum([cs.has_lower, cs.has_upper, cs.has_digit, cs.has_special])
    if types >= 3: s += 5
    if types >= 4: s += 5

    # ── Deductions ────────────────────────────────
    if not rules.no_spaces:       s -= 10
    if threat.repeated_pattern:   s -= 15
    if threat.sequential_chars:   s -= 10
    if threat.keyboard_walk:      s -= 8
    if threat.dictionary_risk:    s -= 25
    if not rules.min_length:      s = min(s, 20)
    if not rules.max_length:      s -= 30

    return max(0, min(100, s))


def _strength_label(score: int) -> tuple[str, str]:
    """Returns (label, hex_colour)."""
    if score == 0:   return ("No Input",    "#6aada3")
    if score <= 20:  return ("Very Weak",   "#ff3d5a")
    if score <= 40:  return ("Weak",        "#ff6b35")
    if score <= 60:  return ("Moderate",    "#ffe100")
    if score <= 80:  return ("Strong",      "#00d97e")
    return               ("Very Strong", "#00e5c8")


def _recommendations(pw: str, cs: CharsetInfo, threat: ThreatInfo, rules: RulesCheck) -> list[str]:
    tips: list[str] = []
    if not rules.min_length:
        tips.append("Increase length to at least 8 characters.")
    if not rules.has_upper:
        tips.append("Add uppercase letters (A–Z).")
    if not rules.has_lower:
        tips.append("Add lowercase letters (a–z).")
    if not rules.has_digit:
        tips.append("Include at least one number (0–9).")
    if not rules.has_special:
        tips.append("Add a special character (e.g. !@#$%^&*).")
    if not rules.no_spaces:
        tips.append("Remove spaces — they are rejected by many systems.")
    if threat.repeated_pattern:
        tips.append("Avoid repeated characters or patterns (e.g. 'aaa', 'ababab').")
    if threat.sequential_chars:
        tips.append("Avoid sequential characters (e.g. '123', 'abc').")
    if threat.keyboard_walk:
        tips.append("Avoid keyboard-walk patterns (e.g. 'qwerty', 'asdfg').")
    if threat.dictionary_risk:
        tips.append("Your password resembles a common/dictionary password. Choose something unique.")
    if len(pw) >= 8 and len(pw) < 16 and not tips:
        tips.append("Consider using 16+ characters for significantly higher entropy.")
    if not tips:
        tips.append("Password meets all security standards. Excellent work!")
    return tips


# ── PUBLIC API ─────────────────────────────────────────────────────────────
def analyze_password(password: str) -> dict:
    """
    Analyse a password and return a serialisable dict with all metrics.
    """
    if not password:
        # Return zeroed structure
        empty = PasswordAnalysis(
            password_length=0,
            score=0,
            strength="No Input",
            strength_color="#6aada3",
            charset=CharsetInfo(False, False, False, False, 0),
            threat=ThreatInfo(0.0, "Low", 0.0, "Instant", False, False, False, False),
            rules=RulesCheck(False, True, False, False, False, False, True, False),
            recommendations=["Enter a password to receive a security assessment."],
            passed_rules=0,
            total_rules=8,
        )
        return asdict(empty)

    cs      = _charset_info(password)
    entropy = _entropy(password, cs.size)
    crack_s = (2 ** entropy) / GUESSES_PER_SECOND if entropy > 0 else 0.0

    if entropy < 28:       ent_level = "Low"
    elif entropy < 50:     ent_level = "Medium"
    elif entropy < 72:     ent_level = "High"
    else:                  ent_level = "Very High"

    threat = ThreatInfo(
        entropy_bits      = entropy,
        entropy_level     = ent_level,
        crack_time_seconds= crack_s,
        crack_time_display= _crack_time_display(crack_s),
        dictionary_risk   = _dictionary_risk(password),
        repeated_pattern  = _has_repeated_pattern(password),
        sequential_chars  = _has_sequential(password),
        keyboard_walk     = _has_keyboard_walk(password),
    )

    rules  = _rules_check(password, cs)
    score  = _score(password, cs, threat, rules)
    label, color = _strength_label(score)
    recs   = _recommendations(password, cs, threat, rules)

    rules_dict = asdict(rules)
    passed = sum(1 for v in rules_dict.values() if v)

    result = PasswordAnalysis(
        password_length = len(password),
        score           = score,
        strength        = label,
        strength_color  = color,
        charset         = cs,
        threat          = threat,
        rules           = rules,
        recommendations = recs,
        passed_rules    = passed,
        total_rules     = len(rules_dict),
    )
    return asdict(result)


def generate_strong_password(length: int = 20) -> str:
    """
    Generate a cryptographically random password guaranteed to satisfy
    all CyberShield security rules.
    """
    upper   = string.ascii_uppercase
    lower   = string.ascii_lowercase
    digits  = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Guarantee at least one from each category
    mandatory = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    pool = upper + lower + digits + special
    rest = [secrets.choice(pool) for _ in range(length - len(mandatory))]

    chars = mandatory + rest
    # Fisher-Yates shuffle using secrets
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)