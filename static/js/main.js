/* CyberShield – main.js */
(function () {
  "use strict";

  const $ = id => document.getElementById(id);

  // Elements
  const pwInput      = $("pwInput");
  const toggleVis    = $("toggleVis");
  const scoreBadge   = $("scoreBadge");
  const strengthBar  = $("strengthBar");
  const strengthLabel= $("strengthLabel");
  const strengthDesc = $("strengthDesc");
  const btnAnalyze   = $("btnAnalyze");
  const btnGenerate  = $("btnGenerate");
  const loading      = $("loading");
  const ringFill     = $("ringFill");
  const ringScore    = $("ringScore");
  const strengthBadge= $("strengthBadge");
  const recList      = $("recList");
  const rulesSummary = $("rulesSummary");
  const generatedWrap= $("generatedWrap");
  const generatedText= $("generatedText");
  const btnCopy      = $("btnCopy");

  const CIRCUMFERENCE = 339.3;

  // Rule IDs in both panels
  const RULE_KEYS = ["min_length","max_length","has_upper","has_lower","has_digit","has_special","no_spaces","diversity"];
  const QUICK_KEYS= ["min_length","has_upper","has_lower","has_digit","has_special","no_spaces","diversity"];

  // Threat element IDs
  const threatMap = {
    entropy_bits:      "tEntropy",
    crack_time_display:"tCrack",
    dictionary_risk:   "tDict",
    repeated_pattern:  "tRepeat",
    keyboard_walk:     "tKeyboard",
    sequential_chars:  "tSeq",
  };

  /* ── Toggle visibility ───────────────────────── */
  toggleVis.addEventListener("click", () => {
    const isText = pwInput.type === "text";
    pwInput.type = isText ? "password" : "text";
    toggleVis.textContent = isText ? "👁" : "🙈";
  });

  /* ── Live strength bar while typing ─────────── */
  pwInput.addEventListener("input", () => {
    const len = pwInput.value.length;
    const rough = Math.min(100, len * 5);
    strengthBar.style.width = rough + "%";
    strengthBar.style.background = rough < 30 ? "var(--red)" : rough < 60 ? "var(--yellow)" : "var(--teal)";
    strengthLabel.textContent = len ? "TYPING…" : "AWAITING INPUT";
    strengthDesc.textContent  = len ? `${len} characters` : "type a password above";
    scoreBadge.textContent = "— / 100";
  });

  /* ── Analyze ─────────────────────────────────── */
  btnAnalyze.addEventListener("click", () => analyzePassword());
  pwInput.addEventListener("keydown", e => { if (e.key === "Enter") analyzePassword(); });

  async function analyzePassword() {
    const pw = pwInput.value;
    if (!pw) { alert("Please enter a password first."); return; }

    setLoading(true);
    try {
      const res  = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw }),
      });
      const data = await res.json();
      renderAnalysis(data);
    } catch (err) {
      console.error(err);
      alert("Error contacting server. Is Flask running?");
    } finally {
      setLoading(false);
    }
  }

  /* ── Generate ────────────────────────────────── */
  btnGenerate.addEventListener("click", async () => {
    setLoading(true);
    try {
      const res  = await fetch("/api/generate");
      const data = await res.json();
      pwInput.value = data.password;
      generatedText.textContent = data.password;
      generatedWrap.style.display = "block";
      renderAnalysis(data.analysis);
    } catch (err) {
      console.error(err);
      alert("Error contacting server.");
    } finally {
      setLoading(false);
    }
  });

  /* ── Copy ────────────────────────────────────── */
  btnCopy.addEventListener("click", () => {
    navigator.clipboard.writeText(generatedText.textContent).then(() => {
      btnCopy.textContent = "✓ Copied!";
      btnCopy.classList.add("copied");
      setTimeout(() => { btnCopy.textContent = "⎘ Copy"; btnCopy.classList.remove("copied"); }, 2000);
    });
  });

  /* ── Render analysis result ──────────────────── */
  function renderAnalysis(d) {
    const score  = d.score;
    const color  = d.strength_color;

    // Score badge + bar
    scoreBadge.textContent = `${score} / 100`;
    strengthBar.style.width      = score + "%";
    strengthBar.style.background = color;
    strengthLabel.textContent    = d.strength.toUpperCase();
    strengthLabel.style.color    = color;
    strengthDesc.textContent     = `${d.password_length} characters`;

    // Ring
    const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    ringFill.style.strokeDashoffset = offset;
    ringFill.style.stroke           = color;
    ringScore.textContent           = score;
    ringScore.style.color           = color;
    strengthBadge.textContent       = d.strength.toUpperCase();
    strengthBadge.style.borderColor = color;
    strengthBadge.style.color       = color;

    // Threat panel
    const t = d.threat;
    $("tEntropy").textContent = `${t.entropy_bits} bits (${t.entropy_level})`;
    $("tCrack").textContent   = t.crack_time_display;
    $("tDict").textContent    = t.dictionary_risk    ? "⚠ HIGH RISK"  : "✓ Low Risk";
    $("tRepeat").textContent  = t.repeated_pattern   ? "⚠ Detected"   : "✓ None";
    $("tKeyboard").textContent= t.keyboard_walk      ? "⚠ Detected"   : "✓ None";
    $("tSeq").textContent     = t.sequential_chars   ? "⚠ Detected"   : "✓ None";

    // Entropy bar (max ~128 bits)
    $("entropyBar").style.width = Math.min(100, (t.entropy_bits / 128) * 100) + "%";

    // Color threat values
    ["tDict","tRepeat","tKeyboard","tSeq"].forEach(id => {
      const el = $(id);
      el.style.color = el.textContent.startsWith("⚠") ? "var(--red)" : "var(--teal)";
    });

    // Rules panels
    const rules = d.rules;
    RULE_KEYS.forEach(key => {
      const el = $(`r-${key}`);
      if (!el) return;
      el.classList.toggle("pass", !!rules[key]);
      el.classList.toggle("fail", !rules[key]);
    });
    QUICK_KEYS.forEach(key => {
      const el = $(`q-${key}`);
      if (!el) return;
      el.classList.toggle("pass", !!rules[key]);
      el.classList.toggle("fail", !rules[key]);
    });
    rulesSummary.textContent = `${d.passed_rules} / ${d.total_rules} rules passed`;

    // Recommendations
    recList.innerHTML = d.recommendations.map(r => {
      const ok = r.toLowerCase().includes("excellent") || r.toLowerCase().includes("meets all");
      return `<li class="${ok ? "success" : ""}">${r}</li>`;
    }).join("");
  }

  function setLoading(on) {
    loading.classList.toggle("active", on);
    btnAnalyze.disabled  = on;
    btnGenerate.disabled = on;
  }
})();
