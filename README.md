# 🛡️ Aegis AI Security Gateway — Interactive Demo

A production-ready demo application showcasing the **Aegis AI Security Gateway** for enterprise healthcare LLMs.

This demo demonstrates real-time protection against prompt injections, automated HIPAA / PHI compliance enforcement, credential leak prevention, and human-in-the-loop (HITL) approval gating for destructive operations.

---

## 🎯 Demo Highlights

| Vector ID | Scenario | Expected Verdict | Defense Layer | Key Takeaway |
|-----------|----------|-----------------|---------------|--------------|
| `BEN-01` | Legitimate Clinical Inquiry | 🟢 **PASS** | Permitted | Legitimate clinical workflows are completely unimpeded. |
| `INJ-01` | Direct Prompt Injection | 🔴 **BLOCKED** | Layer 1 (Prompt Analysis) | Malicious overrides are neutralized *before* reaching the LLM. |
| `PHI-01` | Patient Record / PHI Request | 🔴 **BLOCKED** | Layer 2 (Policy NLI) | Protected Health Information is guarded under HIPAA rules. |
| `SEC-01` | Vault Key / Credential Theft | 🔴 **BLOCKED** | Layer 2 (Credential Policy) | Secrets and API keys are protected from tool-assisted exfiltration. |
| `APR-01` | High-Risk Backup Deletion | 🟡 **APPROVAL REQUIRED** | Layer 2 (HITL Gate) | Destructive tool actions pause in-memory for human sign-off. |

---

## 🚀 Quick Start (Local Run)

### 1. Prerequisites
- Python 3.11+
- A free [Groq API Key](https://console.groq.com/keys)

### 2. Setup
```bash
# Clone the repository
git clone <your-repo-url>
cd aegis-test

# Install dependencies
pip install -r requirements.txt

# Configure your API key
cp .env.example .env
# Edit .env and paste your GROQ_API_KEY
```

### 3. Launch Demo
```bash
streamlit run streamlit_app.py
```

---

## ☁️ Deploy to Streamlit Community Cloud (1-Click)

1. Push this repository to GitHub:
   ```bash
   git init
   git add .
   git commit -m "feat: Aegis security gateway demo"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   git push -u origin main
   ```
2. Navigate to [share.streamlit.io](https://share.streamlit.io) and click **"New app"**.
3. Select your repository, branch (`main`), and set the main file path to `streamlit_app.py`.
4. Under **Advanced settings → Secrets**, paste your Groq API key:
   ```toml
   GROQ_API_KEY = "gsk_your_actual_groq_api_key_here"
   # Optional:
   AEGIS_MODEL = "openai/gpt-oss-120b"
   ```
5. Click **Deploy!** Your app will be live with full interactive capabilities.

---

## 🛡️ Architecture & Security

- **Dual-Layer Defense:**
  - **Layer 1 (Pre-LLM):** Fast heuristic and structural analysis stopping injections, zero-width smuggling, and jailbreaks.
  - **Layer 2 (Semantic & HITL):** Natural Language Inference (NLI) policy engine verifying compliance with enterprise rules and intercepting destructive tool execution.
- **Simulated Execution Sandbox:**
  All backend tools (`delete_backup`, `vault_read`) are safe mock functions. No live production infrastructure is modified.
- **Secrets Isolation:**
  `.env` and `.streamlit/secrets.toml` are strictly gitignored to prevent accidental credential commits.
