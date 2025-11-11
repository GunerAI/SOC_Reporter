# PRD — SOC Executive Summary Assistant (Prompt + Agent Flow)

**Scope:** Ready models + prompt engineering + tool-calling. **No fine-tuning (for now).**  
**Primary Outputs:** Policy-compliant Markdown report + optional Event Timeline + HTML preview.

---

## 1) Purpose & Outcomes

**What**  
Turn structured SOC investigation inputs (alert/entity details, queries, logs, IoCs, screenshots, actions) into a safe, consistent, executive-readable report with collapsible raw evidence, compact tables, and an auto Event Timeline. Analysts can lightly edit the Markdown and preview the final display.

**Why**  
Analysts lose time balancing readability vs technical fidelity, formatting evidence, and sanitizing risky indicators. Prompt-first automation with guardrails shortens drafting and increases consistency.

**Done looks like**  
- Deterministic, policy-compliant Markdown + Timeline + HTML preview  
- Passes safety (defang) and lint gates  
- Requires < 5% edits

**How (now)**  
Prompt engineering + tool-calling only (no SFT).

---

## 2) User Interface (4 Main Parts)

### Part 1 — Analyst Input (Data Capture)

**Purpose**  
Normalize all inputs once so generation is reliable and repeatable.

**Behavior (capture)**  
- **Alert overview:** ticket_id, source, alert_title, observed_at (ISO), severity, quick what/when/where/how/who  
- **User/Entity:** user/device IDs, names, emails, titles, accounts, hostnames  
- **Search queries:** Splunk / Sentinel / Defender / KQL / custom  
- **Raw logs:** Firewall, IDS/IPS, Proxy, Auth, VPN, Network, DHCP, Web Requests, Email; Entra Audit/Sign-in; Device/OS/Email/CloudApps events  
- **IoCs & payloads:** domains, IPs, URLs, hashes, registry changes, URIs, scripts/commands (PowerShell/Bash/Python), code samples  
- **OSINT/Sandbox:** reputation results, detonation notes, screenshots (file/URL + caption)  
- **Actions taken:** list with timestamps  
- **Leadership summary / Next steps / Lessons learned:** optional drafts  
- **UX:** multi-section form, autosave, drag-drop screenshots, validators (required fields, ISO time parsing)

**Reasoning**  
Upfront structure reduces downstream parsing ambiguity and keeps prompts short/stable.

---

### Part 2 — AI Transform (Markdown Executive Summary)

**Purpose**  
Convert inputs into a structured, editable Markdown report.

**Important constraint — “as-is” fields**  
Queries, raw logs, and alert/user/entity fields must be preserved verbatim (no paraphrasing). Only allowed changes:  
1. Defang risky items; 2) Redact secrets if policy demands (future toggle); 3) Wrap/format (collapsibles, code fences, headings).  
Narrative sections (technical summary, leadership summary) may be rewritten for clarity.

**Behavior (what the agent produces)**  
- **Alert Overview** (as-is fields normalized to tidy bullets)  
- **Executive Summary (Technical)** — concise narrative for SOC/IR  
- **Evidence (subsections)**  
  - **Search query** (collapsible, fenced with correct language tag: splunk, kusto, etc.)  
  - **Raw logs** (collapsible, syntax-highlighted)  
  - **Logs as tables** (compact Markdown tables derived from representative logs)  
  - **User/Entity details** (as-is, tidy bullets)  
  - **Defanged IoCs & payloads** (domains, IPs, URLs, hashes, registry keys, commands)  
  - **OSINT/Sandbox** (reputation results, detonation notes, screenshots + captions)  
- **Actions Taken** — chronological bullets with timestamps  
- **Lessons Learned / Next Steps** — actionable bullets (start with verbs)  
- **Executive Summary for Leadership** — plain, non-technical paragraph

**Formatting rules (must)**  
- Bold headings; stable H1–H3 hierarchy  
- Code fences with language tags (`powershell`, `bash`, `kusto`, `splunk`, `json`)  
- Long artifacts inside `<details><summary>…</summary>…</details>`  
- Defang all risky text (URLs, domains, IPs, emails, commands)  
- Preserve literal values inside fences; short captions under screenshots  
- Clarity via syntax highlighting by language tag and structure (headings, lists, tables, collapsibles) 
- Executive sections stay plain English; dense artifacts live in Evidence

**Editability**  
Monospace Markdown editor + “Re-generate w/ changes” that merges deltas and preserves user edits (minimal diff).

**Reasoning**  
Clear boundary: narrative may change; evidence must not (beyond defang/wrap). Safety and auditability are preserved.

---

### Part 3 — Display Preview (Rendered View)

**Purpose**  
Show exactly how it will look in Confluence/SharePoint/HTML.

**Behavior**  
Read-only render of current Markdown; functional collapsibles; language-highlighted fences; responsive tables; Copy Markdown/HTML buttons.

**Reasoning**  
Eliminates “surprise after paste” and speeds review/approval.

---

### Part 4 — Event Timeline (Auto-Generated)

**Purpose**  
Accurate chronology to support traceability and post-mortems.

**Behavior**  
- Parse timestamps from logs, EDR events, actions, and any time-stamped notes  
- Normalize to org timezone; optionally display multiple timezones (US/EU/IN) for distributed teams  
- Sort ascending; deduplicate near-identical events; phase-tag: Initial Alert, Access, Command, Network, Containment, Recovery, Other  
- Export Markdown bullets + JSON/CSV

**Reasoning**  
Multi-TZ is a common cross-regional need; dedupe keeps timelines readable.
