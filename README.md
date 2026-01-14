# CyberArk CPM Plugins & Utilities

This repository contains **CyberArk CPM / TPC plugins and supporting tools** developed for
**general, reusable CyberArk use cases** (for example: SaaS integrations, API-based account
reconciliation, and non-traditional password rotation workflows).

The scripts and utilities in this repository are designed to be:
- **Environment-agnostic**
- **Vendor-API driven**
- **Reusable across organizations**
- Compatible with **CyberArk CPM / TPC execution models**

---

## Scope & Intent

- These tools are intended to demonstrate **how CyberArk CPM can integrate with modern APIs**
  (OAuth, certificate-based auth, DPoP, etc.).
- They are **not tailored to any specific organization**.
- They do **not** contain:
  - environment-specific assumptions
  - internal configurations
  - embedded secrets
  - proprietary logic

All development and testing was performed using **generic / fresh tenants** and publicly
documented APIs.

---

## ⚠️ Disclaimer

This project is **experimental and not production-ready**.

The software is provided **as-is**, without warranty of any kind.
Use at your own risk.

The author assumes **no responsibility or liability** for:
- outages
- security incidents
- data loss
- policy violations
- misconfiguration
- production impact

Before deploying in a production CyberArk environment:
- review the code
- validate permissions and scope
- test thoroughly in a non-production environment

---

## Licensing

This project is licensed under the **MIT License**.

You are free to:
- use the code internally or commercially
- modify it
- redistribute it
- adapt it to your own CyberArk platforms

There is **no warranty** and **no obligation of support**.

See the [`LICENSE`](LICENSE) file for full license text.

---

## Internal Adoption Note (For Organizations)

If you intend to adopt any of these tools internally:

- Treat this repository as **reference or integration scaffolding**
- Perform your own:
  - security review
  - code review
  - operational testing
- Assign ownership to an internal team if used in production

These tools are best suited for:
- proof-of-concept integrations
- extending CPM into API-only platforms
- starting points for internal plugins

---

## PowerShell Requirements

Some tools in this repository require:
- **PowerShell 7+ (`pwsh.exe`)**
- Modern .NET cryptography APIs

Scripts may not be compatible with Windows PowerShell 5.1 unless explicitly stated.

---

## No Official Affiliation

This project is **not affiliated with or endorsed by CyberArk**.

CyberArk®, CPM®, and related terms are trademarks of their respective owners.
