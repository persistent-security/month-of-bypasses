# Month of Bypasses

Proof-of-Concepts for Detection Engineering Purposes Only

This repository contains proof of concepts for the **Month of Bypasses** series by the [Persistent Security](https://www.persistent-security.net) Research Team.

Each bypass is a variation of a technique that Microsoft Defender already catches, covering the same MITRE ATT&CK technique ID and attack objective but via a different execution path. The goal is to help defenders understand where their protections apply and where the gaps are — before adversaries exploit them.

POCs are discovered using AI-driven variant analysis on the [Nemesis BAS](https://www.persistent-security.net) platform.

📖 **Read the introductory blog post:** [Introducing the Month of Bypasses — What Defender Can't See](https://www.persistent-security.net/post/introducing-the-month-of-bypasses-what-defender-can-t-see)

---

## Techniques Covered

| # | MITRE ATT&CK ID | Technique | Bypass |
|---|----------------|-----------|--------|
| 1 | [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | OS Credential Dumping: Security Account Manager | [`esentutl.exe /y /vss` to copy SAM and SYSTEM hives without triggering Defender](https://www.persistent-security.net/post/introducing-the-month-of-bypasses-what-defender-can-t-see) |
| 2 | [T1055.002](https://attack.mitre.org/techniques/T1055/002/) | Portable Executable Injection | [You Can't Escape The Katz!](https://www.persistent-security.net/post/month-of-bypasses-iteration-2-you-can-t-escape-the-katz) |

> POCs will be uploaded on a rolling basis over the 30-day series.

---

## Disclaimer

All content in this repository is published for **detection engineering and defensive research purposes only**. All findings based on actual vulnerabilities are disclosed through the Belgian Coordinated Vulnerability Disclosure (CVD) framework via the Centre for Cybersecurity Belgium (CCB).

Have questions or want to test your own defenses? Contact us at [info@persistent-security.net](mailto:info@persistent-security.net).
