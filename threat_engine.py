"""
Threat Signal Detection Engine across 5 security vectors:
1. Link or Attachment Risk (25%)
2. Credential / Payment Request (25%)
3. Urgency & Social Pressure (20%)
4. Sender & Context Discrepancy (20%)
5. Known Attack Behavior Match / MITRE ATT&CK (10%)
"""
import re
from typing import List, Tuple, Dict, Any
from .models import EvidenceSignal

# Domain shorteners list
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "goo.gl",
    "ow.ly", "buff.ly", "adf.ly", "shorturl.at", "v.gd"
]

# Official internal enterprise domains for organization context
ENTERPRISE_TRUSTED_DOMAINS = [
    "enterprise.corp", "company.com", "portal.enterprise.net", "corp-internal.net",
    "gov.in", "nic.in", "sbi.co.in", "onlinesbi.sbi"
]

class ThreatEngine:
    def __init__(self):
        pass

    def extract_urls(self, text: str) -> List[str]:
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}/[^\s<>"]*'
        matches = re.findall(url_pattern, text)
        return matches

    def analyze_all_signals(
        self,
        raw_text: str,
        normalized_text: str,
        sender: str,
        provided_urls: List[str]
    ) -> List[EvidenceSignal]:
        signals: List[EvidenceSignal] = []

        all_urls = list(set(self.extract_urls(raw_text) + (provided_urls or [])))

        # -----------------------------------------------------------------
        # Vector 1: Link or Attachment Risk (Weight 25%)
        # -----------------------------------------------------------------
        shortened_urls_found = [u for u in all_urls if any(s in u.lower() for s in SHORTENERS)]
        if shortened_urls_found:
            signals.append(EvidenceSignal(
                signal_id="SIG-LINK-01",
                signal_name="Mismatched / Suspicious Shortened URL",
                signal_family="Link or Attachment Risk",
                weight=25.0,
                confidence=0.96,
                contribution=24.0,
                evidence_text=", ".join(shortened_urls_found),
                mitre_technique="T1566.002",
                description="Destination URL uses shortener service hiding actual malicious domain host."
            ))
        elif len(all_urls) > 0:
            # Check for suspicious non-enterprise domain or typosquatting
            suspicious_urls = [u for u in all_urls if not any(d in u.lower() for d in ENTERPRISE_TRUSTED_DOMAINS)]
            if suspicious_urls:
                signals.append(EvidenceSignal(
                    signal_id="SIG-LINK-02",
                    signal_name="Unverified External Domain Link",
                    signal_family="Link or Attachment Risk",
                    weight=25.0,
                    confidence=0.85,
                    contribution=21.25,
                    evidence_text=", ".join(suspicious_urls),
                    mitre_technique="T1566.002",
                    description="Link points to unverified external web portal outside enterprise perimeter trust boundary."
                ))

        # Check for suspicious file attachments mentioned or linked
        suspicious_files = re.findall(r'\b[\w-]+\.(exe|vbs|scr|zip\.exe|apk|bat|cmd|jar)\b', raw_text, re.I)
        if suspicious_files:
            signals.append(EvidenceSignal(
                signal_id="SIG-ATTACH-01",
                signal_name="Suspicious Executable Payload Attachment",
                signal_family="Link or Attachment Risk",
                weight=25.0,
                confidence=0.95,
                contribution=23.75,
                evidence_text=", ".join(suspicious_files),
                mitre_technique="T1566.001",
                description="Attachment contains executable extension capable of remote code execution."
            ))

        # -----------------------------------------------------------------
        # Vector 2: Credential / Payment Request (Weight 25%)
        # -----------------------------------------------------------------
        cred_keywords = [
            r"\b(password|pasward|passward|pin|otp|otapi|cvv|debit card|credit card|login credential|secret key)\b",
            r"\b(verify your password|enter otp|share otp|update kyc|bank account details|upi pin)\b",
            r"\[AUTHENTICATION_TOKEN\]", r"\[LOGIN_PORTAL\]"
        ]
        
        found_cred_matches = []
        for pat in cred_keywords:
            matches = re.findall(pat, raw_text + " " + normalized_text, re.IGNORECASE)
            if matches:
                for m in matches:
                    found_cred_matches.append(m if isinstance(m, str) else m[0])

        if found_cred_matches:
            signals.append(EvidenceSignal(
                signal_id="SIG-CRED-01",
                signal_name="Credential & OTP Solicitation Request",
                signal_family="Credential / Payment Request",
                weight=25.0,
                confidence=1.0,
                contribution=25.0,
                evidence_text=", ".join(list(set(found_cred_matches))[:3]),
                mitre_technique="T1556",
                description="Message requests high-sensitivity authentication tokens (passwords, PINs, or OTPs)."
            ))
        else:
            # Check for financial transfer solicits
            fin_matches = re.findall(r'\b(transfer|pay rs|bhejo|paisa|bank transfer|gift card|crypto|bitcoin)\b', raw_text + " " + normalized_text, re.I)
            if fin_matches:
                signals.append(EvidenceSignal(
                    signal_id="SIG-CRED-02",
                    signal_name="Urgent Financial Solicitation / Transfer Request",
                    signal_family="Credential / Payment Request",
                    weight=25.0,
                    confidence=0.80,
                    contribution=20.0,
                    evidence_text=", ".join(list(set(fin_matches))[:3]),
                    mitre_technique="T1556",
                    description="Solicits immediate direct monetary transfers or unverified payments."
                ))

        # -----------------------------------------------------------------
        # Vector 3: Urgency & Social Pressure (Weight 20%)
        # -----------------------------------------------------------------
        urgency_keywords = [
            r"\b(closed today|suspended today|account will be closed|freeze|immediate action|turant|aaj hi|24 hours|within 1 hour)\b",
            r"\[URGENT_DEADLINE\]", r"\[SUSPENDED\]", r"\[LEGAL_THREAT\]"
        ]
        
        found_urgency = []
        for pat in urgency_keywords:
            matches = re.findall(pat, raw_text + " " + normalized_text, re.IGNORECASE)
            if matches:
                for m in matches:
                    found_urgency.append(m if isinstance(m, str) else m[0])

        if found_urgency:
            signals.append(EvidenceSignal(
                signal_id="SIG-URG-01",
                signal_name="Urgent Account-Closure Language Pressure",
                signal_family="Urgency & Social Pressure",
                weight=20.0,
                confidence=0.90,
                contribution=18.0,
                evidence_text=", ".join(list(set(found_urgency))[:3]),
                mitre_technique="T1566",
                description="Severe coercive deadline imposing immediate loss of account access."
            ))

        # -----------------------------------------------------------------
        # Vector 4: Sender & Context Discrepancy (Weight 20%)
        # -----------------------------------------------------------------
        sender_lower = sender.lower() if sender else ""
        is_unknown_sender = not sender or "unknown" in sender_lower or any(domain in sender_lower for domain in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "mail.ru"])
        
        # Discrepancy check: claims to be official enterprise authority/bank but comes from free public webmail
        claims_official = any(kw in (raw_text + " " + normalized_text).lower() for kw in [
            "bank", "admin", "it-support", "ciso", "security cell", "cyber cell",
            "account", "payroll", "compliance", "human resources", "executive"
        ])
        
        if claims_official and is_unknown_sender:
            signals.append(EvidenceSignal(
                signal_id="SIG-SND-01",
                signal_name="Unknown Sender Context & Domain Mismatch",
                signal_family="Sender & Context Discrepancy",
                weight=20.0,
                confidence=0.75,
                contribution=15.0,
                evidence_text=f"Sender: '{sender}' claiming official authority",
                mitre_technique="T1566",
                description="Unauthenticated or public webmail origin claiming official enterprise executive or banking authority."
            ))
        elif is_unknown_sender and len(all_urls) > 0:
            signals.append(EvidenceSignal(
                signal_id="SIG-SND-02",
                signal_name="Unverified External Origin",
                signal_family="Sender & Context Discrepancy",
                weight=20.0,
                confidence=0.60,
                contribution=12.0,
                evidence_text=f"Sender: {sender}",
                mitre_technique="T1566",
                description="Inbound communication originates from external untrusted email infrastructure."
            ))

        # -----------------------------------------------------------------
        # Vector 5: Known Attack Behavior Match / MITRE ATT&CK (Weight 10%)
        # -----------------------------------------------------------------
        # Check if combination of credential request + link + pressure exists
        if len(signals) >= 2:
            signals.append(EvidenceSignal(
                signal_id="SIG-MITRE-01",
                signal_name="MITRE ATT&CK Spearphishing Pattern (T1566.002)",
                signal_family="Known Attack Behavior Match",
                weight=10.0,
                confidence=1.0,
                contribution=10.0,
                evidence_text="Coercive language combined with credential request & link",
                mitre_technique="T1566.002",
                description="Semantic structure aligns with MITRE ATT&CK T1566.002 (Spearphishing Link for Credential Access)."
            ))

        return signals
