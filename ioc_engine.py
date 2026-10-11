"""
Indicators of Compromise (IoC) Extraction, Normalization, and Threat Intelligence Engine.
Autonomous extraction and reputation scoring of URLs, IPs, CVEs, file hashes, executables, and spoofed senders.
"""
import re
import uuid
from typing import List, Dict, Tuple, Any, Optional
from .models import IoCEntity

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "goo.gl",
    "ow.ly", "buff.ly", "adf.ly", "shorturl.at", "v.gd"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".club", ".work", ".site", ".tk", ".ml", ".ga", ".cf", ".gq", ".download", ".zip", ".mov"
]

KNOWN_MALWARE_FAMILIES = [
    "lockbit", "redline", "pegasus", "agenttesla", "mirai", "wannacry", "cobalt strike",
    "blackcat", "emotet", "darkside", "revil", "conti", "qakbot", "icedid", "formbook",
    "asyncrat", "njrat", "remcos", "brute ratel", "trickbot"
]

ENTERPRISE_TRUSTED_DOMAINS = [
    "enterprise.corp", "company.com", "portal.enterprise.net", "corp-internal.net", "gov.in", "nic.in", "sbi.co.in", "onlinesbi.sbi"
]

class IoCEngine:
    def __init__(self):
        # Compiled regex patterns
        self.url_regex = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}/[^\s<>"]*', re.IGNORECASE)
        self.ipv4_regex = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        self.cve_regex = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
        self.md5_regex = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.sha1_regex = re.compile(r'\b[a-fA-F0-9]{40}\b')
        self.sha256_regex = re.compile(r'\b[a-fA-F0-9]{64}\b')
        self.email_regex = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        self.executable_file_regex = re.compile(r'\b[\w\-.]+\.(exe|vbs|apk|bat|cmd|scr|dll|jar|sh|msi|ps1|zip\.exe)\b', re.IGNORECASE)

    def extract_and_normalize_iocs(self, text: str, sender: Optional[str] = None, explicit_urls: Optional[List[str]] = None) -> Tuple[List[IoCEntity], float]:
        """
        Extracts, normalizes, and scores all Indicators of Compromise.
        Returns (list_of_iocs, ioc_evidence_factor_I [0.0 - 1.0]).
        """
        iocs: List[IoCEntity] = []
        combined_text = text + " " + (sender or "")
        seen_values = set()

        # 1. URLs
        found_urls = self.url_regex.findall(text)
        if explicit_urls:
            found_urls.extend(explicit_urls)

        for raw_url in set(found_urls):
            clean_url = raw_url.strip(".,;:()[]{}<>\"'")
            if not clean_url or clean_url.lower() in seen_values:
                continue
            seen_values.add(clean_url.lower())

            is_short = any(s in clean_url.lower() for s in SHORTENERS)
            is_suspicious_tld = any(tld in clean_url.lower() for tld in SUSPICIOUS_TLDS)
            is_trusted = any(td in clean_url.lower() for td in ENTERPRISE_TRUSTED_DOMAINS)

            if is_short:
                risk = 0.95
                reputation = "Malicious"
                mitre = "T1566.002"
                desc = "Shortened URL masking true destination domain host"
            elif is_suspicious_tld:
                risk = 0.90
                reputation = "Malicious"
                mitre = "T1566.002"
                desc = "Suspicious high-risk top-level domain frequently used in phishing campaigns"
            elif is_trusted:
                risk = 0.05
                reputation = "Benign"
                mitre = None
                desc = "Verified corporate internal enterprise domain"
            else:
                risk = 0.65
                reputation = "Suspicious"
                mitre = "T1566.002"
                desc = "Unverified external destination web link"

            normalized = clean_url if clean_url.startswith("http") else "http://" + clean_url
            iocs.append(IoCEntity(
                ioc_id=f"IOC-URL-{uuid.uuid4().hex[:6].upper()}",
                ioc_type="URL",
                value=clean_url,
                normalized_value=normalized,
                risk_score=risk,
                reputation=reputation,
                mitre_technique=mitre,
                description=desc
            ))

        # 2. IP Addresses (IPv4)
        found_ips = self.ipv4_regex.findall(text)
        for ip in set(found_ips):
            if ip in seen_values:
                continue
            seen_values.add(ip)
            is_private = ip.startswith(("10.", "192.168.", "172.16.", "127."))
            risk = 0.35 if is_private else 0.80
            rep = "Suspicious" if not is_private else "Benign"
            iocs.append(IoCEntity(
                ioc_id=f"IOC-IP-{uuid.uuid4().hex[:6].upper()}",
                ioc_type="IP_Address",
                value=ip,
                normalized_value=ip,
                risk_score=risk,
                reputation=rep,
                mitre_technique="T1071",
                description="Direct network IP address destination embedded in message"
            ))

        # 3. CVE Vulnerabilities
        found_cves = self.cve_regex.findall(text)
        for cve in set(found_cves):
            norm_cve = cve.upper()
            if norm_cve in seen_values:
                continue
            seen_values.add(norm_cve)
            iocs.append(IoCEntity(
                ioc_id=f"IOC-CVE-{uuid.uuid4().hex[:6].upper()}",
                ioc_type="CVE_Vulnerability",
                value=cve,
                normalized_value=norm_cve,
                risk_score=0.90,
                reputation="Malicious",
                mitre_technique="T1190",
                description="Common Vulnerabilities and Exposures (CVE) exploit reference"
            ))

        # 4. Cryptographic Hashes (SHA-256, SHA-1, MD5)
        for h in set(self.sha256_regex.findall(text)):
            if h.lower() not in seen_values:
                seen_values.add(h.lower())
                iocs.append(IoCEntity(
                    ioc_id=f"IOC-HSH-{uuid.uuid4().hex[:6].upper()}",
                    ioc_type="File_Hash_SHA256",
                    value=h,
                    normalized_value=h.lower(),
                    risk_score=0.92,
                    reputation="Malicious",
                    mitre_technique="T1027",
                    description="SHA-256 Cryptographic file/payload artifact hash"
                ))

        for h in set(self.sha1_regex.findall(text)):
            if h.lower() not in seen_values:
                seen_values.add(h.lower())
                iocs.append(IoCEntity(
                    ioc_id=f"IOC-HSH-{uuid.uuid4().hex[:6].upper()}",
                    ioc_type="File_Hash_SHA1",
                    value=h,
                    normalized_value=h.lower(),
                    risk_score=0.88,
                    reputation="Malicious",
                    mitre_technique="T1027",
                    description="SHA-1 File hash identifier"
                ))

        for h in set(self.md5_regex.findall(text)):
            if h.lower() not in seen_values:
                seen_values.add(h.lower())
                iocs.append(IoCEntity(
                    ioc_id=f"IOC-HSH-{uuid.uuid4().hex[:6].upper()}",
                    ioc_type="File_Hash_MD5",
                    value=h,
                    normalized_value=h.lower(),
                    risk_score=0.85,
                    reputation="Malicious",
                    mitre_technique="T1027",
                    description="MD5 File/payload artifact hash"
                ))

        # 5. Dangerous Executable Attachments
        found_files = self.executable_file_regex.findall(text)
        for fn in set(found_files):
            # Check full match
            matches = [m.group(0) for m in self.executable_file_regex.finditer(text)]
            for full_name in set(matches):
                if full_name.lower() in seen_values:
                    continue
                seen_values.add(full_name.lower())
                iocs.append(IoCEntity(
                    ioc_id=f"IOC-FILE-{uuid.uuid4().hex[:6].upper()}",
                    ioc_type="Malicious_Attachment",
                    value=full_name,
                    normalized_value=full_name.lower(),
                    risk_score=0.95,
                    reputation="Malicious",
                    mitre_technique="T1566.001",
                    description="Executable or script file payload extension capable of arbitrary code execution"
                ))

        # 6. Malware Families
        text_lower = text.lower()
        for mw in KNOWN_MALWARE_FAMILIES:
            if re.search(r'\b' + re.escape(mw) + r'\b', text_lower):
                if mw in seen_values:
                    continue
                seen_values.add(mw)
                iocs.append(IoCEntity(
                    ioc_id=f"IOC-MALW-{uuid.uuid4().hex[:6].upper()}",
                    ioc_type="Malware_Family",
                    value=mw.title(),
                    normalized_value=mw.lower(),
                    risk_score=0.94,
                    reputation="Malicious",
                    mitre_technique="T1204",
                    description="Identified known threat actor or malware strain"
                ))

        # 7. Email Sender Discrepancy
        if sender and sender != "unknown@external-sec.net":
            clean_sender = sender.strip().lower()
            is_free_mail = any(fm in clean_sender for fm in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "yopmail.com"])
            claims_authority = any(w in text_lower for w in [
                "bank", "admin", "security cell", "cyber cell", "it-support", "helpdesk",
                "payroll", "ciso", "soc-admin", "hr", "sbi", "rbi", "executive"
            ])
            
            if is_free_mail and claims_authority:
                iocs.append(IoCEntity(
                    ioc_id=f"IOC-EML-{uuid.uuid4().hex[:6].upper()}",
                    ioc_type="Sender_Identity",
                    value=sender,
                    normalized_value=clean_sender,
                    risk_score=0.88,
                    reputation="Suspicious",
                    mitre_technique="T1566",
                    description="Spoofed sender: claims official enterprise or banking authority from public free webmail"
                ))

        # Calculate IoC Evidence Factor I (0.00 - 1.00)
        if not iocs:
            ioc_factor_i = 0.05
        else:
            # Weighted average of top IoC risk scores + bonus for multiple distinct IoCs
            scores = sorted([item.risk_score for item in iocs], reverse=True)
            top_score = scores[0]
            bonus = min(0.15, (len(scores) - 1) * 0.05)
            ioc_factor_i = min(1.0, round(top_score * 0.85 + bonus, 2))

        return iocs, ioc_factor_i
