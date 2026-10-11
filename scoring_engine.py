"""
Risk Scoring Engine & Explainability Generator.
Implements the exact Mathematical Formulation from Section 10.3 and Appendix A:
Risk = 100 x (0.30C + 0.25S + 0.15R + 0.15I + 0.10T + 0.05K)
where:
  C = Calibrated Confidence
  S = Category Severity
  R = Source Reliability
  I = IoC Evidence
  T = Temporal Recency
  K = Corroboration
Assigns severity bands (LOW, MEDIUM, HIGH, CRITICAL) and generates actionable decision playbooks.
"""
from typing import List, Dict, Tuple, Any, Optional
from .models import (
    RiskFactorBreakdown,
    AnalysisResponse,
    ScriptInfo,
    IoCEntity,
    EvidenceSpan
)
from .ml_classifier import CATEGORY_DISPLAY_NAMES

DEFAULT_WEIGHTS = {
    "C": 30.0,  # 30% Calibrated confidence
    "S": 25.0,  # 25% Category severity
    "R": 15.0,  # 15% Source reliability
    "I": 15.0,  # 15% IoC evidence strength
    "T": 10.0,  # 10% Temporal recency
    "K": 5.0    # 5% Corroboration
}

# Threshold bands
DEFAULT_THRESHOLDS = {
    "LOW": 40.0,
    "MEDIUM": 70.0,
    "HIGH": 85.0
}

PLAYBOOK_RECOMMENDATIONS = {
    "phishing": {
        "CRITICAL": "Block domain at enterprise edge firewall immediately. Revoke compromised SSO tokens. Issue corporate-wide security alert.",
        "HIGH": "Quarantine email payload. Submit look-alike URL to threat blacklist. Notify SOC analyst for user impact assessment.",
        "MEDIUM": "Flag message with suspicious banner. Require multi-factor authentication check if link was opened.",
        "LOW": "Normal delivery with standard email authentication headers verified."
    },
    "ransomware": {
        "CRITICAL": "ISOLATE HOST FROM NETWORK IMMEDIATELY. Terminate active remote sessions, freeze backup sync, and initiate Incident Response Playbook IR-04.",
        "HIGH": "Block command & control IP/domain. Audit shadow copies and verify immutability of cold backup storage.",
        "MEDIUM": "Inspect host process tree and monitor high-frequency disk write activity.",
        "LOW": "Benign security advisory regarding ransomware hygiene."
    },
    "malware": {
        "CRITICAL": "Quarantine attachment and blackhole hash across endpoint EDR. Detonate in sandbox and inspect persistence mechanisms.",
        "HIGH": "Block executable payload extension. Restrict ingress from sender domain and scan local machine endpoints.",
        "MEDIUM": "Submit unverified attachment to automated sandboxing and notify recipient.",
        "LOW": "Verified non-executable attachment passed through AV scan."
    },
    "social_engineering": {
        "CRITICAL": "Impersonation alert: High-level executive/authority spoofing detected. Contact alleged sender via out-of-band channel immediately.",
        "HIGH": "Advise target employee to halt financial transfers or gift-card purchases. Log attempt in threat registry.",
        "MEDIUM": "Highlight sender mismatch warning to recipient. Verify request through corporate directory.",
        "LOW": "Standard internal employee inquiry."
    },
    "credential_theft": {
        "CRITICAL": "Emergency: Active credential/OTP theft solicitation. Trigger immediate password reset for targeted account and enforce hardware token.",
        "HIGH": "Block credential harvesting link. Warn recipient never to disclose one-time passwords.",
        "MEDIUM": "Review recent login attempts for anomaly detection.",
        "LOW": "Standard routine credential maintenance."
    },
    "vulnerability_exploitation": {
        "CRITICAL": "Active CVE exploitation detected. Deploy emergency virtual patch on perimeter gateway and verify vulnerable package versions.",
        "HIGH": "Correlate CVE identifier with enterprise asset inventory and prioritize patch deployment within 24 hours.",
        "MEDIUM": "Log vulnerability scan attempt and verify IDS/IPS signature status.",
        "LOW": "Informational vulnerability bulletin."
    },
    "benign_security_discussion": {
        "LOW": "Authorized corporate communication. No containment action necessary. Retain in security archive."
    },
    "unknown_uncertain": {
        "MEDIUM": "Low-confidence signal: route to analyst triage queue for human annotation and sample labeling.",
        "LOW": "Benign low-confidence communication."
    }
}

class ScoringEngine:
    def __init__(self):
        self.weights = dict(DEFAULT_WEIGHTS)
        self.thresholds = dict(DEFAULT_THRESHOLDS)

    def set_weights(self, weights: Dict[str, float]):
        self.weights.update(weights)

    def set_thresholds(self, thresholds: Dict[str, float]):
        self.thresholds.update(thresholds)

    def compute_risk(
        self,
        calibrated_confidence: float,
        category_severity: float,
        source_reliability: float,
        ioc_evidence: float,
        temporal_recency: float = 1.0,
        corroboration: float = 0.5
    ) -> Tuple[float, str, RiskFactorBreakdown]:
        """
        Calculates Risk = 100 * (wC*C + wS*S + wR*R + wI*I + wT*T + wK*K) / 100
        """
        w_c = self.weights.get("C", 30.0) / 100.0
        w_s = self.weights.get("S", 25.0) / 100.0
        w_r = self.weights.get("R", 15.0) / 100.0
        w_i = self.weights.get("I", 15.0) / 100.0
        w_t = self.weights.get("T", 10.0) / 100.0
        w_k = self.weights.get("K", 5.0) / 100.0

        # Raw formula calculation
        raw_score = 100.0 * (
            (w_c * calibrated_confidence) +
            (w_s * category_severity) +
            (w_r * source_reliability) +
            (w_i * ioc_evidence) +
            (w_t * temporal_recency) +
            (w_k * corroboration)
        )

        risk_score = round(min(max(raw_score, 0.0), 100.0), 1)

        # Determine severity band
        if risk_score >= self.thresholds.get("HIGH", 85.0):
            severity_band = "CRITICAL"
        elif risk_score >= self.thresholds.get("MEDIUM", 70.0):
            severity_band = "HIGH"
        elif risk_score >= self.thresholds.get("LOW", 40.0):
            severity_band = "MEDIUM"
        else:
            severity_band = "LOW"

        breakdown = RiskFactorBreakdown(
            factor_c=round(calibrated_confidence, 2),
            factor_s=round(category_severity, 2),
            factor_r=round(source_reliability, 2),
            factor_i=round(ioc_evidence, 2),
            factor_t=round(temporal_recency, 2),
            factor_k=round(corroboration, 2),
            weights=self.weights,
            calculated_score=risk_score,
            severity_band=severity_band
        )

        return risk_score, severity_band, breakdown

    def generate_recommendation(self, category: str, severity_band: str) -> str:
        cat_playbook = PLAYBOOK_RECOMMENDATIONS.get(category, {})
        if severity_band in cat_playbook:
            return cat_playbook[severity_band]
        # Fallback to closest band
        for band in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if band in cat_playbook:
                return cat_playbook[band]
        return "Review communication carefully and cross-reference with official institutional security contacts."

    def generate_rules_triggered(
        self,
        category: str,
        script_info: ScriptInfo,
        iocs: List[IoCEntity],
        normalized_replacements: List[Dict[str, str]]
    ) -> List[str]:
        rules = []
        if script_info.is_code_switched:
            rules.append(f"Multilingual Code-Switching Rule: Detected mixed {script_info.primary_language} with {script_info.secondary_language or 'regional slang'}")

        if script_info.is_transliterated:
            rules.append("Vernacular Transliteration Rule: Romanized Indic threat semantics identified")

        for repl in normalized_replacements[:2]:
            rules.append(f"Canonical Security Mapping: '{repl['original']}' recognized as {repl['canonical_semantic']}")

        shortened_links = [ioc.value for ioc in iocs if ioc.ioc_type == "URL" and "shortened" in (ioc.description or "").lower()]
        if shortened_links:
            rules.append(f"URL Shortener Obfuscation Rule: Identified masked destination link ({shortened_links[0]})")

        cves = [ioc.value for ioc in iocs if ioc.ioc_type == "CVE_Vulnerability"]
        if cves:
            rules.append(f"Exploit Correlation Rule: Active reference to known CVE identifier ({cves[0]})")

        attachments = [ioc.value for ioc in iocs if ioc.ioc_type == "Malicious_Attachment"]
        if attachments:
            rules.append(f"Dangerous Attachment Rule: Executable payload extension ({attachments[0]})")

        if category in ["credential_theft", "phishing"]:
            rules.append("MITRE ATT&CK T1556: Input capture / Credential solicitation behavior pattern matched")

        if category == "ransomware":
            rules.append("MITRE ATT&CK T1486: Data Encrypted for Impact extortion pattern matched")

        if not rules:
            rules.append("Standard Low-Risk Baseline: Communication matches legitimate institutional communication patterns")

        return rules
