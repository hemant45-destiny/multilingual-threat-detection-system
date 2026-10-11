"""
Pydantic Data Models and Schemas for PolyShield Multilingual Cyber-Threat Detection System.
Implements the data contracts described in Section 6, 8, 9, 10, and Appendices A-B of the report.
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import time

# Threat Categories taxonomy (Section 3, 9, 10)
THREAT_CATEGORIES = [
    "phishing",
    "malware",
    "ransomware",
    "social_engineering",
    "credential_theft",
    "vulnerability_exploitation",
    "benign_security_discussion",
    "unknown_uncertain"
]

class IoCEntity(BaseModel):
    ioc_id: str
    ioc_type: str  # URL, Domain, IP, Hash, CVE, Email, Malware, File, Username
    value: str
    normalized_value: str
    risk_score: float  # 0.0 - 1.0
    reputation: str    # Malicious, Suspicious, Unknown, Benign
    mitre_technique: Optional[str] = None
    description: Optional[str] = None

class ScriptInfo(BaseModel):
    primary_language: str
    secondary_language: Optional[str] = None
    detected_scripts: List[str]
    is_code_switched: bool
    is_transliterated: bool
    dialect_label: str
    language_confidence: float = 0.95

class EvidenceSpan(BaseModel):
    text: str
    category: str
    weight: float
    start_pos: int
    end_pos: int

class RiskFactorBreakdown(BaseModel):
    factor_c: float = Field(..., description="Calibrated confidence (0.00-1.00)")
    factor_s: float = Field(..., description="Category severity (0.00-1.00)")
    factor_r: float = Field(..., description="Source reliability (0.00-1.00)")
    factor_i: float = Field(..., description="IoC evidence strength (0.00-1.00)")
    factor_t: float = Field(..., description="Temporal recency (0.00-1.00)")
    factor_k: float = Field(..., description="Cross-source corroboration (0.00-1.00)")
    weights: Dict[str, float] = Field(..., description="Formula weights e.g. C:30, S:25, R:15, I:15, T:10, K:5")
    calculated_score: float
    severity_band: str  # LOW, MEDIUM, HIGH, CRITICAL

class MessageAnalysisRequest(BaseModel):
    text: str = Field(..., description="Raw inbound message content (English, Hindi, Marathi, Hinglish, etc.)")
    sender: Optional[str] = Field("unknown@external-sec.net", description="Sender email address or origin ID")
    source_type: Optional[str] = Field("email", description="Source format: email, sms, chat, social, threat_feed")
    source_reliability: Optional[float] = Field(0.5, description="Source reliability score (0.0-1.0)")
    urls: Optional[List[str]] = Field(default=[], description="Explicitly extracted URLs")
    language_hint: Optional[str] = Field(None, description="Optional language override")

class AnalysisResponse(BaseModel):
    message_id: str
    alert_id: str
    original_text: str
    normalized_text: str
    transliteration_mappings: List[Dict[str, str]]
    script_info: ScriptInfo
    predicted_category: str
    category_display_name: str
    category_severity: float
    calibrated_confidence: float
    probabilities: Dict[str, float]
    risk_factors: RiskFactorBreakdown
    risk_score: float
    severity_band: str
    extracted_iocs: List[IoCEntity]
    evidence_spans: List[EvidenceSpan]
    triggered_rules: List[str]
    similar_benchmark_examples: List[Dict[str, Any]]
    recommended_action: str
    mitre_techniques: List[str]
    latency_ms: float
    timestamp: float = Field(default_factory=time.time)

class AnalystActionRequest(BaseModel):
    alert_id: str
    user_id: str = "SOC-Analyst-Hemant"
    action: str  # update_disposition, update_category, add_notes
    new_disposition: Optional[str] = None  # Pending Validation, Investigating, Escalated, Closed Benign, Confirmed Incident
    new_category: Optional[str] = None
    notes: Optional[str] = ""
    reason: Optional[str] = "Analyst verified case evidence."

class ExplanationFeedbackRequest(BaseModel):
    message_id: str
    alert_id: str
    user_id: str = "SOC-Analyst-Hemant"
    feedback_rating: str  # useful, incomplete, misleading
    analyst_notes: Optional[str] = ""

class WeightConfigurationRequest(BaseModel):
    weight_c: float = 30.0  # 30%
    weight_s: float = 25.0  # 25%
    weight_r: float = 15.0  # 15%
    weight_i: float = 15.0  # 15%
    weight_t: float = 10.0  # 10%
    weight_k: float = 5.0   # 5%
    threshold_low: float = 40.0
    threshold_medium: float = 70.0
    threshold_high: float = 85.0
    user_id: str = "Coordinator-Admin"

class DatasetSampleItem(BaseModel):
    text: str
    category: str
    language: str
    source: str
    severity: Optional[float] = None
    notes: Optional[str] = None

class SystemMetrics(BaseModel):
    script_accuracy: float
    macro_f1: float
    model_accuracy: float
    avg_latency_ms: float
    false_positive_rate: float
    brier_score: float
    total_analyzed: int
    critical_risk_count: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    categories_distribution: Dict[str, int]
    languages_distribution: Dict[str, int]
