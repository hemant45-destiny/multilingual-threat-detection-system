"""
FastAPI Main Web Application for PolyShield™ Enterprise Multilingual Threat Intelligence Gateway.
Autonomous Inbound Payload Triage, Vernacular Threat De-obfuscation & SOC Incident Decision Support.
"""
import os
import time
import uuid
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional

from .models import (
    MessageAnalysisRequest,
    AnalysisResponse,
    AnalystActionRequest,
    ExplanationFeedbackRequest,
    WeightConfigurationRequest,
    DatasetSampleItem,
    SystemMetrics
)
from .language_engine import LanguageEngine
from .ioc_engine import IoCEngine
from .ml_classifier import MultilingualThreatClassifier, CATEGORY_DISPLAY_NAMES
from .scoring_engine import ScoringEngine
from .database import StorageManager
from .dataset import add_curated_sample, BENCHMARK_DATASET

app = FastAPI(
    title="PolyShield™ Enterprise Multilingual Threat Intelligence Gateway API",
    description="Autonomous Explainable Early-Warning Risk Scoring, Vernacular De-obfuscation & Decision Support Platform",
    version="2.4.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Base Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Core Engine Singletons
lang_engine = LanguageEngine()
ioc_engine = IoCEngine()
classifier = MultilingualThreatClassifier()
scoring_engine = ScoringEngine()
storage_manager = StorageManager()

# Pre-packaged real-world multilingual test cases
PRESET_CASES = [
    {
        "id": "preset-account-suspension",
        "title": "Urgent Account Suspension Phishing Lure (Shortened Link)",
        "sender": "alert-service@external-sec.net",
        "source_type": "email",
        "source_reliability": 0.35,
        "text": "Your account will be closed today. Verify your password and OTP at this link: http://bit.ly/bank-verify",
        "description": "Urgent coercive language demanding password & OTP with masked bit.ly shortener link."
    },
    {
        "id": "preset-hinglish-otp",
        "title": "Hinglish Urgent Account Freeze & OTP Theft (Romanized Indic)",
        "sender": "sbi-security-notice@gmail.com",
        "source_type": "sms",
        "source_reliability": 0.40,
        "text": "ALERT: Aapka SBI bank khata aaj hi freeze hone wala hai! Update password and enter OTP at http://bit.ly/sbi-khata-update turant badlo.",
        "description": "Romanized Hinglish code-mixing demanding urgent password & OTP input."
    },
    {
        "id": "preset-marathi-devanagari",
        "title": "Regional Marathi Devanagari Bank Coercion (Devanagari)",
        "sender": "maha-cyber-notice@random-domain.xyz",
        "source_type": "sms",
        "source_reliability": 0.30,
        "text": "महत्वाची सूचना: तुमचे बँक खाते आज बंद केले जाईल! दंड टाळण्यासाठी तुमचा पासवर्ड आणि OTP त्वरित पडताळून पहा: http://bit.ly/bank-marathi",
        "description": "Devanagari script Marathi language credential harvesting attempt with urgent legal penalty threat."
    },
    {
        "id": "preset-hindi-devanagari",
        "title": "Regional Hindi Devanagari Bank Phishing (Devanagari)",
        "sender": "support-rbi@notice-portal.online",
        "source_type": "sms",
        "source_reliability": 0.30,
        "text": "प्रिय ग्राहक, आपका बैंक खाता आज ब्लॉक कर दिया जाएगा। अपना पासवर्ड और ओटीपी तुरंत दर्ज करके खाता चालू रखें: http://bit.ly/bank-hindi-verify",
        "description": "Devanagari script Hindi credential lure threatening immediate account block."
    },
    {
        "id": "preset-ransomware-extortion",
        "title": "LockBit 3.0 Ransomware Extortion Attack",
        "sender": "lockbit-affiliate@onion-host.biz",
        "source_type": "email",
        "source_reliability": 0.70,
        "text": "All your corporate files, databases and backups have been encrypted with LockBit 3.0 military-grade algorithm. Send 5 Bitcoin to decrypt within 48 hours.",
        "description": "Extortion attack announcing encryption and cryptocurrency ransom demand."
    },
    {
        "id": "preset-malware-payload",
        "title": "Trojanized Android APK & Executable Payload Lure",
        "sender": "security-patch@external-cdn.top",
        "source_type": "chat",
        "source_reliability": 0.35,
        "text": "Urgent security update: Download and install critical enterprise update Enterprise_VPN_Client.apk to prevent unauthorized device access: http://malicious-cdn.xyz/tool.apk",
        "description": "Malware delivery disguising an Android APK payload as an urgent system security patch."
    },
    {
        "id": "preset-cve-exploit",
        "title": "Active CVE-2024-3400 Perimeter Gateway Exploitation",
        "sender": "osint-feed@cert-advisory.gov.in",
        "source_type": "threat_feed",
        "source_reliability": 0.90,
        "text": "Active exploitation observed in the wild targeting CVE-2024-3400 affecting Palo Alto PAN-OS GlobalProtect gateway via arbitrary command injection from IP 185.220.101.5.",
        "description": "Verified threat intelligence advisory reporting in-the-wild zero-day CVE exploitation."
    },
    {
        "id": "preset-corporate-legitimate",
        "title": "Legitimate Corporate Internal Notification (Benign)",
        "sender": "hr-operations@enterprise.corp",
        "source_type": "email",
        "source_reliability": 0.95,
        "text": "Dear Team, please review the updated quarterly policy documentation available on the official corporate intranet portal at https://enterprise.corp/hr-portal before Friday.",
        "description": "Legitimate corporate communication from verified internal organizational domain."
    }
]

def seed_initial_alerts_if_empty():
    """Seeds the initial alert queue so analysts have realistic cases immediately upon launching."""
    alerts = storage_manager.get_all_alerts(limit=5)
    if not alerts:
        for preset in PRESET_CASES[:5]:
            req = MessageAnalysisRequest(
                text=preset["text"],
                sender=preset["sender"],
                source_type=preset["source_type"],
                source_reliability=preset.get("source_reliability", 0.5)
            )
            # Run analysis and save
            run_analysis_pipeline(req)

def run_analysis_pipeline(payload: MessageAnalysisRequest) -> AnalysisResponse:
    start_time = time.time()
    msg_id = f"MSG-2026-{uuid.uuid4().hex[:6].upper()}"
    alert_id = f"ALR-2026-{uuid.uuid4().hex[:5].upper()}"

    # 1. Language & Script Identification
    script_info = lang_engine.detect_script_and_language(payload.text)

    # 2. Transliteration & Canonical Normalization
    normalized_text, transliteration_mappings, evidence_spans = lang_engine.normalize_text(payload.text)

    # 3. Indicators of Compromise Extraction
    iocs, ioc_factor_i = ioc_engine.extract_and_normalize_iocs(
        text=payload.text,
        sender=payload.sender,
        explicit_urls=payload.urls
    )

    # 4. Multilingual ML Classification & Calibrated Confidence
    predicted_category, calib_conf, cat_severity, probabilities, keywords = classifier.predict(
        text=payload.text,
        normalized_text=normalized_text
    )

    # 5. Risk Score Computation
    # Risk = 100 * (0.30C + 0.25S + 0.15R + 0.15I + 0.10T + 0.05K)
    source_rel = payload.source_reliability if payload.source_reliability is not None else 0.5
    corroboration = 0.8 if len(iocs) > 1 or payload.source_type == "threat_feed" else 0.4
    recency = 1.0

    risk_score, severity_band, factor_breakdown = scoring_engine.compute_risk(
        calibrated_confidence=calib_conf,
        category_severity=cat_severity,
        source_reliability=source_rel,
        ioc_evidence=ioc_factor_i,
        temporal_recency=recency,
        corroboration=corroboration
    )

    # 6. Decision Support & Explainability
    triggered_rules = scoring_engine.generate_rules_triggered(
        category=predicted_category,
        script_info=script_info,
        iocs=iocs,
        normalized_replacements=transliteration_mappings
    )
    recommended_action = scoring_engine.generate_recommendation(predicted_category, severity_band)

    # Similar benchmark examples
    similar_examples = [
        {"category": item["category"], "text": item["text"][:75] + "...", "language": item["language"]}
        for item in BENCHMARK_DATASET if item["category"] == predicted_category
    ][:2]

    mitre_techs = list(set([ioc.mitre_technique for ioc in iocs if ioc.mitre_technique]))
    if predicted_category in ["phishing", "social_engineering"] and "T1566" not in mitre_techs:
        mitre_techs.append("T1566")
    if predicted_category == "credential_theft" and "T1556" not in mitre_techs:
        mitre_techs.append("T1556")
    if predicted_category == "ransomware" and "T1486" not in mitre_techs:
        mitre_techs.append("T1486")

    latency_ms = (time.time() - start_time) * 1000.0

    response = AnalysisResponse(
        message_id=msg_id,
        alert_id=alert_id,
        original_text=payload.text,
        normalized_text=normalized_text,
        transliteration_mappings=transliteration_mappings,
        script_info=script_info,
        predicted_category=predicted_category,
        category_display_name=CATEGORY_DISPLAY_NAMES.get(predicted_category, predicted_category.title()),
        category_severity=cat_severity,
        calibrated_confidence=calib_conf,
        probabilities=probabilities,
        risk_factors=factor_breakdown,
        risk_score=risk_score,
        severity_band=severity_band,
        extracted_iocs=iocs,
        evidence_spans=evidence_spans,
        triggered_rules=triggered_rules,
        similar_benchmark_examples=similar_examples,
        recommended_action=recommended_action,
        mitre_techniques=mitre_techs,
        latency_ms=round(latency_ms, 2)
    )

    # Persist in Relational Database (Section 8)
    storage_manager.save_analysis(response, source_reliability=source_rel)
    return response

@app.on_event("startup")
def startup_event():
    seed_initial_alerts_if_empty()

@app.get("/")
async def render_dashboard():
    index_path = os.path.join(TEMPLATES_DIR, "index.html")
    return FileResponse(index_path)

@app.post("/api/analyze", response_model=AnalysisResponse)
@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_message(payload: MessageAnalysisRequest):
    return run_analysis_pipeline(payload)

@app.get("/api/alerts")
@app.get("/api/v1/alerts")
async def get_alerts(limit: int = 50):
    return storage_manager.get_all_alerts(limit=limit)

@app.post("/api/alerts/action")
@app.post("/api/v1/alerts/action")
async def perform_analyst_action(action: AnalystActionRequest):
    success = storage_manager.update_alert_disposition(
        alert_id=action.alert_id,
        user_id=action.user_id,
        disposition=action.new_disposition or "Investigating",
        status="Closed" if "closed" in (action.new_disposition or "").lower() else "Under Review",
        notes=action.notes or "",
        reason=action.reason or "Analyst validation action"
    )
    if not success:
        raise HTTPException(status_code=400, detail="Failed to update alert disposition.")
    return {"status": "success", "message": f"Alert {action.alert_id} disposition updated to {action.new_disposition}."}

@app.post("/api/explanation/feedback")
@app.post("/api/v1/explanation/feedback")
async def submit_explanation_feedback(req: ExplanationFeedbackRequest):
    success = storage_manager.save_explanation_feedback(
        alert_id=req.alert_id,
        message_id=req.message_id,
        user_id=req.user_id,
        feedback=req.feedback_rating,
        notes=req.analyst_notes or ""
    )
    return {"status": "success", "message": f"Explanation feedback '{req.feedback_rating}' logged."}

@app.get("/api/iocs")
@app.get("/api/v1/iocs")
async def get_all_iocs(limit: int = 100):
    return storage_manager.get_all_iocs(limit=limit)

@app.post("/api/curate-sample")
@app.post("/api/v1/curate-sample")
async def curate_new_sample(sample: DatasetSampleItem):
    item = {
        "text": sample.text,
        "category": sample.category,
        "language": sample.language,
        "source": sample.source,
        "severity": sample.severity or 0.8
    }
    total = add_curated_sample(item)
    classifier.retrain_with_new_sample(item)
    return {"status": "success", "message": f"Sample added to dataset. Total curated samples: {total}. Model retrained."}

@app.get("/api/metrics", response_model=SystemMetrics)
@app.get("/api/v1/metrics", response_model=SystemMetrics)
async def get_system_metrics():
    return storage_manager.get_metrics()

@app.get("/api/model-evaluation")
@app.get("/api/v1/model-evaluation")
async def get_model_evaluation():
    return classifier.evaluation_metrics

@app.get("/api/decision-logs")
@app.get("/api/v1/decision-logs")
async def get_decision_logs(limit: int = 50):
    return storage_manager.get_decision_logs(limit=limit)

@app.post("/api/weights")
@app.post("/api/v1/weights")
async def update_risk_weights(req: WeightConfigurationRequest):
    scoring_engine.set_weights({
        "C": req.weight_c,
        "S": req.weight_s,
        "R": req.weight_r,
        "I": req.weight_i,
        "T": req.weight_t,
        "K": req.weight_k
    })
    scoring_engine.set_thresholds({
        "LOW": req.threshold_low,
        "MEDIUM": req.threshold_medium,
        "HIGH": req.threshold_high
    })
    return {"status": "success", "message": "Risk formula weights and thresholds updated successfully."}

@app.get("/api/presets")
@app.get("/api/v1/presets")
async def get_presets():
    return PRESET_CASES

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
