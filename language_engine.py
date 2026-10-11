"""
Language Identification, Normalization, Transliteration, and Script Analysis Engine.
PolyShield Vernacular Processing: Supports English, Hindi, Marathi, Hinglish, Marathlish, and regional Arabic scripts.
"""
import re
import unicodedata
from typing import Dict, List, Tuple, Any, Optional
from .models import ScriptInfo, EvidenceSpan

# Comprehensive vernacular mapping: Romanized Hindi (Hinglish) & Romanized Marathi (Marathlish) + Devanagari
VERNACULAR_MAPPINGS = {
    # Account & Identity
    r"\b(aapka|apka|tumcha|tumche|tumchaa|apna|mera|amche|khata|khate|khatra|khataye|account|bank-khata)\b": "[ACCOUNT_TARGET]",
    # Urgency & Panic Induction
    r"\b(aaj|aaj-hi|today|abhi|turant|atach|tattkal|tatkal|immadiate|urgent|jaldi|lagaatar|closed today|band honar|band ho jayega|within 24 hours|within 1 hour)\b": "[URGENT_DEADLINE]",
    # Account Suspension / Coercion
    r"\b(band|block|suspend|freeze|thambavla|hona|honar|roka|karvayi|karwai|action)\b": "[SUSPENSION_THREAT]",
    # Credential Solicitation
    r"\b(pasward|passward|paswrd|password|pin|otapi|otp|passcode|token|cvv|secret-key|kunjika)\b": "[AUTHENTICATION_TOKEN]",
    # Action Triggers
    r"\b(badal|badla|update|verify|navin|badlayche|tapasani|parikshan|padtalun|daba|click|bhejo|bhej|send|daakhil|karo|kara)\b": "[ACTION_TRIGGER]",
    # Legal / Institutional Fear
    r"\b(shasan|sarkar|police|cyber|cbi|income-tax|tax|court|legal|dand|fine|jurmana|gunehgar)\b": "[LEGAL_COERCION]",
    # Financial Solicitation
    r"\b(paise|paisa|rupaye|rs|cash|balance|fine|shulk|bheja|transfer|bhim|upi)\b": "[FINANCIAL_FUNDS]",
    # Malicious Links / Portals
    r"\b(link|url|website|portal|site|darwaza|pravesh|khola)\b": "[DESTINATION_LINK]",
    # Malware & Ransomware Lures
    r"\b(lottery|inaam|gift|bhet|winner|vijeta|free recharge|muft|bonus|karo click|files encrypted|decryptor)\b": "[MALICIOUS_LURE]"
}

# Devanagari script Unicode range: \u0900 - \u097F
DEVANAGARI_REGEX = re.compile(r'[\u0900-\u097F]')
# Latin alphabet range: [a-zA-Z]
LATIN_REGEX = re.compile(r'[a-zA-Z]')
# Arabic script Unicode range: \u0600 - \u06FF
ARABIC_REGEX = re.compile(r'[\u0600-\u06FF]')

# Distinctive Marathi vocabulary cues (distinguishes Marathi from Hindi in Devanagari)
MARATHI_CUES = [
    "आहे", "नाही", "करा", "पडताळणी", "खाते", "त्वरित", "बंद", "केले", "जाईल", "तुमचे",
    "आमचे", "दंडात्मक", "कारवाई", "करावे", "होईल", "येथे", "लिंक", "शुल्क", "विद्यार्थी"
]

# Distinctive Hindi vocabulary cues
HINDI_CUES = [
    "है", "नहीं", "करें", "सत्यापन", "खाता", "तुरंत", "बंद", "किया", "जाएगा", "आपका",
    "हमारा", "जुर्माना", "कार्यवाही", "होगा", "यहाँ", "लिंक", "छात्र", "भेजें"
]

class LanguageEngine:
    def __init__(self):
        pass

    def detect_script_and_language(self, text: str) -> ScriptInfo:
        """
        Identifies scripts, code-switching, transliteration, and primary language profile.
        """
        devanagari_count = len(DEVANAGARI_REGEX.findall(text))
        latin_count = len(LATIN_REGEX.findall(text))
        arabic_count = len(ARABIC_REGEX.findall(text))

        detected_scripts = []
        if devanagari_count > 0:
            detected_scripts.append("Devanagari")
        if latin_count > 0:
            detected_scripts.append("Latin")
        if arabic_count > 0:
            detected_scripts.append("Arabic")

        if not detected_scripts:
            detected_scripts.append("Numeric/Symbolic")

        # Code-switching check (Devanagari + Latin script in same message)
        is_code_switched = (devanagari_count > 0 and latin_count > 0)
        
        # Transliteration check (Romanized Indic cues e.g. Hinglish / Marathlish in Latin script)
        text_lower = text.lower()
        has_indic_transliteration = any(re.search(pat, text_lower) for pat in VERNACULAR_MAPPINGS.keys())

        # Determine Primary Language & Dialect
        primary_lang = "English"
        secondary_lang = None
        dialect_label = "Standard English"
        confidence = 0.95

        if devanagari_count > 0:
            # Check whether Devanagari text is Marathi or Hindi
            marathi_matches = sum(1 for cue in MARATHI_CUES if cue in text)
            hindi_matches = sum(1 for cue in HINDI_CUES if cue in text)

            if marathi_matches > hindi_matches:
                primary_lang = "Marathi"
                dialect_label = "Regional Marathi (Devanagari)"
            elif hindi_matches > 0:
                primary_lang = "Hindi"
                dialect_label = "Regional Hindi (Devanagari)"
            else:
                primary_lang = "Hindi/Marathi"
                dialect_label = "Devanagari Indic"

            if latin_count > 0:
                secondary_lang = "English"
                dialect_label = f"Code-Switched {primary_lang}-English (Mixed Scripts)"
                confidence = 0.96
        elif arabic_count > 0:
            primary_lang = "Arabic"
            dialect_label = "Arabic Regional Script"
            confidence = 0.94
        elif has_indic_transliteration:
            # Determine Hinglish vs Marathlish
            is_marathlish = any(m in text_lower for m in ["tumche", "tumcha", "khatya", "thambavla", "atach", "padtalun", "honar", "amche"])
            if is_marathlish:
                primary_lang = "Marathlish"
                secondary_lang = "English"
                dialect_label = "Romanized Marathi-English (Marathlish)"
            else:
                primary_lang = "Hinglish"
                secondary_lang = "English"
                dialect_label = "Romanized Hindi-English (Hinglish)"
            is_code_switched = True
            confidence = 0.93
        else:
            primary_lang = "English"
            dialect_label = "Standard English / Technical"
            confidence = 0.98

        return ScriptInfo(
            primary_language=primary_lang,
            secondary_language=secondary_lang,
            detected_scripts=detected_scripts,
            is_code_switched=is_code_switched,
            is_transliterated=has_indic_transliteration,
            dialect_label=dialect_label,
            language_confidence=confidence
        )

    def normalize_text(self, text: str) -> Tuple[str, List[Dict[str, str]], List[EvidenceSpan]]:
        """
        Preserves raw message while creating a safe analysis copy with Unicode normalization,
        canonical semantic mapping, and evidence span location tracking.
        """
        # Unicode NFKC normalization
        normalized = unicodedata.normalize('NFKC', text)
        replacements: List[Dict[str, str]] = []
        evidence_spans: List[EvidenceSpan] = []

        # Find and map vernacular patterns
        for pattern, semantic_token in VERNACULAR_MAPPINGS.items():
            for match in re.finditer(pattern, text, re.IGNORECASE):
                matched_str = match.group(0)
                replacements.append({
                    "original": matched_str,
                    "canonical_semantic": semantic_token
                })
                evidence_spans.append(EvidenceSpan(
                    text=matched_str,
                    category=semantic_token.strip("[]"),
                    weight=0.85,
                    start_pos=match.start(),
                    end_pos=match.end()
                ))

        # Substitute canonical semantics for model inspection
        canonical_text = normalized
        for pattern, semantic_token in VERNACULAR_MAPPINGS.items():
            canonical_text = re.sub(pattern, f" {semantic_token} ", canonical_text, flags=re.IGNORECASE)

        # Whitespace cleanup while preserving symbols
        canonical_text = re.sub(r'\s+', ' ', canonical_text).strip()

        # Deduplicate replacements
        unique_replacements = []
        seen = set()
        for r in replacements:
            key = (r["original"].lower(), r["canonical_semantic"])
            if key not in seen:
                seen.add(key)
                unique_replacements.append(r)

        return canonical_text, unique_replacements, evidence_spans
