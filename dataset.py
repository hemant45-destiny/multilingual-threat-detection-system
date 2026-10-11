"""
Multilingual Cyber-Threat Benchmark Dataset & Kaggle Integrator.
Supplies realistic training and evaluation samples across English, Hindi, Marathi,
and Code-Mixed Hinglish/Marathlish for all 8 project threat categories.
"""
import os
import json
from typing import List, Dict, Any, Tuple

# Comprehensive benchmark samples representing realistic cyber threat communications
BENCHMARK_DATASET = [
    # ---------------- 1. PHISHING ----------------
    {
        "text": "Dear customer, your bank account access will be terminated today. Verify credentials and update KYC immediately at: http://bit.ly/bank-auth-kyc",
        "category": "phishing",
        "language": "English",
        "source": "email",
        "severity": 0.80
    },
    {
        "text": "Alert: Your netbanking session expired. Click here to re-login and verify your card details: http://secure-banking-login.xyz/portal",
        "category": "phishing",
        "language": "English",
        "source": "sms",
        "severity": 0.80
    },
    {
        "text": "Aapka SBI bank khata aaj hi band ho jayega. Turant kyc update karo aur OTP verify karo is link par: http://bit.ly/sbi-kyc-verify",
        "category": "phishing",
        "language": "Hinglish",
        "source": "sms",
        "severity": 0.85
    },
    {
        "text": "प्रिय ग्राहक, आपका बैंक खाता आज ब्लॉक कर दिया जाएगा। अपना पासवर्ड और ओटीपी तुरंत दर्ज करके खाता चालू रखें: http://bit.ly/bank-hindi-verify",
        "category": "phishing",
        "language": "Hindi",
        "source": "sms",
        "severity": 0.85
    },
    {
        "text": "महत्वाची सूचना: तुमचे बँक खाते आज बंद केले जाईल! दंड टाळण्यासाठी तुमचा पासवर्ड आणि OTP त्वरित पडताळून पहा: http://bit.ly/bank-marathi",
        "category": "phishing",
        "language": "Marathi",
        "source": "sms",
        "severity": 0.85
    },
    {
        "text": "Tumche bank khate thambavle ahe. Atach login kara aani pan card verify kara ya link var: http://cutt.ly/maha-bank-login",
        "category": "phishing",
        "language": "Marathlish",
        "source": "chat",
        "severity": 0.80
    },
    {
        "text": "Income Tax Refund approved! Rs 45,820 deposited. Confirm your debit card CVV and netbanking PIN to claim: http://incometax-refunds-india.top",
        "category": "phishing",
        "language": "English",
        "source": "sms",
        "severity": 0.82
    },
    {
        "text": "Aapko Rs 25,000 ka cash refund mila hai. Turant debit card details daalein aur claim karein: http://rb.gy/tax-refund-claim",
        "category": "phishing",
        "language": "Hinglish",
        "source": "sms",
        "severity": 0.82
    },

    # ---------------- 2. MALWARE ----------------
    {
        "text": "Please find attached the updated corporate vendor invoice Invoice_Sept2026.pdf.exe for your urgent accounting review and settlement.",
        "category": "malware",
        "language": "English",
        "source": "email",
        "severity": 0.90
    },
    {
        "text": "Urgent IT security update: Download and install critical enterprise VPN patch VPN_Client_Update.apk to prevent service interruption.",
        "category": "malware",
        "language": "English",
        "source": "chat",
        "severity": 0.90
    },
    {
        "text": "Is link se free premium recharge app download karo: http://malicious-cdn.xyz/Free_Recharge_Mod.apk aur install karo.",
        "category": "malware",
        "language": "Hinglish",
        "source": "chat",
        "severity": 0.88
    },
    {
        "text": "नवीन कंपनी धोरण आणि वेतनवाढ तपशील पाहण्यासाठी खालील फाइल उघडा: Payroll_Update_2026.vbs त्वरित रन करा.",
        "category": "malware",
        "language": "Marathi",
        "source": "email",
        "severity": 0.90
    },
    {
        "text": "कृपया संलग्न सुरक्षा अपडेट फ़ाइल Security_Patch_v4.bat डाउनलोड करें और अपने सिस्टम पर निष्पादित करें।",
        "category": "malware",
        "language": "Hindi",
        "source": "email",
        "severity": 0.92
    },
    {
        "text": "RedLine Stealer botnet payload detected reaching out to command and control IP 185.220.101.5 on port 8080 with hash a1b2c3d4e5f678901234567890abcdef.",
        "category": "malware",
        "language": "English",
        "source": "threat_feed",
        "severity": 0.94
    },
    {
        "text": "AgentTesla infostealer payload distributed via malicious macro sheet. MD5 hash 5d41402abc4b2a76b9719d911017c592.",
        "category": "malware",
        "language": "English",
        "source": "threat_feed",
        "severity": 0.92
    },

    # ---------------- 3. RANSOMWARE ----------------
    {
        "text": "All your corporate files, databases and backups have been encrypted with LockBit 3.0 military-grade algorithm. Send 5 Bitcoin to decrypt.",
        "category": "ransomware",
        "language": "English",
        "source": "email",
        "severity": 0.98
    },
    {
        "text": "Your servers are locked! Decryptor will only be provided after cryptocurrency transfer. You have 48 hours before private key deletion.",
        "category": "ransomware",
        "language": "English",
        "source": "email",
        "severity": 0.96
    },
    {
        "text": "Aapki saari office files encrypt ho chuki hain. Decrypt karne ke liye 2 BTC transfer karo nahi toh sara confidential data leak ho jayega.",
        "category": "ransomware",
        "language": "Hinglish",
        "source": "chat",
        "severity": 0.96
    },
    {
        "text": "तुमचा सर्व संगणक डेटा कूटबद्ध (encrypted) करण्यात आला आहे. डीक्रिप्टर मिळवण्यासाठी खंडणी रक्कम पाठवा, अन्यथा सर्व डेटा नष्ट केला जाईल.",
        "category": "ransomware",
        "language": "Marathi",
        "source": "email",
        "severity": 0.98
    },
    {
        "text": "आपके सभी दस्तावेज और सर्वर डेटा लॉक कर दिए गए हैं। फिरौती राशि का भुगतान न करने पर सभी फाइलें डार्क वेब पर बेच दी जाएंगी।",
        "category": "ransomware",
        "language": "Hindi",
        "source": "email",
        "severity": 0.96
    },
    {
        "text": "BlackCat ALPHV ransomware operators demand 10 ETH ransom note left in README_RECOVERY.txt following network intrusion.",
        "category": "ransomware",
        "language": "English",
        "source": "threat_feed",
        "severity": 0.95
    },

    # ---------------- 4. SOCIAL ENGINEERING ----------------
    {
        "text": "Hi Team, this is the Chief Executive Officer. I am currently in a confidential executive meeting and need you to process an urgent wire transfer immediately.",
        "category": "social_engineering",
        "language": "English",
        "source": "email",
        "severity": 0.78
    },
    {
        "text": "Urgent from Human Resources: We are updating corporate group medical insurance. Reply with your employee ID and verified mobile number immediately.",
        "category": "social_engineering",
        "language": "English",
        "source": "email",
        "severity": 0.75
    },
    {
        "text": "Bhai main Cyber Crime Cell police station se bol raha hoon. Tumhare khilaf FIR lodge hui hai. Bachna hai toh turant is number par call karo aur settlement fees bhejo.",
        "category": "social_engineering",
        "language": "Hinglish",
        "source": "sms",
        "severity": 0.85
    },
    {
        "text": "नमस्कार, मी नाशिक पोलीस सायबर सेल अधिकारी बोलत आहे. तुमच्या खात्यावर संशयास्पद व्यवहार आढळले आहेत. अटक टाळण्यासाठी त्वरित संपर्क करा.",
        "category": "social_engineering",
        "language": "Marathi",
        "source": "chat",
        "severity": 0.85
    },
    {
        "text": "सावधान: यह सीबीआई विशेष जांच दल का नोटिस है। आपका नाम ऑनलाइन वित्तीय धोखाधड़ी में दर्ज है। कानूनी कार्रवाई से बचने के लिए तुरंत जवाब दें।",
        "category": "social_engineering",
        "language": "Hindi",
        "source": "sms",
        "severity": 0.85
    },
    {
        "text": "Urgent payroll adjustment notice: Due to tax restructuring, send your updated bank routing code and personal phone number to hr-desk@gmail.com.",
        "category": "social_engineering",
        "language": "English",
        "source": "email",
        "severity": 0.76
    },

    # ---------------- 5. CREDENTIAL THEFT ----------------
    {
        "text": "Google Security Alert: Unauthorized login from Russia. Reply to this SMS with the 6-digit verification code sent to your phone to safeguard your account.",
        "category": "credential_theft",
        "language": "English",
        "source": "sms",
        "severity": 0.88
    },
    {
        "text": "Aapka UPI PIN reset kiya ja raha hai. Agar aapne request nahi ki hai toh apna purana PIN aur naya OTP abhi 9823019283 par share karein.",
        "category": "credential_theft",
        "language": "Hinglish",
        "source": "sms",
        "severity": 0.90
    },
    {
        "text": "तुमचा गुप्त UPI पिन आणि मोबाईलवर आलेला OTP त्वरित सामायिक करा, अन्यथा बँक खाते २४ तासांत गोठवले जाईल.",
        "category": "credential_theft",
        "language": "Marathi",
        "source": "sms",
        "severity": 0.90
    },
    {
        "text": "सुरक्षा प्रमाणीकरण: कृपया अपना नेटबैंकिंग उपयोगकर्ता नाम, पासवर्ड और 6-अंकीय ओटीपी तुरंत साझा करें।",
        "category": "credential_theft",
        "language": "Hindi",
        "source": "sms",
        "severity": 0.90
    },
    {
        "text": "Tumcha corporate SSO password aani ERP otp mala WhatsApp var pathva, system access unlock karaycha ahe.",
        "category": "credential_theft",
        "language": "Marathlish",
        "source": "chat",
        "severity": 0.85
    },
    {
        "text": "Microsoft 365 Password Expiry: Your corporate enterprise account password expires in 2 hours. Keep current password by validating at: http://msft-creds-auth.xyz/verify",
        "category": "credential_theft",
        "language": "English",
        "source": "email",
        "severity": 0.88
    },

    # ---------------- 6. VULNERABILITY EXPLOITATION ----------------
    {
        "text": "Active exploitation observed in the wild targeting CVE-2024-3400 affecting Palo Alto PAN-OS GlobalProtect gateway via arbitrary command injection.",
        "category": "vulnerability_exploitation",
        "language": "English",
        "source": "threat_feed",
        "severity": 0.88
    },
    {
        "text": "Proof of concept exploit released for CVE-2023-38606 allowing kernel privilege escalation on Apple iOS and macOS platforms.",
        "category": "vulnerability_exploitation",
        "language": "English",
        "source": "threat_feed",
        "severity": 0.85
    },
    {
        "text": "Hacker forum post selling zero-day remote code execution exploit for Apache HTTP Server 2.4.58 with bypass payload: curl -X POST http://victim/cgi-bin/test.",
        "category": "vulnerability_exploitation",
        "language": "English",
        "source": "threat_feed",
        "severity": 0.92
    },
    {
        "text": "हैकर्स द्वारा संस्थान के वेब सर्वर पर CVE-2021-44228 Log4j भेद्यता का उपयोग करके रिमोट कोड निष्पादन का प्रयास किया गया।",
        "category": "vulnerability_exploitation",
        "language": "Hindi",
        "source": "threat_feed",
        "severity": 0.90
    },
    {
        "text": "संस्थेच्या अंतर्गत फायरवॉलवर CVE-2024-21887 रिमोट कोड एक्झिक्यूशन एक्सप्लॉईटचा हल्ला नोंदवला गेला आहे.",
        "category": "vulnerability_exploitation",
        "language": "Marathi",
        "source": "threat_feed",
        "severity": 0.90
    },

    # ---------------- 7. BENIGN SECURITY DISCUSSION ----------------
    {
        "text": "Dear Team, the updated Q4 Corporate Employee Handbook and Benefits Guide is now published on the official intranet portal at https://enterprise.corp/benefits.",
        "category": "benign_security_discussion",
        "language": "English",
        "source": "email",
        "severity": 0.05
    },
    {
        "text": "Notice: Annual IT asset inventory verification will take place next Tuesday. Please ensure corporate laptops are connected to the enterprise network.",
        "category": "benign_security_discussion",
        "language": "English",
        "source": "email",
        "severity": 0.05
    },
    {
        "text": "Sabhi team members ko suchit kiya jata hai ki All-Hands Quarterly Business Review meeting kal subah 10 baje Main Conference Hall aur Teams par aayojit ki jayegi.",
        "category": "benign_security_discussion",
        "language": "Hinglish",
        "source": "chat",
        "severity": 0.05
    },
    {
        "text": "सर्व कर्मचाऱ्यांना कळविण्यात येते की वार्षिक एंटरप्राइज सुरक्षा आणि अनुपालन प्रशिक्षण पुढील आठवड्यात सुरू होत आहे. उपस्थिती अनिवार्य आहे.",
        "category": "benign_security_discussion",
        "language": "Marathi",
        "source": "email",
        "severity": 0.05
    },
    {
        "text": "सूचना: वार्षिक एंटरप्राइज अनुपालन प्रमाणन पोर्टल सक्रिय कर दिया गया है। सभी कर्मचारी https://enterprise.corp/compliance पर अपना मॉड्यूल पूरा करें।",
        "category": "benign_security_discussion",
        "language": "Hindi",
        "source": "email",
        "severity": 0.05
    },
    {
        "text": "NIST Special Publication 800-30 Rev 1 provides guidelines for conducting risk assessments across federal information systems and organizations.",
        "category": "benign_security_discussion",
        "language": "English",
        "source": "threat_feed",
        "severity": 0.08
    },
    {
        "text": "Official CERT-In advisory issued regarding regular password change best practices and multi-factor authentication implementation.",
        "category": "benign_security_discussion",
        "language": "English",
        "source": "threat_feed",
        "severity": 0.08
    },

    # ---------------- 8. UNKNOWN / UNCERTAIN ----------------
    {
        "text": "Hey check this out bro, saw this interesting stuff online yesterday.",
        "category": "unknown_uncertain",
        "language": "English",
        "source": "chat",
        "severity": 0.25
    },
    {
        "text": "Kaisa chal raha hai sab? Aaj sham ko milte hain canteen ke bahar.",
        "category": "unknown_uncertain",
        "language": "Hinglish",
        "source": "chat",
        "severity": 0.20
    },
    {
        "text": "आजचा दिवस छान आहे. उद्या भेटूया का?",
        "category": "unknown_uncertain",
        "language": "Marathi",
        "source": "chat",
        "severity": 0.20
    },
    {
        "text": "Random alphanumeric query string without context: 9948271049281.",
        "category": "unknown_uncertain",
        "language": "English",
        "source": "chat",
        "severity": 0.30
    }
]

def load_kaggle_or_benchmark_dataset() -> List[Dict[str, Any]]:
    """
    Returns the benchmark training dataset. If external Kaggle datasets exist in local cache,
    they are seamlessly merged into the dataset.
    """
    dataset = list(BENCHMARK_DATASET)
    
    # Check if a custom Kaggle export or additional dataset JSON exists
    custom_dataset_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kaggle_curated_data.json")
    if os.path.exists(custom_dataset_path):
        try:
            with open(custom_dataset_path, "r", encoding="utf-8") as f:
                extra = json.load(f)
                if isinstance(extra, list):
                    dataset.extend(extra)
        except Exception:
            pass

    return dataset

def add_curated_sample(item: Dict[str, Any]) -> int:
    """
    Allows Threat Researchers to dynamically curate and save new samples to the dataset.
    """
    custom_dataset_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kaggle_curated_data.json")
    existing = []
    if os.path.exists(custom_dataset_path):
        try:
            with open(custom_dataset_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []
            
    existing.append(item)
    with open(custom_dataset_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)
    return len(existing)
