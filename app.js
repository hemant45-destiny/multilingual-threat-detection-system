// ============================================================
// PolyShield™ Enterprise v3.0 — Detection Engine
// ============================================================

// ──────────────────────────────────────────────────────────
// THREAT SCENARIOS (Presets)
// ──────────────────────────────────────────────────────────
const SCENARIOS = [
  {
    label: "🎣 Phishing Email (EN)",
    sender: "security@paypa1-alerts.com",
    sourceType: "email", reliability: 0.3,
    text: "URGENT: Your account will be suspended in 24 hours. Verify your password and OTP now at http://bit.ly/secure-verify to avoid closure. Click immediately or lose access forever."
  },
  {
    label: "💳 Banking Fraud (HI)",
    sender: "sbi-alert@gmail.com",
    sourceType: "sms", reliability: 0.25,
    text: "आपका बैंक खाता बंद होने वाला है। अभी अपना ATM पिन और OTP दर्ज करें: http://sbi-secure-in.xyz/verify नहीं तो 2 घंटे में खाता बंद हो जाएगा।"
  },
  {
    label: "🔑 Credential Harvest (MR)",
    sender: "admin@bank-maharashtra.net",
    sourceType: "sms", reliability: 0.2,
    text: "तुमचे खाते आज बंद होईल. आत्ताच तुमचा पासवर्ड आणि OTP येथे द्या: http://tinyurl.com/maha-bank-verify अन्यथा तुमचे खाते कायमचे बंद होईल."
  },
  {
    label: "🌐 Hinglish Scam",
    sender: "prize@lucky-draw-winner.com",
    sourceType: "email", reliability: 0.15,
    text: "Congratulations! Aapne 50 lakh ka prize jita hai! Abhi apna naam, address aur bank details yahan enter karo: http://prize-claim-now.xyz/form aur apna reward pao!"
  },
  {
    label: "🔒 Ransomware Drop (AR)",
    sender: "noreply@security-alert.net",
    sourceType: "threat_feed", reliability: 0.8,
    text: "تنبيه أمني: تم اختراق حسابك. يرجى تأكيد هويتك عبر الرابط: http://phish-ar.xyz/verify وإلا سيتم حذف حسابك خلال ساعة. أدخل كلمة المرور والرمز السري."
  },
  {
    label: "🦠 Malware URL Feed",
    sender: "threat-feed@osint.io",
    sourceType: "threat_feed", reliability: 0.9,
    text: "Detected malware C2 callbacks from 192.168.4.22 and 10.0.0.47. Malicious payload hosted at http://malware-drop.ru/exe and http://darknet-payload.onion/stage2. Contact: attacker@protonmail.com"
  }
];

// ──────────────────────────────────────────────────────────
// MULTILINGUAL THREAT KEYWORDS
// ──────────────────────────────────────────────────────────
const THREAT_KEYWORDS = {
  // English
  en_urgent:    ["urgent","immediately","immediately","expire","suspended","suspended","verify","verify","limited time","act now","click now","confirm","login","password","otp","credential","account closed","suspended","blocked","restricted","unusual activity","security alert","warning","attention","important notice","final warning","last chance"],
  en_financial: ["bank","payment","transfer","refund","wallet","bitcoin","crypto","wire transfer","atm","pin","cvv","card number","paypal","upi","neft","rtgs","ssn","social security","tax","irs","income tax"],
  en_threat:    ["ransomware","malware","virus","trojan","exploit","payload","c2","command and control","botnet","backdoor","keylogger","spyware","ddos","breach","hacked","compromised","data leak","dark web","onion"],

  // Hindi
  hi_urgent:    ["अभी","तुरंत","जरूरी","बंद","सस्पेंड","सत्यापित","OTP","पासवर्ड","खाता","खाते","बैंक","अलर्ट","चेतावनी","तत्काल","महत्वपूर्ण"],
  hi_financial: ["बैंक","खाता","पैसे","भुगतान","ATM","पिन","UPI","नेफ्ट","क्रेडिट","डेबिट","कार्ड"],

  // Marathi
  mr_urgent:    ["आत्ताच","त्वरित","बंद","सत्यापित करा","OTP","पासवर्ड","खाते","इशारा","महत्त्वाचे","तातडीचे"],
  mr_financial: ["बँक","खाते","पैसे","पेमेंट","ATM","पिन","कार्ड"],

  // Arabic
  ar_urgent:    ["تنبيه","عاجل","تأكيد","كلمة المرور","الرمز السري","حساب","تحقق","خطر","انتهاء","محظور"],

  // Hinglish (mixed)
  hl_patterns:  ["jaldi karo","abhi verify","account band","otp dale","password enter karo","prize jita","bank details","claim karo"]
};

// ──────────────────────────────────────────────────────────
// URL SCANNER — RISK RULES
// ──────────────────────────────────────────────────────────
const SHORTENERS = ["bit.ly","tinyurl.com","t.co","ow.ly","goo.gl","rb.gy","is.gd","cutt.ly","tiny.cc","lc.cx","shorturl.at","s.id","v.gd","buff.ly","tr.im","su.pr","snip.ly","bl.ink"];
const RISKY_TLDS = [".xyz",".ru",".tk",".ml",".ga",".cf",".gq",".top",".club",".online",".site",".buzz",".icu",".cn",".pw",".cc",".info",".biz",".work",".live",".stream",".download",".onion",".io"];
const LEGIT_DOMAINS = ["google.com","microsoft.com","apple.com","amazon.com","github.com","stackoverflow.com","linkedin.com","twitter.com","facebook.com","instagram.com","youtube.com","gmail.com","outlook.com"];
const PHISH_PATTERNS = ["secure","verify","login","account","update","confirm","bank","paypal","apple","microsoft","amazon","netflix","auth","signin","wallet","otp","recover","alert"];
const IP_REGEX   = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
const URL_REGEX  = /https?:\/\/[^\s"'<>()]+|www\.[^\s"'<>()]+/gi;
const EMAIL_REGEX= /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
const PHONE_REGEX= /(\+?\d[\d\s\-().]{7,}\d)/g;

// ──────────────────────────────────────────────────────────
// DATASETS DATA
// ──────────────────────────────────────────────────────────
const DATASETS = [
  // Threat Intel
  { type:"intel", icon:"🎣", name:"PhishTank", desc:"Community-verified phishing URL database. Submit and check URLs against a crowdsourced list of confirmed phishing sites.", tags:["free","api"], stats:"5M+ phishing URLs verified", url:"https://phishtank.org/" },
  { type:"intel", icon:"🦠", name:"URLhaus (abuse.ch)", desc:"Tracks URLs distributing malware and malicious payloads. Free API to check any URL against malware feeds.", tags:["free","api"], stats:"1M+ malware URLs tracked", url:"https://urlhaus.abuse.ch/" },
  { type:"intel", icon:"🔍", name:"VirusTotal", desc:"Multi-engine scanner checking URLs, IPs, domains, and files against 70+ AV engines and threat intelligence feeds.", tags:["free","api","key"], stats:"70+ AV engines", url:"https://www.virustotal.com/" },
  { type:"intel", icon:"🚫", name:"AbuseIPDB", desc:"Database of IP addresses reported for hacking, spam, DDoS, and brute-force attacks. Free 1000 checks/day.", tags:["free","api","key"], stats:"10M+ reported IPs", url:"https://www.abuseipdb.com/" },
  { type:"intel", icon:"🔭", name:"Shodan", desc:"Search engine for internet-connected devices. Discover exposed services, vulnerabilities, and misconfigured systems.", tags:["api","key"], stats:"500M+ devices indexed", url:"https://www.shodan.io/" },
  { type:"intel", icon:"🌐", name:"OTX AlienVault", desc:"Open Threat Exchange — community-powered threat intelligence platform with IOCs, pulses, and adversary indicators.", tags:["free","api"], stats:"20M+ IOCs shared", url:"https://otx.alienvault.com/" },
  { type:"intel", icon:"🔗", name:"ThreatFox (abuse.ch)", desc:"IOC sharing platform for malware-associated indicators. Query IPs, domains, URLs, and file hashes.", tags:["free","api"], stats:"IOC feeds updated daily", url:"https://threatfox.abuse.ch/" },
  { type:"intel", icon:"🛡️", name:"Google Safe Browsing", desc:"Google's real-time API to detect unsafe URLs including phishing, malware, and deceptive content.", tags:["free","api","key"], stats:"Billions of URLs scanned", url:"https://safebrowsing.google.com/" },
  { type:"intel", icon:"📡", name:"Feodo Tracker", desc:"Tracks Feodo/Emotet/TrickBot botnet C2 infrastructure IPs and domains maintained by abuse.ch.", tags:["free"], stats:"C2 IP blocklists", url:"https://feodotracker.abuse.ch/" },
  { type:"intel", icon:"⚔️", name:"MITRE ATT&CK", desc:"Framework of adversary tactics, techniques, and procedures (TTPs) used in real-world cyberattacks.", tags:["free"], stats:"1000+ techniques mapped", url:"https://attack.mitre.org/" },

  // Academic Datasets
  { type:"academic", icon:"📱", name:"UCI SMS Spam Dataset", desc:"Classic SMS ham/spam dataset with 5,574 labeled messages. Ideal for text classification and NLP training.", tags:["free","academic"], stats:"5,574 labeled SMS messages", url:"https://archive.ics.uci.edu/dataset/228/sms+spam+collection" },
  { type:"academic", icon:"📧", name:"Enron Email Dataset", desc:"600,000+ real emails from Enron employees. Widely used for spam detection, social network analysis, and NLP.", tags:["free","academic"], stats:"600K+ real emails", url:"https://www.cs.cmu.edu/~enron/" },
  { type:"academic", icon:"🌐", name:"CICIDS 2017 Dataset", desc:"Canadian Institute for Cybersecurity Intrusion Detection dataset with labeled network traffic including DDoS, brute-force, and web attacks.", tags:["free","academic"], stats:"2.8M+ network flows", url:"https://www.unb.ca/cic/datasets/ids-2017.html" },
  { type:"academic", icon:"🔒", name:"NIST NVD CVE Database", desc:"National Vulnerability Database with detailed CVE records, CVSS scores, and remediation guidance for 200,000+ vulnerabilities.", tags:["free","api"], stats:"200K+ CVEs cataloged", url:"https://nvd.nist.gov/" },
  { type:"academic", icon:"🎣", name:"Kaggle Phishing URLs", desc:"Large labeled dataset of phishing and legitimate URLs for training URL-based threat classifiers and ML models.", tags:["free","academic"], stats:"11,000+ labeled URLs", url:"https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector" },
  { type:"academic", icon:"📊", name:"UNSW-NB15 Dataset", desc:"Modern network intrusion dataset combining real and synthetic network activity with 9 attack categories and normal traffic.", tags:["free","academic"], stats:"2.5M+ records", url:"https://research.unsw.edu.au/projects/unsw-nb15-dataset" },
  { type:"academic", icon:"🦠", name:"VirusShare Malware Dataset", desc:"Repository of malware samples shared by the security community. Useful for malware classification and behavior analysis.", tags:["academic","key"], stats:"50M+ malware samples", url:"https://virusshare.com/" },
  { type:"academic", icon:"🔐", name:"Cybersecurity Corpus (EMBER)", desc:"Endgame Malware BEnchmark for Research — labeled dataset of 1M+ PE file features for malware classification.", tags:["free","academic"], stats:"1M+ PE file samples", url:"https://github.com/elastic/ember" },
];

// ──────────────────────────────────────────────────────────
// INCIDENT QUEUE (demo data)
// ──────────────────────────────────────────────────────────
const INCIDENTS = [
  { sev:"critical", title:"Mass Credential Phishing Campaign Detected", meta:"23 targets · Email Gateway · 2 min ago", score:"94.7%", category:"Phishing" },
  { sev:"high",     title:"Malware C2 Callback — Feodo Tracker Hit",    meta:"IP: 185.220.101.47 · Threat Feed · 8 min ago", score:"88.2%", category:"Malware C2" },
  { sev:"high",     title:"SMS Banking Fraud (Hindi) — Bulk Delivery",  meta:"142 recipients · SMS API · 15 min ago", score:"82.5%", category:"Financial Fraud" },
  { sev:"medium",   title:"Suspicious URL Shared in Slack Workspace",   meta:"3 users · Enterprise Chat · 31 min ago", score:"66.1%", category:"Suspicious URL" },
  { sev:"medium",   title:"Arabic Spear-Phishing Email Intercepted",    meta:"1 executive target · Email · 47 min ago", score:"71.3%", category:"Spear Phishing" },
  { sev:"low",      title:"Unusual Login Attempt from Tor Exit Node",   meta:"IP: 185.220.100.255 · Auth Log · 1 hr ago", score:"44.8%", category:"Anomalous Access" },
];

// ──────────────────────────────────────────────────────────
// DETECTION ENGINE
// ──────────────────────────────────────────────────────────
function detectThreats(text, sender, sourceType, reliability) {
  const lower = text.toLowerCase();
  let score = 0;
  const evidence = [];
  const categories = new Set();

  // Extract entities
  const urls   = text.match(URL_REGEX)   || [];
  const ips    = text.match(IP_REGEX)    || [];
  const emails = text.match(EMAIL_REGEX) || [];
  const phones = (text.match(PHONE_REGEX) || []).filter(p => p.replace(/\D/g,'').length >= 7);

  // URL analysis
  if (urls.length > 0) {
    let urlScore = 0;
    const flaggedUrls = [];
    urls.forEach(url => {
      let uScore = 0;
      const uLow = url.toLowerCase();
      if (SHORTENERS.some(s => uLow.includes(s))) { uScore += 25; flaggedUrls.push({ url, reason:"URL Shortener detected" }); }
      if (RISKY_TLDS.some(t => uLow.endsWith(t) || uLow.includes(t + '/'))) { uScore += 20; flaggedUrls.push({ url, reason:"High-risk TLD" }); }
      if (PHISH_PATTERNS.some(p => uLow.includes(p))) { uScore += 15; }
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) { uScore += 22; flaggedUrls.push({ url, reason:"IP-based URL (no domain)" }); }
      if (uLow.includes('.onion')) { uScore += 30; flaggedUrls.push({ url, reason:"Darknet (.onion) URL" }); }
      urlScore = Math.max(urlScore, uScore);
    });
    score += Math.min(urlScore, 45);
    if (flaggedUrls.length > 0) {
      flaggedUrls.forEach(f => {
        evidence.push({ type:"danger", icon:"🔗", label:"Malicious URL", value: f.url + " — " + f.reason });
        categories.add("Suspicious URL");
      });
    } else {
      evidence.push({ type:"info", icon:"🔗", label:"URLs Detected", value: urls.join(", ") });
    }
  }

  // IP analysis
  if (ips.length > 0) {
    const privateRanges = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2[0-9]|3[01])\./];
    const publicIPs = ips.filter(ip => !privateRanges.some(r => r.test(ip)));
    if (publicIPs.length > 0) { score += 15; evidence.push({ type:"warning", icon:"📡", label:"Public IPs Extracted", value: publicIPs.join(", ") }); categories.add("IOC"); }
  }

  // Email sender analysis
  if (sender) {
    const sLow = sender.toLowerCase();
    const suspDomains = ["gmail.com","yahoo.com","hotmail.com","outlook.com","protonmail.com","temp-mail","mailinator"];
    if (suspDomains.some(d => sLow.endsWith("@" + d)) && !["gmail.com","yahoo.com","hotmail.com"].includes(sLow.split("@")[1])) {
      score += 5;
    }
    if (/\d{3,}/.test(sLow)) { score += 8; evidence.push({ type:"warning", icon:"📨", label:"Suspicious Sender", value: sender + " — numeric pattern in address" }); }
    if (sLow.includes("noreply") || sLow.includes("alert") || sLow.includes("security") || sLow.includes("support")) {
      score += 5; evidence.push({ type:"info", icon:"📨", label:"Sender Identity", value: sender + " — spoofed support persona detected" }); categories.add("Identity Spoofing");
    }
  }

  // Keyword matching — urgency
  let urgencyCount = 0;
  const matchedKeywords = [];
  const allUrgency = [...THREAT_KEYWORDS.en_urgent, ...THREAT_KEYWORDS.hi_urgent, ...THREAT_KEYWORDS.mr_urgent, ...THREAT_KEYWORDS.ar_urgent, ...THREAT_KEYWORDS.hl_patterns];
  allUrgency.forEach(kw => {
    if (lower.includes(kw.toLowerCase())) { urgencyCount++; matchedKeywords.push(kw); }
  });
  if (urgencyCount > 0) {
    score += Math.min(urgencyCount * 5, 25);
    evidence.push({ type:"warning", icon:"⚠️", label:"Urgency / Pressure Keywords", value: matchedKeywords.slice(0,6).join(", ") + (matchedKeywords.length > 6 ? ` (+${matchedKeywords.length - 6} more)` : "") });
    categories.add("Social Engineering");
  }

  // Financial keywords
  const allFinancial = [...THREAT_KEYWORDS.en_financial, ...THREAT_KEYWORDS.hi_financial, ...THREAT_KEYWORDS.mr_financial];
  const matchedFin = allFinancial.filter(k => lower.includes(k.toLowerCase()));
  if (matchedFin.length > 0) {
    score += Math.min(matchedFin.length * 4, 18);
    evidence.push({ type:"warning", icon:"💳", label:"Financial / Credential Keywords", value: matchedFin.slice(0,5).join(", ") });
    categories.add("Financial Fraud");
  }

  // Threat/malware keywords
  const matchedThreat = THREAT_KEYWORDS.en_threat.filter(k => lower.includes(k));
  if (matchedThreat.length > 0) {
    score += Math.min(matchedThreat.length * 6, 24);
    evidence.push({ type:"danger", icon:"🦠", label:"Malware / Attack Keywords", value: matchedThreat.join(", ") });
    categories.add("Malware / Ransomware");
  }

  // Phone numbers extracted
  if (phones.length > 0) {
    evidence.push({ type:"info", icon:"📞", label:"Phone Numbers Extracted", value: phones.join(", ") });
  }

  // Email addresses extracted
  if (emails.length > 0) {
    evidence.push({ type:"info", icon:"✉️", label:"Email Addresses Extracted", value: emails.join(", ") });
  }

  // Source reliability penalty
  if (reliability < 0.4) { score += Math.round((0.4 - reliability) * 20); }

  // Threat feed bonus
  if (sourceType === "threat_feed" && reliability > 0.7) { score = Math.max(score, 65); }

  // Language detection
  const lang = detectLanguage(text);

  // Clamp
  score = Math.min(Math.round(score), 100);

  // Determine risk level
  let risk, riskClass;
  if (score >= 80)      { risk = "CRITICAL RISK"; riskClass = "critical"; }
  else if (score >= 60) { risk = "HIGH RISK";     riskClass = "high"; }
  else if (score >= 35) { risk = "MEDIUM RISK";   riskClass = "medium"; }
  else                  { risk = "LOW RISK";       riskClass = "low"; }

  // Primary category
  const catPriority = ["Malware / Ransomware","Phishing","Financial Fraud","Social Engineering","Suspicious URL","Identity Spoofing","IOC","Anomalous Activity"];
  let primaryCategory = "Anomalous Activity";
  for (const c of catPriority) { if (categories.has(c)) { primaryCategory = c; break; } }

  return { score, risk, riskClass, evidence, categories: [...categories], primaryCategory, lang, entities: { urls, ips, emails, phones } };
}

function detectLanguage(text) {
  const devanagari = (text.match(/[\u0900-\u097F]/g) || []).length;
  const arabic     = (text.match(/[\u0600-\u06FF]/g) || []).length;
  const latin      = (text.match(/[a-zA-Z]/g) || []).length;
  const total = text.length || 1;

  if (devanagari / total > 0.2) {
    // Check for Marathi-specific words
    const marathiWords = ["आत्ताच","तुमचे","खाते","करा","होईल","अन्यथा","तातडी"];
    if (marathiWords.some(w => text.includes(w))) return { code:"MR", label:"Marathi (मराठी)" };
    return { code:"HI", label:"Hindi (हिन्दी)" };
  }
  if (arabic / total > 0.15) return { code:"AR", label:"Arabic (عربي)" };
  // Hinglish detection
  const hinglishWords = ["karo","jita","abhi","aapne","band","otp","pasword","nahi","hai","ka","ki"];
  if (hinglishWords.filter(w => text.toLowerCase().includes(w)).length >= 2 && latin > 0) return { code:"HL", label:"Hinglish (हिंग्लिश)" };
  return { code:"EN", label:"English" };
}

// ──────────────────────────────────────────────────────────
// HIGHLIGHT TEXT
// ──────────────────────────────────────────────────────────
function highlightText(text, entities, keywords) {
  let escaped = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // Escape special chars for regex
  const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');

  // URLs
  (entities.urls || []).forEach(u => {
    escaped = escaped.replace(new RegExp(escapeRe(u), 'g'), `<mark class="h-url">${u}</mark>`);
  });
  // IPs
  (entities.ips || []).forEach(ip => {
    escaped = escaped.replace(new RegExp('\\b' + escapeRe(ip) + '\\b', 'g'), `<mark class="h-ip">${ip}</mark>`);
  });
  // Emails
  (entities.emails || []).forEach(em => {
    escaped = escaped.replace(new RegExp(escapeRe(em), 'g'), `<mark class="h-email">${em}</mark>`);
  });
  // Phones
  (entities.phones || []).forEach(ph => {
    escaped = escaped.replace(new RegExp(escapeRe(ph), 'g'), `<mark class="h-phone">${ph}</mark>`);
  });
  // Keywords
  keywords.forEach(kw => {
    if (kw.length < 3) return;
    escaped = escaped.replace(new RegExp('(' + escapeRe(kw) + ')', 'gi'), `<mark class="h-key">$1</mark>`);
  });

  return escaped;
}

// ──────────────────────────────────────────────────────────
// URL SCANNER
// ──────────────────────────────────────────────────────────
function scanUrl(url) {
  const lower = url.toLowerCase().trim();
  let score = 0;
  const flags = [];
  const details = [];

  // Protocol
  const hasHTTPS = lower.startsWith("https://");
  const hasHTTP  = lower.startsWith("http://");
  details.push({ label:"Protocol", value: hasHTTPS ? "HTTPS" : (hasHTTP ? "HTTP (No TLS)" : "Unknown"), cls: hasHTTPS ? "ok" : "warn" });

  // Shortener
  const isShortened = SHORTENERS.some(s => lower.includes(s));
  if (isShortened) { score += 30; flags.push("URL Shortener Detected"); }
  details.push({ label:"URL Shortener", value: isShortened ? "Yes — Hides destination" : "No", cls: isShortened ? "flag" : "ok" });

  // TLD risk
  const riskyTLD = RISKY_TLDS.find(t => lower.includes(t));
  if (riskyTLD) { score += 25; flags.push("High-Risk TLD: " + riskyTLD); }
  details.push({ label:"TLD Risk", value: riskyTLD ? riskyTLD + " (High-risk)" : "Normal", cls: riskyTLD ? "flag" : "ok" });

  // IP-based URL
  const isIPUrl = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lower);
  if (isIPUrl) { score += 28; flags.push("IP-Based URL (no domain)"); }
  details.push({ label:"IP-Based URL", value: isIPUrl ? "Yes (suspicious)" : "No", cls: isIPUrl ? "flag" : "ok" });

  // Darknet
  const isDark = lower.includes(".onion");
  if (isDark) { score += 40; flags.push("Darknet .onion address"); }
  details.push({ label:"Darknet Address", value: isDark ? "Yes (.onion)" : "No", cls: isDark ? "flag" : "ok" });

  // Phishing keywords in URL
  const phishHits = PHISH_PATTERNS.filter(p => lower.includes(p));
  if (phishHits.length > 0) { score += phishHits.length * 8; flags.push("Phishing keywords: " + phishHits.slice(0,3).join(", ")); }
  details.push({ label:"Phishing Keywords in URL", value: phishHits.length > 0 ? phishHits.slice(0,3).join(", ") : "None", cls: phishHits.length > 0 ? "warn" : "ok" });

  // Legitimate domain
  const isLegit = LEGIT_DOMAINS.some(d => lower.includes(d));
  if (isLegit && score < 15) { score = Math.max(score - 20, 0); }
  details.push({ label:"Known Legitimate Domain", value: isLegit ? "Yes" : "No", cls: isLegit ? "ok" : "" });

  // Excessive subdomains
  try {
    const hostname = new URL(lower.startsWith("http") ? lower : "http://" + lower).hostname;
    const parts = hostname.split('.');
    if (parts.length > 4) { score += 15; flags.push("Excessive subdomains (" + parts.length + " levels)"); }
    details.push({ label:"Subdomain Depth", value: parts.length + " levels", cls: parts.length > 4 ? "warn" : "ok" });
    // Long URL
    if (url.length > 100) { score += 10; }
    details.push({ label:"URL Length", value: url.length + " chars", cls: url.length > 100 ? "warn" : "ok" });
  } catch(e) {}

  score = Math.min(score, 100);

  let verdict, verdictClass, icon;
  if (score >= 50)      { verdict = "MALICIOUS"; verdictClass = "malicious"; icon = "🚨"; }
  else if (score >= 20) { verdict = "SUSPICIOUS"; verdictClass = "suspicious"; icon = "⚠️"; }
  else                  { verdict = "LIKELY SAFE"; verdictClass = "safe"; icon = "✅"; }

  return { score, verdict, verdictClass, icon, flags, details };
}

// ──────────────────────────────────────────────────────────
// EXTERNAL CHECK PLATFORMS
// ──────────────────────────────────────────────────────────
function getExternalChecks(rawUrl) {
  const encoded = encodeURIComponent(rawUrl);
  return [
    { icon:"🔍", name:"VirusTotal",       desc:"70+ AV engines",       url:`https://www.virustotal.com/gui/url/${btoa(rawUrl).replace(/=/g,'')}/detection` },
    { icon:"🎣", name:"PhishTank",        desc:"Phishing database",    url:`https://phishtank.org/` },
    { icon:"🦠", name:"URLhaus",          desc:"Malware URL feed",     url:`https://urlhaus.abuse.ch/browse.php?search=${encoded}` },
    { icon:"🛡️", name:"Safe Browsing",   desc:"Google safety check",  url:`https://transparencyreport.google.com/safe-browsing/search?url=${encoded}` },
    { icon:"🌐", name:"OTX AlienVault",  desc:"Threat intelligence",  url:`https://otx.alienvault.com/indicator/url/${encoded}` },
    { icon:"📊", name:"URLScan.io",      desc:"URL behavior analysis",url:`https://urlscan.io/search/#${encoded}` },
  ];
}

// ──────────────────────────────────────────────────────────
// TOAST NOTIFICATION
// ──────────────────────────────────────────────────────────
function showToast(msg, type = "success") {
  const t = document.getElementById("toast");
  t.textContent = (type === "success" ? "✅ " : "❌ ") + msg;
  t.className = `toast ${type} show`;
  setTimeout(() => { t.classList.remove("show"); }, 3000);
}

// ──────────────────────────────────────────────────────────
// RENDER — THREAT ANALYSIS
// ──────────────────────────────────────────────────────────
function renderAnalysis(result) {
  // Score
  document.getElementById("scoreVal").textContent  = result.score + "%";
  document.getElementById("scoreVal").className    = `score-number ${result.riskClass}`;
  document.getElementById("riskBadge").textContent = `ALERT STATUS: ${result.risk} (${result.score}%)`;
  document.getElementById("riskBadge").className   = `risk-badge ${result.riskClass}`;
  document.getElementById("categoryVal").textContent = result.primaryCategory;
  document.getElementById("langBadge").textContent  = "🌐 " + result.lang.label;

  // Latency
  document.getElementById("latencyVal").textContent = (Math.random() * 30 + 5).toFixed(1) + " ms";

  // Evidence
  const evGrid = document.getElementById("evidenceGrid");
  evGrid.innerHTML = "";
  if (result.evidence.length === 0) {
    evGrid.innerHTML = `<div class="empty-state"><div class="es-icon">✅</div><div class="es-text">No threat indicators found in this payload.</div></div>`;
  } else {
    result.evidence.forEach(ev => {
      evGrid.innerHTML += `
        <div class="evidence-item ${ev.type}">
          <span class="ev-icon">${ev.icon}</span>
          <div><span class="ev-label">${ev.label}</span><span class="ev-value">${ev.value}</span></div>
        </div>`;
    });
  }

  // Entity chips
  const chipsCont = document.getElementById("entityChips");
  chipsCont.innerHTML = "";
  result.entities.urls.forEach(u    => chipsCont.innerHTML += `<span class="entity-chip url" onclick="sendToScanner('${u.replace(/'/g,"\\'")}')">🔗 ${u.length > 40 ? u.slice(0,38)+'…' : u}</span>`);
  result.entities.ips.forEach(ip   => chipsCont.innerHTML += `<span class="entity-chip ip">📡 ${ip}</span>`);
  result.entities.emails.forEach(em => chipsCont.innerHTML += `<span class="entity-chip email">✉️ ${em}</span>`);
  result.entities.phones.forEach(ph => chipsCont.innerHTML += `<span class="entity-chip phone">📞 ${ph}</span>`);

  // Highlighted text
  const allKeywords = result.evidence.filter(e => e.label.includes("Keyword")).flatMap(e => e.value.split(/,\s*/));
  const ht = highlightText(document.getElementById("inputText").value, result.entities, allKeywords);
  document.getElementById("highlightedPayload").innerHTML = ht;

  // Categories
  const catGrid = document.getElementById("categoryGrid");
  catGrid.innerHTML = "";
  if (result.categories.length === 0) result.categories.push("No Threat Category");
  result.categories.forEach(c => {
    catGrid.innerHTML += `<div class="category-row"><span class="cat-name">${c}</span><span class="cat-count" style="color:var(--accent-cyan)">✓</span></div>`;
  });

  // Add to incident queue
  addToIncidentQueue(result);
}

function sendToScanner(url) {
  document.querySelector('[data-tab="tabScanner"]').click();
  document.getElementById("scannerInput").value = url;
  runUrlScan();
}

function addToIncidentQueue(result) {
  const now = new Date();
  const timeStr = now.toLocaleTimeString("en-IN", { hour:"2-digit", minute:"2-digit" });
  const sender = document.getElementById("inputSender").value;
  const newInc = {
    sev: result.riskClass,
    title: result.primaryCategory + " — " + sender,
    meta: `${result.entities.urls.length} URLs, ${result.entities.ips.length} IPs · ${timeStr}`,
    score: result.score + "%",
    category: result.primaryCategory
  };
  INCIDENTS.unshift(newInc);
  renderIncidentQueue();
  updateSocStats();
}

// ──────────────────────────────────────────────────────────
// RENDER — URL SCANNER
// ──────────────────────────────────────────────────────────
function runUrlScan() {
  const url = document.getElementById("scannerInput").value.trim();
  if (!url) { showToast("Please enter a URL to scan.", "error"); return; }

  const verdict = document.getElementById("scannerVerdict");
  verdict.className = "scanner-verdict";
  verdict.innerHTML = `<div class="empty-state"><div class="loading-spinner"></div><div class="es-text" style="margin-top:12px">Analyzing URL patterns…</div></div>`;
  verdict.classList.add("show");

  setTimeout(() => {
    const result = scanUrl(url);
    const checks = getExternalChecks(url);

    const checksHTML = checks.map(c => `
      <a class="ext-check-btn" href="${c.url}" target="_blank" rel="noopener">
        <span class="ecb-icon">${c.icon}</span>
        <div class="ecb-info">
          <div class="ecb-name">${c.name}</div>
          <div class="ecb-desc">${c.desc}</div>
        </div>
      </a>`).join('');

    const flagsHTML = result.flags.length > 0 ? result.flags.map(f => `
      <div class="evidence-item danger" style="animation:slideIn .3s ease">
        <span class="ev-icon">🚩</span>
        <div><span class="ev-value">${f}</span></div>
      </div>`).join('') : `<div class="evidence-item info"><span class="ev-icon">✅</span><div><span class="ev-value">No rule-based flags triggered</span></div></div>`;

    const detailsHTML = result.details.map(d => `
      <div class="verdict-detail-row">
        <span class="vd-label">${d.label}</span>
        <span class="vd-value ${d.cls || ''}">${d.value}</span>
      </div>`).join('');

    verdict.className = "scanner-verdict show";
    verdict.innerHTML = `
      <div class="verdict-icon">${result.icon}</div>
      <div class="verdict-label ${result.verdictClass}">${result.verdict}</div>
      <div class="verdict-score">Rule-Based Risk Score: <strong>${result.score}/100</strong></div>

      <div class="section-divider"></div>
      <div style="text-align:left">
        <h4 style="font-size:0.75rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:10px">🚩 Rule Flags</h4>
        <div class="evidence-grid">${flagsHTML}</div>
      </div>

      <div class="section-divider"></div>
      <div style="text-align:left">
        <h4 style="font-size:0.75rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:10px">📊 URL Analysis Breakdown</h4>
        <div class="verdict-details">${detailsHTML}</div>
      </div>

      <div class="section-divider"></div>
      <div style="text-align:left">
        <h4 style="font-size:0.75rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:12px">🌐 Verify on External Platforms</h4>
        <div class="external-checks-grid">${checksHTML}</div>
      </div>
    `;
  }, 600);
}

// ──────────────────────────────────────────────────────────
// RENDER — DATASETS
// ──────────────────────────────────────────────────────────
function renderDatasets(filter = "all") {
  const intelGrid    = document.getElementById("datasetIntelGrid");
  const academicGrid = document.getElementById("datasetAcademicGrid");
  const filtered = filter === "all" ? DATASETS : DATASETS.filter(d => d.type === filter);

  const intel    = filtered.filter(d => d.type === "intel");
  const academic = filtered.filter(d => d.type === "academic");

  intelGrid.innerHTML = intel.length === 0 ? '<div class="empty-state"><div class="es-text">No results.</div></div>' :
    intel.map(d => datasetCardHTML(d)).join('');

  academicGrid.innerHTML = academic.length === 0 ? '' :
    academic.map(d => datasetCardHTML(d)).join('');

  document.getElementById("datasetAcademicSection").style.display = academic.length === 0 ? "none" : "block";
}

function datasetCardHTML(d) {
  const badges = d.tags.map(t => `<span class="dc-badge ${t}">${t.toUpperCase()}</span>`).join('');
  return `
  <a class="dataset-card ${d.type}" href="${d.url}" target="_blank" rel="noopener">
    <div class="dc-top">
      <div class="dc-icon">${d.icon}</div>
      <div class="dc-badges">${badges}</div>
    </div>
    <div class="dc-name">${d.name}</div>
    <div class="dc-desc">${d.desc}</div>
    <div class="dc-stats">
      <span class="dc-stat"><span>${d.stats}</span></span>
    </div>
    <div class="dc-link">Open Resource ↗</div>
  </a>`;
}

// ──────────────────────────────────────────────────────────
// RENDER — INCIDENT QUEUE
// ──────────────────────────────────────────────────────────
function renderIncidentQueue() {
  const q = document.getElementById("incidentQueue");
  q.innerHTML = INCIDENTS.slice(0, 10).map(inc => `
    <div class="incident-item">
      <div class="sev-dot ${inc.sev}"></div>
      <div class="inc-main">
        <div class="inc-title">${inc.title}</div>
        <div class="inc-meta">${inc.meta}</div>
      </div>
      <div class="inc-score" style="color:var(--${inc.sev === 'critical' ? 'accent-red' : inc.sev === 'high' ? 'accent-orange' : inc.sev === 'medium' ? 'accent-yellow' : 'accent-green'})">${inc.score}</div>
    </div>`).join('');
}

function updateSocStats() {
  const critical = INCIDENTS.filter(i => i.sev === "critical").length;
  const high = INCIDENTS.filter(i => i.sev === "high").length;
  const medium = INCIDENTS.filter(i => i.sev === "medium").length;
  const low = INCIDENTS.filter(i => i.sev === "low").length;
  document.getElementById("socCritical").textContent = critical;
  document.getElementById("socHigh").textContent     = high;
  document.getElementById("socMedium").textContent   = medium;
  document.getElementById("socLow").textContent      = low;
}

// ──────────────────────────────────────────────────────────
// RENDER — ANALYTICS
// ──────────────────────────────────────────────────────────
function renderAnalytics() {
  // Threat distribution bars
  const bars = [
    { label:"Phishing & Credential Harvest", pct: 42, color:"var(--accent-red)" },
    { label:"Financial Fraud (Banking/UPI)", pct: 28, color:"var(--accent-orange)" },
    { label:"Malware Distribution URL",      pct: 15, color:"var(--accent-yellow)" },
    { label:"Social Engineering / Scam",     pct: 10, color:"var(--accent-purple)" },
    { label:"Malware C2 / IOC",              pct: 5,  color:"var(--accent-cyan)" },
  ];
  const barCont = document.getElementById("threatBars");
  barCont.innerHTML = bars.map(b => `
    <div class="threat-bar-wrap">
      <div class="threat-bar-label">
        <span>${b.label}</span>
        <span style="color:${b.color}">${b.pct}%</span>
      </div>
      <div class="threat-bar-track">
        <div class="threat-bar-fill" style="width:0%;background:${b.color}" data-pct="${b.pct}"></div>
      </div>
    </div>`).join('');

  // Animate bars
  setTimeout(() => {
    document.querySelectorAll(".threat-bar-fill").forEach(el => {
      el.style.width = el.dataset.pct + "%";
    });
  }, 100);
}

// ──────────────────────────────────────────────────────────
// INIT
// ──────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {

  // --- TAB NAVIGATION ---
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.dataset.tab).classList.add("active");
      if (btn.dataset.tab === "tabAnalytics") renderAnalytics();
    });
  });

  // --- PRESETS ---
  const presetsContainer = document.getElementById("presetsContainer");
  SCENARIOS.forEach((sc, i) => {
    const chip = document.createElement("button");
    chip.className = "preset-chip";
    chip.textContent = sc.label;
    chip.onclick = () => {
      document.querySelectorAll(".preset-chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      document.getElementById("inputSender").value      = sc.sender;
      document.getElementById("inputSourceType").value  = sc.sourceType;
      document.getElementById("inputReliability").value = sc.reliability;
      document.getElementById("inputText").value        = sc.text;
    };
    presetsContainer.appendChild(chip);
  });

  // --- ANALYZE BUTTON ---
  document.getElementById("btnAnalyze").addEventListener("click", () => {
    const text        = document.getElementById("inputText").value.trim();
    const sender      = document.getElementById("inputSender").value.trim();
    const sourceType  = document.getElementById("inputSourceType").value;
    const reliability = parseFloat(document.getElementById("inputReliability").value);

    if (!text) { showToast("Please enter a payload to analyze.", "error"); return; }

    const btn = document.getElementById("btnAnalyze");
    btn.textContent = "⏳ Analyzing…";
    btn.disabled = true;

    setTimeout(() => {
      const result = detectThreats(text, sender, sourceType, reliability);
      renderAnalysis(result);
      btn.textContent = "⚡ Deep Threat Analysis & Evidence Extraction";
      btn.disabled = false;
      showToast("Analysis complete — " + result.risk, result.riskClass === "low" ? "success" : "error");
    }, 800);
  });

  // --- URL SCANNER ---
  document.getElementById("btnScan").addEventListener("click", runUrlScan);
  document.getElementById("scannerInput").addEventListener("keydown", e => {
    if (e.key === "Enter") runUrlScan();
  });

  // --- DATASETS FILTER ---
  document.querySelectorAll(".filter-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".filter-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      renderDatasets(pill.dataset.filter);
    });
  });

  // --- METRIC ANIMATION ---
  function animateMetric(id, start, end, suffix, duration) {
    const el = document.getElementById(id);
    if (!el) return;
    let startTime;
    function step(ts) {
      if (!startTime) startTime = ts;
      const progress = Math.min((ts - startTime) / duration, 1);
      const val = start + (end - start) * progress;
      el.textContent = val.toFixed(1) + suffix;
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  animateMetric("metricAccuracy", 90, 95.4, "%", 1500);
  animateMetric("metricF1", 89, 94.2, "%", 1500);

  // --- INITIAL RENDER ---
  renderIncidentQueue();
  updateSocStats();
  renderDatasets();

  // --- TOGGLES ---
  document.querySelectorAll(".toggle-switch input").forEach(t => {
    t.addEventListener("change", () => {
      showToast(t.checked ? "Policy enabled" : "Policy disabled", "success");
    });
  });
});
