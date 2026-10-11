"""
PolyShield™ Enterprise Cyber Defense Platform
Production Launcher: Starts the Multilingual Threat Intelligence & Autonomous SOC Triage Gateway.
"""
import os
import sys

# Ensure UTF-8 output encoding on Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import uvicorn

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("=" * 76)
    print(" [+] POLYSHIELD(TM) ENTERPRISE CYBER DEFENSE PLATFORM")
    print("     Autonomous Multilingual Threat Intelligence & SOC Triage Gateway")
    print("     Enterprise Commercial Release v2.4 (Production Ready)")
    print("=" * 76)
    print(" [*] Gateway Engine Status      : ONLINE & READY")
    print(" [*] Web Management Console     : http://localhost:8000")
    print(" [*] OpenAPI REST API Docs      : http://localhost:8000/docs")
    print(" [*] ReDoc Technical Reference  : http://localhost:8000/redoc")
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 8000))

    print(f" [*] Localhost Access           : http://localhost:{port}")
    print(f" [*] Network / LAN Access       : http://10.155.171.105:{port}")
    print("=" * 76)
    print(f" Starting PolyShield Enterprise Gateway on {host}:{port} ...")
    print(" Press Ctrl+C to terminate gateway.\n")
    
    uvicorn.run("backend.app.main:app", host=host, port=port, reload=True)
