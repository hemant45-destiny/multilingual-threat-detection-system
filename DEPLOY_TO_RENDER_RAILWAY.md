# 🚀 PolyShield™ Enterprise — Cloud Deployment Guide
### How to Deploy to Render or Railway for a Free Public HTTPS URL

This guide provides simple, step-by-step instructions to deploy your PolyShield platform to the cloud so anyone on the internet (clients, reviewers, partners) can access it via a public HTTPS link (e.g., `https://polyshield-cyber-defense.onrender.com`).

All required configuration files (`requirements.txt`, `Procfile`, `render.yaml`, `Dockerfile`) are already pre-configured in this repository.

---

## 🌟 Method 1: Deploy on Render (Recommended — 100% Free)

Render provides free hosting with automatic HTTPS SSL certificates for FastAPI web applications.

### Step 1: Create a GitHub Repository
1. Go to [https://github.com/new](https://github.com/new) and log in.
2. Name your repository (e.g., `polyshield-enterprise`).
3. Set visibility to **Public** or **Private**, and click **Create repository**.
4. In the empty repository page, click **uploading an existing file**.
5. Drag and drop all files and folders from `multilingual-threat-detection` (or extract `polyshield_enterprise_v2.4_deployment_package.zip` and upload all files).
6. Click **Commit changes**.

### Step 2: Deploy on Render
1. Go to [https://dashboard.render.com](https://dashboard.render.com) and sign in (you can sign in with your GitHub account).
2. In the Render Dashboard, click the blue **New +** button in the top right corner and select **Web Service**.
3. Select **Build and deploy from a Git repository**, then choose your `polyshield-enterprise` GitHub repository.
4. Fill in the following settings (Render may auto-detect them from `render.yaml`):
   - **Name:** `polyshield-cyber-defense` *(determines your URL)*
   - **Region:** Any region close to your users (e.g., Singapore, Frankfurt, Oregon)
   - **Branch:** `main` (or `master`)
   - **Root Directory:** *(leave blank)*
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type:** `Free`
5. Click **Create Web Service**.

### Step 3: Access Your Live Public URL
Render will install dependencies and start the gateway. Within 2–3 minutes, you will see a green **Live** badge and your public HTTPS URL at the top:
👉 **`https://polyshield-cyber-defense.onrender.com`**

You can now share this link with your customer, test on your mobile phone, or connect your enterprise email gateway!

---

## 🚆 Method 2: Deploy on Railway (Fast 1-Click Alternative)

Railway is another popular platform that supports instant Docker and Procfile deployments.

1. Go to [https://railway.app](https://railway.app) and sign in with GitHub.
2. Click **New Project** -> **Deploy from GitHub repo**.
3. Select your `polyshield-enterprise` repository.
4. Railway will automatically detect the `Procfile` and `requirements.txt`.
5. Once built, go to **Settings** -> **Domains** -> click **Generate Domain**.
6. You will get a free public HTTPS URL like:
   👉 **`https://polyshield-production.up.railway.app`**

---

## 📱 Method 3: Instant Access on Your Local Network / Wi-Fi Right Now

If you want to immediately show the platform to a customer, colleague, or test it on your mobile phone without uploading to the cloud first:

1. Ensure the gateway is running (`py run.py` or double-click `start_enterprise_server.bat`).
2. Make sure your phone or the customer's laptop is connected to the same Wi-Fi / network.
3. Open a browser on their device and visit:
   👉 **`http://10.155.171.105:8000`**

---

## 📋 Pre-Configured Deployment Files Reference

| File | Purpose |
| :--- | :--- |
| `requirements.txt` | Defines production Python dependencies (`fastapi`, `uvicorn`, `scikit-learn`, `pydantic`). |
| `Procfile` | Specifies the startup command for Render, Railway, and Heroku. |
| `render.yaml` | Infrastructure-as-code Blueprint for zero-configuration deployment on Render. |
| `Dockerfile` | Production container specification for Docker, AWS ECS, GCP Cloud Run, and Kubernetes. |
| `threat_detection_audit.db` | Pre-seeded SQLite database with enterprise security incidents. |
| `model_pipeline.joblib` | Calibrated ML threat classification pipeline ready for inference. |
