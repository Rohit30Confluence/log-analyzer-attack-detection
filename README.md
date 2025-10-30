# 🧠 Log Analyzer & Attack Detection System — Project Progress Report  

> **Hackathon Track:** Cybersecurity & AI-Powered Threat Detection  
> **Repository:** [log-analyzer-attack-detection](https://github.com/Rohit30Confluence/log-analyzer-attack-detection)  
> **Maintainer:** [@Rohit30Confluence](https://github.com/Rohit30Confluence)  
> **Project Start Date:** October 25, 2025  

---

## 🚀 Project Overview

This project implements a **real-time log analysis and attack detection engine**, designed to identify malicious activities such as **SQL Injection, Cross-Site Scripting (XSS), and Brute-force attacks** from application and server logs.  
Built with **FastAPI**, **Redis**, and **Docker**, it is structured for scalable real-time deployment and analytics visualization.

---

## 📅 Progress Timeline (Hackathon Development Cycle)

### **🔹 Day 1 – Initialization (Oct 25, 2025)**
- Defined project scope and architecture.
- Created initial repository structure on GitHub.
- Set up `.gitignore`, `requirements.txt`, and `Dockerfile`.
- Initialized `FastAPI` base with `/ping` and `/health` endpoints.

---

### **🔹 Day 2 – Core Detection Engine**
- Added **log parser** for Apache/Nginx-style access logs.
- Implemented **signature-based detection**:
  - SQL Injection pattern matching.
  - XSS payload detection.
  - Brute-force login attempt identification.
- Modularized detection logic in `main.py`.

---

### **🔹 Day 3 – Real-Time Queueing & Redis Integration**
- Integrated **Redis** queue (`logs_stream`) for asynchronous log ingestion.
- Added fallback inline analysis when Redis is not configured.
- Extended `/ingest` API to accept:
  - Raw text
  - File uploads
  - JSON payloads

---

### **🔹 Day 4 – Deployment & Containerization**
- Created Dockerized backend under `/backend/Dockerfile`.
- Configured environment variables for:
  - `REDIS_URL`
  - `PORT`
- Deployed backend to **Railway.app** using GitHub Actions CI/CD.
- Backend container built successfully — application started via Uvicorn.

---

### **🔹 Day 5 – DNS & Access Issue Investigation**
- Despite active deployment, **Railway domain unreachable** (`DNS_PROBE_FINISHED_NXDOMAIN`).
- Verified:
  - Healthy container logs (`Uvicorn running on 0.0.0.0:8000`)
  - No build/runtime errors
  - Port configuration (8000) correct
- Opened detailed **GitHub Issue #21** documenting environment, logs, and suspected causes.

---

### **🔹 Day 6 – Repository Enhancements**
- Opened and merged feature pull requests:
  - **#1:** Apache log parser module  
  - **#2:** Attack detection rule modules (SQLi, XSS, Brute Force)  
  - **#3:** Unit tests  
  - **#4:** Visualization logic for detected patterns  
  - **#5:** Adaptive anomaly detection engine  
  - **#6:** CLI interface for unified analysis
- Repository now supports both **batch** and **real-time** log analysis workflows.

---

### **🔹 Day 7 – Transition to Real-Time Experimentation**
- Preparing for **live ingestion loop** testing.
- Plan to move deployment from Railway to **Render** for a stable public endpoint.
- Beginning real-time **log intelligence and visualization layer** integration.

---

## ⚙️ Current Repository Status

| Component | Status | Notes |
|------------|--------|-------|
| **FastAPI Backend** | ✅ Functional | Core detection logic stable |
| **Docker Deployment** | ✅ Working | Container builds successfully |
| **Railway Deployment** | ⚠️ DNS Error | Active deployment, endpoint unreachable |
| **Redis Integration** | ⚙️ Optional | Ready for activation |
| **Frontend / Dashboard** | 🧩 In Progress | Visualization PR pending |
| **Real-Time Experiment** | 🚧 Upcoming | Next implementation phase |

---

## 🎯 Next Steps
1. **Redeploy backend** on Render / Fly.io to achieve public endpoint availability.  
2. **Implement live ingestion loop** to continuously process incoming logs.  
3. **Integrate anomaly scoring module** for adaptive risk detection.  
4. **Build visualization dashboard** for security insights in real-time.  
5. **Conduct final test run & benchmarking** before hackathon submission.

---

## 📊 Repository Links
- **GitHub:** [Rohit30Confluence/log-analyzer-attack-detection](https://github.com/Rohit30Confluence/log-analyzer-attack-detection)
- **Active Issue:** [#21 – Deployment Active but Application Not Reachable](https://github.com/Rohit30Confluence/log-analyzer-attack-detection/issues/21)
- **Demo Deployment (pending):** `https://log-analyzer-attack-detection-production.up.railway.app`

---

### 🏁 Summary
This repository evolved from a basic FastAPI app to a fully modular **real-time log analysis framework** ready for cloud-scale attack detection.  
Ongoing improvements will complete the intelligence loop, providing autonomous pattern recognition and live monitoring capabilities.

