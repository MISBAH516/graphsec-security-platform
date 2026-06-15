# graphsec-security-platform
AI-Powered Security Operations Platform | FastAPI + PostgreSQL + Machine Learning | Real-time threat detection, brute force protection, JWT auth, role-based access control
# GraphSec — AI-Powered Security Operations Platform

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-green)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue)
![AI](https://img.shields.io/badge/AI-Scikit--Learn-orange)
![JWT](https://img.shields.io/badge/Auth-JWT-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

A full-stack **Security Information & Event Management (SIEM)** system 
built with FastAPI, PostgreSQL, and Machine Learning. 
Automatically detects cyber threats, logs security events, 
and provides real-time monitoring dashboard.

> Similar to enterprise tools like **Splunk**, **IBM QRadar**, 
> and **Microsoft Sentinel** — built from scratch by a solo developer.

---

## 🚀 Live Demo

> Dashboard: `http://localhost:8000/static/index.html`  
> API Docs: `http://localhost:8000/docs`

---

## ✨ Features

### 🤖 AI-Powered Detection
- **Isolation Forest** — Anomaly detection for unknown attacks
- **Random Forest** — Automatic threat severity prediction
- **Self-Learning** — Model improves with more data
- **IP Reputation System** — Tracks suspicious IPs automatically

### 🔐 Security
- JWT Authentication with Access + Refresh tokens
- bcrypt password hashing
- Role-Based Access Control (Admin / User)
- Auto brute force detection
- DDoS attack detection
- Odd hours login alerts
- Unauthorized admin access detection

### 📊 Dashboard
- Real-time threat statistics
- Security event log with source IP
- AI model status and statistics
- Auto-refresh every 30 seconds
- Works on mobile and desktop

### 👮 Admin Panel
- View all users
- Promote users to admin
- Deactivate suspicious accounts
- Monitor all threats and events

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python 3.12) |
| Database | PostgreSQL + SQLAlchemy ORM |
| AI/ML | Scikit-Learn (Isolation Forest + Random Forest) |
| Authentication | JWT (python-jose) + bcrypt |
| Frontend | Vanilla HTML/CSS/JavaScript |
| Server | Uvicorn ASGI |

---

## 📁 Project Structure
