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
graphsec/

├── ai/

│   └── engine.py          # AI models — Isolation Forest + Random Forest

├── auth/

│   ├── hashing.py         # bcrypt password hashing

│   ├── jwt_handler.py     # JWT access + refresh tokens

│   ├── oauth2.py          # Auth dependencies

│   └── monitor.py         # Auto threat detection rules

├── backend/

│   ├── main.py            # FastAPI app entry point

│   ├── database.py        # PostgreSQL connection

│   └── config.py          # Settings and secrets

├── models/

│   ├── user.py            # User table with roles

│   ├── threat.py          # Threat table with severity enums

│   └── security_event.py  # Security events table

├── routes/

│   ├── auth.py            # Register, Login, Refresh token

│   ├── user.py            # Profile, Admin user management

│   ├── threat.py          # Threat CRUD

│   ├── event.py           # Event CRUD

│   ├── dashboard.py       # Dashboard statistics

│   └── ai_routes.py       # AI analysis endpoints

├── schemas/

│   ├── user.py            # Pydantic request/response models

│   ├── threat.py          # Threat schemas

│   └── security_event.py  # Event schemas

├── static/

│   └── index.html         # Frontend dashboard

├── wifi_monitor.py        # WiFi network monitor script

└── requirements.txt
---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.12+
- PostgreSQL 15+

### Step 1 — Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/graphsec-security-platform.git
cd graphsec-security-platform
```

### Step 2 — Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3 — Create Database
```bash
psql -U postgres -c "CREATE DATABASE graphsec_db;"
```

### Step 4 — Configure Database
Edit `backend/database.py`:
```python
DATABASE_URL = "postgresql://YOUR_USER:YOUR_PASSWORD@localhost:5432/graphsec_db"
```

### Step 5 — Run Server
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 6 — Open Dashboard
http://localhost:8000/static/index.html
---

## 🔌 API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/register | Register new user |
| POST | /auth/login | Login → get tokens |
| POST | /auth/refresh | Refresh access token |

### Users
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | /users/me | User | Get own profile |
| PUT | /users/me | User | Update profile |
| GET | /users/ | Admin | List all users |
| PUT | /users/{id}/make-admin | Admin | Promote to admin |
| PUT | /users/{id}/deactivate | Admin | Deactivate user |

### Threats
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /threats/ | Create threat |
| GET | /threats/ | List threats |
| PUT | /threats/{id} | Update threat |
| DELETE | /threats/{id} | Delete threat |

### Events
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /events/ | Log event |
| GET | /events/ | List events |
| PUT | /events/{id} | Update event |
| DELETE | /events/{id} | Delete event |

### AI Engine
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /ai/stats | AI model statistics |
| POST | /ai/analyze | Analyze any activity |
| POST | /ai/predict-severity | Predict threat severity |
| GET | /ai/ip-reputation/{ip} | Check IP reputation |
| POST | /ai/retrain | Retrain AI models |

---

## 🤖 How AI Works
User Login Attempt

↓

Extract Features:

[hour, day, failed_count, ip_reputation]

↓

Isolation Forest checks:

"Is this normal behavior?"

↓

Random Forest predicts:

"What severity is this threat?"

↓

Auto creates Threat/Event

with AI confidence score

↓

Dashboard updates in real-time
---

## 🧪 Auto-Detection Test

```bash
# Test brute force detection
# Try wrong password 3 times
# Dashboard will show automatic Critical Threat!
```

---

## 🌐 Network Monitoring

```bash
# Monitor your WiFi network
# Edit wifi_monitor.py — add your token
python wifi_monitor.py
```

---

## 🔒 Security Features

| Attack Type | Detection Method |
|-------------|-----------------|
| Brute Force | Failed login counter + AI |
| DDoS | Request rate monitor |
| SQL Injection | Manual threat logging |
| Odd Hours Login | Time-based AI detection |
| Unknown Device | WiFi network scanner |
| Admin Violation | Role-based monitoring |

---

## 📈 Roadmap

- [ ] Email alerts on critical threats
- [ ] WhatsApp notifications via Twilio
- [ ] Deploy on cloud (Render/Railway)
- [ ] HTTPS/SSL certificate
- [ ] Mobile app (React Native)
- [ ] More ML models for better detection
- [ ] Export reports as PDF

---

## 👨‍💻 Author

**Syed Misbah**  
Backend Developer | Cybersecurity Enthusiast  
📧 syedmisbahuddin516@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/syed-misbah-uddin-73823b271/)

---

## 📄 License

MIT License — feel free to use and modify!

---

## ⭐ If this project helped you, please give it a star!
