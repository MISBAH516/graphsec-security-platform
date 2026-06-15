# GraphSec — Security Operations Platform

A full-stack security event and threat management system built with **FastAPI**, **PostgreSQL**, and **vanilla JS**.

## Tech Stack

| Layer    | Technology |
|----------|-----------|
| Backend  | FastAPI (Python) |
| Database | PostgreSQL + SQLAlchemy ORM |
| Auth     | JWT (Access + Refresh Tokens), bcrypt |
| Frontend | HTML/CSS/JS (no framework) |

## Features

- **JWT Authentication** — Access tokens (30 min) + Refresh tokens (7 days)
- **Role-Based Access Control** — `admin` and `user` roles
- **Threat Management** — Create, update, delete, filter threats by severity
- **Security Event Logging** — Log events with source IP, severity, status
- **Dashboard** — Live stats (total threats, critical, open events, resolved)
- **User Profile** — Update username, email, password
- **Admin Panel** — View all users, promote to admin, deactivate accounts
- **Auto Token Refresh** — Frontend silently refreshes expired tokens

## Project Structure

```
graphsec/
├── backend/
│   ├── main.py         # FastAPI app, routers, CORS, DB init
│   ├── database.py     # SQLAlchemy engine, session, Base
│   └── config.py       # JWT secret, token expiry settings
├── auth/
│   ├── hashing.py      # bcrypt password hashing
│   ├── jwt_handler.py  # create/verify access & refresh tokens
│   └── oauth2.py       # get_current_user, require_admin dependencies
├── models/
│   ├── user.py         # User table (id, username, email, role, is_active)
│   ├── threat.py       # Threat table with severity/status enums
│   └── security_event.py # SecurityEvent table with source_ip
├── schemas/
│   ├── user.py         # Pydantic request/response models
│   ├── threat.py       # ThreatCreate, ThreatUpdate, ThreatResponse
│   └── security_event.py
├── routes/
│   ├── auth.py         # POST /auth/register, /login, /refresh
│   ├── user.py         # GET/PUT /users/me, admin routes
│   ├── dashboard.py    # GET /dashboard/ — summary stats
│   ├── threat.py       # Full CRUD /threats/
│   └── event.py        # Full CRUD /events/
├── static/
│   └── index.html      # Frontend dashboard (no framework)
└── requirements.txt
```

## Setup & Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Make sure PostgreSQL is running and create the DB
#    psql -U postgres -c "CREATE DATABASE graphsec_db;"

# 3. Run the server (from inside the graphsec folder)
uvicorn backend.main:app --reload

# 4. Open in browser
#    API docs:  http://127.0.0.1:8000/docs
#    Frontend:  http://127.0.0.1:8000/static/index.html
```

## API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/register | Register new user |
| POST | /auth/login | Login → access + refresh tokens |
| POST | /auth/refresh | Get new tokens using refresh token |

### Users
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | /users/me | User | Get own profile |
| PUT | /users/me | User | Update profile |
| GET | /users/ | Admin | List all users |
| PUT | /users/{id}/make-admin | Admin | Promote user |
| PUT | /users/{id}/deactivate | Admin | Deactivate user |

### Threats & Events
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /threats/ | Create threat |
| GET | /threats/ | List threats (admin sees all) |
| PUT | /threats/{id} | Update threat |
| DELETE | /threats/{id} | Delete threat |
| POST | /events/ | Log event |
| GET | /events/ | List events |
| PUT | /events/{id} | Update event status |
| DELETE | /events/{id} | Delete event |
