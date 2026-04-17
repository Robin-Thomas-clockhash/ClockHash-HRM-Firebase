# ClockHash HRM — Firebase Management

A production-ready **FastAPI** backend for HR Salary Slip Management.

## Security Model

| Layer | Mechanism |
|---|---|
| Frontend → Backend | `X-API-Key` header (dual keys: admin / employee) |
| Backend → Firebase | Firebase Admin SDK via service account JSON |
| PDF encryption | AES-256-GCM, per-employee unique password, PBKDF2 key derivation |
| Password derivation | `HMAC-SHA256(MASTER_KEY_SEED, employee_id)` — deterministic |

---

## Project Structure

```
├── main.py                          # FastAPI app entry point
├── requirements.txt
├── .env.example                     # Copy to .env and fill in values
├── config/
│   └── settings.py                  # Loads .env via pydantic-settings
├── auth/
│   └── dependencies.py              # X-API-Key FastAPI dependencies
├── models/
│   └── salary.py                    # Pydantic request/response models
├── routes/
│   └── salary.py                    # All salary slip API endpoints
├── services/
│   ├── encryption_service.py        # AES-256-GCM encrypt/decrypt
│   ├── firebase_service.py          # Firebase Storage + Firestore CRUD
│   └── password_service.py          # Employee password derivation
└── utils/
    └── logging_config.py            # Structured logging (no sensitive data)
```

---

## Setup

### 1. Clone and install dependencies

```bash
cd ClockHash-HRM-firebase-management
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### 2. Configure environment

```bash
copy .env.example .env
# Edit .env and fill in all values
```

Generate secure random keys:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```
Run this **3 times** — once each for `ADMIN_API_KEY`, `EMPLOYEE_API_KEY`, and `MASTER_KEY_SEED`.

### 3. Add Firebase credentials

1. Firebase Console → Project Settings → Service Accounts → **Generate new private key**
2. Minify the downloaded JSON file into a single line string. You can use a tool like `jq -c . file.json` or any online JSON minifier.
3. Paste the single-line string into `FIREBASE_CREDENTIALS_JSON` inside your `.env` file.
4. Set `FIREBASE_STORAGE_BUCKET` in `.env` to your bucket name (e.g. `your-project.appspot.com`)

> ⚠️ **Never commit your raw `.env` file to version control. The JSON key inside it gives full access to your Firebase project.**

### 4. Run the server

```bash
uvicorn main:app --reload
```

API docs available at: **http://localhost:8000/docs**

---

## API Endpoints

| Method | Path | Key | Description |
|---|---|---|---|
| `GET` | `/health` | none | Health check |
| `POST` | `/salary/upload` | `ADMIN_API_KEY` | Upload + encrypt a salary slip PDF |
| `GET` | `/salary/list` | any | List salary slips (employee scoped) |
| `GET` | `/salary/download/{file_id}` | any | Download encrypted PDF |
| `GET` | `/salary/password/{employee_id}` | `ADMIN_API_KEY` | Get employee decryption password |
| `DELETE` | `/salary/{file_id}` | `ADMIN_API_KEY` | Delete a salary slip |

---

## How to Use

### Upload a salary slip (admin/finance)

```bash
curl -X POST http://localhost:8000/salary/upload \
  -H "X-API-Key: YOUR_ADMIN_API_KEY" \
  -F "employee_id=EMP001" \
  -F "month=1" \
  -F "year=2025" \
  -F "uploaded_by=finance_team" \
  -F "pdf_file=@/path/to/salary_jan_2025.pdf"
```

### Get employee password (admin/finance)

```bash
curl http://localhost:8000/salary/password/EMP001 \
  -H "X-API-Key: YOUR_ADMIN_API_KEY"
```

### Download encrypted slip (employee)

```bash
curl "http://localhost:8000/salary/download/{file_id}?employee_id=EMP001" \
  -H "X-API-Key: YOUR_EMPLOYEE_API_KEY" \
  --output salary_slip.enc
```

---

## Encryption Notes

The encrypted file format is:
```
[salt: 16 bytes][nonce: 12 bytes][GCM ciphertext + tag: N+16 bytes]
```

Employees decrypt their slip using the password retrieved from finance via a secure channel (e.g., email, HR portal). The `decrypt_pdf()` function in `services/encryption_service.py` can be used in a client-side Python script.

---

## Security Checklist

- [ ] `.env` is in `.gitignore`
- [ ] `ADMIN_API_KEY`, `EMPLOYEE_API_KEY`, and `MASTER_KEY_SEED` are long random secrets
- [ ] Firebase Storage bucket has **no public access rules**
- [ ] API is served over **HTTPS only** in production
- [ ] `CORS allow_origins` in `main.py` is restricted to your frontend URL in production
- [ ] `DEBUG=false` in production `.env`

---

## .gitignore

```gitignore
.env
__pycache__/
*.pyc
venv/
.venv/
```
