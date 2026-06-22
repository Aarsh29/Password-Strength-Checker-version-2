# SHIELD // Password Security Auditor

An advanced, responsive password strength auditor and security dashboard with a dark cybersecurity aesthetic. Built with Python (Flask) and a highly optimized real-time JavaScript frontend.

## Key Features

1.  **Real-Time Local Audit**: Complexity checklists, entropy calculations, dynamic sequences, keyboard walks, leetspeak dictionary checks, and crack-time models are computed instantly inside the browser on every keystroke.
2.  **O(1) Salting & Hashing**: Commits password history to a local SQLite database using a peppered SHA-256 fingerprint index for O(1) quick-lookup combined with a slow, salted `bcrypt` hash (rounds=12) to securely prevent password reuse.
3.  **Have I Been Pwned Integration**: Direct browser-to-API check using HIBP's secure **k-anonymity** range model (only the first 5 characters of the SHA-1 hash leave the client), complete with memory caching and debouncing.
4.  **4-Tier Crack Time Models**: Predicts guess spaces for Online Throttled, Online Unthrottled, Offline CPU, and Offline GPU attack models.
5.  **Smart Suggestions & Alternate Generation**: Recommends leetspeak symbol substitutions and generates strong cryptographically secure alternatives.

---

## Installation & Setup

To clone and run this project locally, follow these steps:

### 1. Clone the Repository
```bash
git clone https://github.com/Aarsh29/Password-Strength-Checker-version-2.git
cd Password-Strength-Checker-version-2
```

### 2. Initialize a Virtual Environment
Initialize a clean Python virtual environment to isolate project dependencies:

**On Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
Install all required packages from `requirements.txt` (Flask, bcrypt, requests):
```bash
pip install -r requirements.txt
```

### 4. Run the Application
Start the Flask web server:
```bash
python app.py
```

Open your browser and navigate to **http://127.0.0.1:5000** to view the app.

---

## Production Security Notes

*   **PEPPER Configuration**: Before pushing to production, configure a secure environment variable named `SHIELD_PEPPER`. If not set, the application will print warning logs and fall back to a default development string.
*   **Database Exclusions**: The SQLite database file (`passwords.db`) is blocked in `.gitignore` to prevent committing development data hashes. On deployment, the SQLite database table schema will automatically initialize on the first run.
