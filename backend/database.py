import sqlite3
import os
import datetime
from threading import Lock

DB_PATH = os.path.join(os.path.dirname(__file__), 'phishguard.db')
db_lock = Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db_lock:
        conn = get_db()
        cursor = conn.cursor()
        
        # Request Log Table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            result TEXT,
            confidence REAL,
            risk_level TEXT,
            timestamp TEXT
        )
        ''')
        
        # Report Log Table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            reason TEXT,
            timestamp TEXT,
            ip TEXT
        )
        ''')
        
        # API Keys Table for Enterprise B2B Auth
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            key_id TEXT PRIMARY KEY,
            company_name TEXT,
            created_at TEXT,
            is_active INTEGER DEFAULT 1
        )
        ''')
        
        # MLOps Feedback Table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            verdict TEXT,
            timestamp TEXT
        )
        ''')

        # Insert default API key if empty
        cursor.execute('SELECT COUNT(*) FROM api_keys')
        if cursor.fetchone()[0] == 0:
            cursor.execute('INSERT INTO api_keys (key_id, company_name, created_at) VALUES (?, ?, ?)',
                           ("PG-API-KEY-2026", "Default Built-In", datetime.datetime.utcnow().isoformat()))
            
        conn.commit()
        conn.close()

# Helper Functions
def log_request(url, result, confidence, risk_level, timestamp):
    with db_lock:
        conn = get_db()
        conn.execute(
            'INSERT INTO requests (url, result, confidence, risk_level, timestamp) VALUES (?, ?, ?, ?, ?)',
            (url, result, confidence, risk_level, timestamp)
        )
        conn.commit()
        conn.close()

def get_recent_requests(limit=500):
    conn = get_db()
    cursor = conn.execute('SELECT * FROM requests ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_analytics():
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) FROM requests').fetchone()[0]
    threats = conn.execute('SELECT COUNT(*) FROM requests WHERE result="phishing"').fetchone()[0]
    
    risk_rows = conn.execute('SELECT risk_level, COUNT(*) FROM requests GROUP BY risk_level').fetchall()
    risk_dist = {row[0]: row[1] for row in risk_rows}
    
    recent_threats = conn.execute('SELECT * FROM requests WHERE result="phishing" ORDER BY id DESC LIMIT 10').fetchall()
    
    conn.close()
    
    return {
        "total_analyzed": total,
        "threats_detected": threats,
        "safe_count": total - threats,
        "threat_rate": round(threats / total * 100, 1) if total else 0,
        "risk_distribution": risk_dist,
        "recent_threats": [dict(r) for r in recent_threats]
    }

def log_report(url, reason, timestamp, ip):
    with db_lock:
        conn = get_db()
        conn.execute(
            'INSERT INTO reports (url, reason, timestamp, ip) VALUES (?, ?, ?, ?)',
            (url, reason, timestamp, ip)
        )
        conn.commit()
        conn.close()

def validate_api_key(api_key):
    conn = get_db()
    cursor = conn.execute('SELECT is_active FROM api_keys WHERE key_id = ?', (api_key,))
    row = cursor.fetchone()
    conn.close()
    return row is not None and row[0] == 1

def log_feedback(url, verdict, timestamp):
    with db_lock:
        conn = get_db()
        conn.execute(
            'INSERT INTO feedback (url, verdict, timestamp) VALUES (?, ?, ?)',
            (url, verdict, timestamp)
        )
        conn.commit()
        conn.close()

# Initialize on import
init_db()
