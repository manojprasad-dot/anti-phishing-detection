import os
import datetime
import logging
from threading import Lock

# Determine which database engine to use
SUPABASE_URL = os.environ.get("SUPABASE_URL")
if SUPABASE_URL:
    try:
        import psycopg2
        from psycopg2.extras import DictCursor
        USE_POSTGRES = True
        logger = logging.getLogger(__name__)
        logger.info("Using Supabase PostgreSQL database.")
    except ImportError:
        logger = logging.getLogger(__name__)
        logger.warning("SUPABASE_URL provided but psycopg2 is not installed. Falling back to SQLite.")
        USE_POSTGRES = False
        import sqlite3
else:
    import sqlite3
    USE_POSTGRES = False

DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(__file__))
DB_PATH = os.path.join(DATA_DIR, 'phishguard.db')
db_lock = Lock()

def get_db():
    if USE_POSTGRES:
        conn = psycopg2.connect(SUPABASE_URL)
        return conn
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

def execute_query(query, params=(), fetchall=False, fetchone=False, commit=False):
    """Abstraction layer to handle SQLite '?' vs PostgreSQL '%s' and execution."""
    if USE_POSTGRES:
        query = query.replace('?', '%s')
    
    # We use a lock only for SQLite to prevent concurrent write issues on local files
    if not USE_POSTGRES:
        db_lock.acquire()
        
    try:
        conn = get_db()
        if USE_POSTGRES:
            cursor = conn.cursor(cursor_factory=DictCursor)
        else:
            cursor = conn.cursor()
            
        cursor.execute(query, params)
        
        result = None
        if fetchall:
            result = [dict(row) for row in cursor.fetchall()]
        elif fetchone:
            row = cursor.fetchone()
            result = dict(row) if row else None
            
        if commit:
            conn.commit()
            
        cursor.close()
        conn.close()
        return result
    finally:
        if not USE_POSTGRES:
            db_lock.release()

def init_db():
    # We define table schemas compatible with both SQLite and Postgres
    queries = [
        '''
        CREATE TABLE IF NOT EXISTS requests (
            id SERIAL PRIMARY KEY,
            url TEXT,
            result TEXT,
            confidence REAL,
            risk_level TEXT,
            timestamp TEXT
        )
        '''.replace('SERIAL', 'INTEGER PRIMARY KEY AUTOINCREMENT') if not USE_POSTGRES else 
        '''
        CREATE TABLE IF NOT EXISTS requests (
            id SERIAL PRIMARY KEY,
            url TEXT,
            result TEXT,
            confidence REAL,
            risk_level TEXT,
            timestamp TEXT
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS reports (
            id SERIAL PRIMARY KEY,
            url TEXT,
            reason TEXT,
            timestamp TEXT,
            ip TEXT
        )
        '''.replace('SERIAL', 'INTEGER PRIMARY KEY AUTOINCREMENT') if not USE_POSTGRES else
        '''
        CREATE TABLE IF NOT EXISTS reports (
            id SERIAL PRIMARY KEY,
            url TEXT,
            reason TEXT,
            timestamp TEXT,
            ip TEXT
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS api_keys (
            key_id TEXT PRIMARY KEY,
            company_name TEXT,
            created_at TEXT,
            is_active INTEGER DEFAULT 1
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS feedback (
            id SERIAL PRIMARY KEY,
            url TEXT,
            verdict TEXT,
            timestamp TEXT
        )
        '''.replace('SERIAL', 'INTEGER PRIMARY KEY AUTOINCREMENT') if not USE_POSTGRES else
        '''
        CREATE TABLE IF NOT EXISTS feedback (
            id SERIAL PRIMARY KEY,
            url TEXT,
            verdict TEXT,
            timestamp TEXT
        )
        '''
    ]
    
    for query in queries:
        execute_query(query, commit=True)

    # Insert default API key if empty
    res = execute_query('SELECT COUNT(*) as count FROM api_keys', fetchone=True)
    if res and res['count'] == 0:
        execute_query(
            'INSERT INTO api_keys (key_id, company_name, created_at) VALUES (?, ?, ?)',
            ("PG-API-KEY-2026", "Default Built-In", datetime.datetime.utcnow().isoformat()),
            commit=True
        )

# Helper Functions
def log_request(url, result, confidence, risk_level, timestamp):
    execute_query(
        'INSERT INTO requests (url, result, confidence, risk_level, timestamp) VALUES (?, ?, ?, ?, ?)',
        (url, result, confidence, risk_level, timestamp),
        commit=True
    )

def get_recent_requests(limit=500):
    return execute_query('SELECT * FROM requests ORDER BY id DESC LIMIT ?', (limit,), fetchall=True)

def get_analytics():
    total = execute_query('SELECT COUNT(*) as count FROM requests', fetchone=True)['count']
    threats = execute_query('SELECT COUNT(*) as count FROM requests WHERE result=?', ('phishing',), fetchone=True)['count']
    
    risk_rows = execute_query('SELECT risk_level, COUNT(*) as count FROM requests GROUP BY risk_level', fetchall=True)
    risk_dist = {row['risk_level']: row['count'] for row in risk_rows}
    
    recent_threats = execute_query('SELECT * FROM requests WHERE result=? ORDER BY id DESC LIMIT 10', ('phishing',), fetchall=True)
    
    return {
        "total_analyzed": total,
        "threats_detected": threats,
        "safe_count": total - threats,
        "threat_rate": round(threats / total * 100, 1) if total else 0,
        "risk_distribution": risk_dist,
        "recent_threats": recent_threats
    }

def log_report(url, reason, timestamp, ip):
    execute_query(
        'INSERT INTO reports (url, reason, timestamp, ip) VALUES (?, ?, ?, ?)',
        (url, reason, timestamp, ip),
        commit=True
    )

def validate_api_key(api_key):
    row = execute_query('SELECT is_active FROM api_keys WHERE key_id = ?', (api_key,), fetchone=True)
    return row is not None and row['is_active'] == 1

def log_feedback(url, verdict, timestamp):
    execute_query(
        'INSERT INTO feedback (url, verdict, timestamp) VALUES (?, ?, ?)',
        (url, verdict, timestamp),
        commit=True
    )

# Admin Helpers
def create_api_key(key_id, company_name, created_at):
    execute_query(
        "INSERT INTO api_keys (key_id, company_name, created_at) VALUES (?, ?, ?)", 
        (key_id, company_name, created_at),
        commit=True
    )

def get_all_api_keys():
    return execute_query("SELECT * FROM api_keys", fetchall=True)

def get_all_feedback():
    return execute_query("SELECT * FROM feedback", fetchall=True)

# Initialize on import
init_db()
