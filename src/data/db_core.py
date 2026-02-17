import sqlite3
from pathlib import Path
from typing import Union, List, Dict, Any

class DBCore:
    # Get the absolute path to the directory where THIS file is located
    BASE_DIR = Path(__file__).resolve().parent.parent 
    DB_PATH = BASE_DIR / "data" / "url_metadata.db"
    SCHEMA_PATH = BASE_DIR / "data" / "schema.sql"

    def __init__(self):
        self._ensure_data_dir()
        # Silence the linter
        self.conn: sqlite3.Connection 
        self.cursor: sqlite3.Cursor 
        
        self.connect()
        self.initialize_db()

    def _ensure_data_dir(self):
        """Make sure the /data/ folder actually exists."""
        self.DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    def connect(self):
        """Keep one connection open to save time."""
        self.conn = sqlite3.connect(self.DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row # Allows dict-like access (row['url'])
        self.cursor = self.conn.cursor()
        # Optimization: fast I/O
        self.cursor.execute("PRAGMA journal_mode=WAL;") 

    def initialize_db(self):
        """Runs the schema if the table doesn't exist."""
        # check if table exists first to avoid re-reading the file every time
        check = self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='url';")
        if check.fetchone():
            return
            
        print("Initializing Database...")
        with open(self.SCHEMA_PATH, "r", encoding="utf-8") as f:
            self.cursor.executescript(f.read())
        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

    def fetch_many(self, query: str, params=()) -> list[dict[str, Any]]:
        self.cursor.execute(query, params)
        return [dict(row) for row in self.cursor.fetchall()]
    
    def fetch_one(self, query: str, params=()) -> dict[str, Any] | None:
        self.cursor.execute(query, params)
        row = self.cursor.fetchone()
        return dict(row) if row else None
    
    def write_one(self, query: str, params=()) -> int | None:
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
            return self.cursor.lastrowid
        except sqlite3.Error as e:
            print(f"DB Error: {e} | Query: {query}")
            return None
    
    def write_many(self, query: str, params_list) -> None:
        self.cursor.execute("BEGIN")
        try:
            self.cursor.executemany(query, params_list)
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            print(f"DB Error: {e} | Query: {query}")
            raise
