import sqlite3
import hashlib
import os
from datetime import datetime
from modules.crypto_utils import encrypt_data, decrypt_data

DB_FILE = "data/blockchain.db"


class Block:
    def __init__(self, index, previous_hash, timestamp, data, block_hash, owner):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = block_hash
        self.owner = owner


class Blockchain:
    def __init__(self):
        os.makedirs("data", exist_ok=True)

        self.chain = []
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self._create_table()
        self._load_chain()

    # ---------------- TABLE SETUP ----------------
    def _create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                block_index INTEGER PRIMARY KEY AUTOINCREMENT,
                previous_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                encrypted_data TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                owner TEXT NOT NULL
            )
        """)
        self.conn.commit()

    # ---------------- LOAD BLOCKCHAIN ----------------
    def _load_chain(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT block_index, previous_hash, timestamp,
                   encrypted_data, block_hash, owner
            FROM blocks
            ORDER BY block_index
        """)
        rows = cursor.fetchall()

        if not rows:
            self._create_genesis_block()
            return

        for row in rows:
            try:
                data = decrypt_data(row[3])
            except Exception:
                data = "[Decryption Error]"

            self.chain.append(
                Block(row[0], row[1], row[2], data, row[4], row[5])
            )

    # ---------------- HASHING ----------------
    def _calculate_hash(self, index, previous_hash, timestamp, data, owner):
        content = f"{index}{previous_hash}{timestamp}{data}{owner}"
        return hashlib.sha256(content.encode()).hexdigest()

    # ---------------- GENESIS BLOCK ----------------
    def _create_genesis_block(self):
        timestamp = str(datetime.now())
        encrypted = encrypt_data("Genesis Block")

        cursor = self.conn.execute("""
            INSERT INTO blocks (previous_hash, timestamp, encrypted_data, block_hash, owner)
            VALUES (?, ?, ?, ?, ?)
        """, ("0", timestamp, encrypted, "GENESIS_HASH", "system"))

        block_index = cursor.lastrowid
        hash_value = self._calculate_hash(
            block_index, "0", timestamp, "Genesis Block", "system"
        )

        # Update hash after knowing index
        self.conn.execute("""
            UPDATE blocks SET block_hash = ?
            WHERE block_index = ?
        """, (hash_value, block_index))
        self.conn.commit()

        self.chain.append(
            Block(block_index, "0", timestamp, "Genesis Block", hash_value, "system")
        )

    # ---------------- ADD LOG ----------------
    def add_log(self, log_data, username):
        prev = self.chain[-1]
        timestamp = str(datetime.now())
        encrypted = encrypt_data(log_data)

        # Insert first (DB decides index)
        cursor = self.conn.execute("""
            INSERT INTO blocks (previous_hash, timestamp, encrypted_data, block_hash, owner)
            VALUES (?, ?, ?, ?, ?)
        """, (prev.hash, timestamp, encrypted, "PENDING", username))

        block_index = cursor.lastrowid

        hash_value = self._calculate_hash(
            block_index, prev.hash, timestamp, log_data, username
        )

        # Update hash now that index exists
        self.conn.execute("""
            UPDATE blocks SET block_hash = ?
            WHERE block_index = ?
        """, (hash_value, block_index))
        self.conn.commit()

        block = Block(
            block_index, prev.hash, timestamp, log_data, hash_value, username
        )

        self.chain.append(block)
        return block

    # ---------------- INTEGRITY CHECK ----------------
    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            cur = self.chain[i]
            prev = self.chain[i - 1]

            if cur.previous_hash != prev.hash:
                return False

            recalculated = self._calculate_hash(
                cur.index, cur.previous_hash,
                cur.timestamp, cur.data, cur.owner
            )

            if cur.hash != recalculated:
                return False

        return True

    # ---------------- USER LOGS ----------------
    def get_user_logs(self, username):
        return [b for b in self.chain if b.owner == username]
