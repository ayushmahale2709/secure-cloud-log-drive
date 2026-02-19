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
        # Ensure data directory exists (CLOUD SAFE)
        os.makedirs("data", exist_ok=True)

        self.chain = []
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self._create_table()
        self._load_chain()

    def _create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                block_index INTEGER PRIMARY KEY,
                previous_hash TEXT,
                timestamp TEXT,
                encrypted_data TEXT,
                block_hash TEXT,
                owner TEXT
            )
        """)
        self.conn.commit()

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
        else:
            for row in rows:
                try:
                    data = decrypt_data(row[3])
                except Exception:
                    data = "[Decryption Error]"

                self.chain.append(
                    Block(row[0], row[1], row[2], data, row[4], row[5])
                )

    def _calculate_hash(self, index, previous_hash, timestamp, data, owner):
        content = f"{index}{previous_hash}{timestamp}{data}{owner}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _create_genesis_block(self):
        timestamp = str(datetime.now())
        hash_value = self._calculate_hash(
            0, "0", timestamp, "Genesis Block", "system"
        )
        encrypted = encrypt_data("Genesis Block")

        self.conn.execute("""
            INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)
        """, (0, "0", timestamp, encrypted, hash_value, "system"))
        self.conn.commit()

        self.chain.append(
            Block(0, "0", timestamp, "Genesis Block", hash_value, "system")
        )

    def add_log(self, log_data, username):
        prev = self.chain[-1]
        index = len(self.chain)
        timestamp = str(datetime.now())
        encrypted = encrypt_data(log_data)
        hash_value = self._calculate_hash(
            index, prev.hash, timestamp, log_data, username
        )

        self.conn.execute("""
            INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)
        """, (index, prev.hash, timestamp, encrypted, hash_value, username))
        self.conn.commit()

        block = Block(
            index, prev.hash, timestamp, log_data, hash_value, username
        )
        self.chain.append(block)
        return block

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            cur = self.chain[i]
            prev = self.chain[i - 1]

            if cur.previous_hash != prev.hash:
                return False

            if cur.hash != self._calculate_hash(
                cur.index, cur.previous_hash,
                cur.timestamp, cur.data, cur.owner
            ):
                return False

        return True

    def get_user_logs(self, username):
        return [b for b in self.chain if b.owner == username]
