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
        # Ensure DB directory exists
        os.makedirs("data", exist_ok=True)

        self.chain = []
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self._create_table()
        self._load_chain()

    # -------------------------------------------------
    # DATABASE TABLE
    # -------------------------------------------------
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

    # -------------------------------------------------
    # LOAD BLOCKCHAIN FROM DATABASE
    # -------------------------------------------------
    def _load_chain(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT block_index, previous_hash, timestamp,
                   encrypted_data, block_hash, owner
            FROM blocks
            ORDER BY block_index
        """)
        rows = cursor.fetchall()

        # If DB is empty, create genesis block
        if not rows:
            self._create_genesis_block()
            return

        # Load existing blocks
        for row in rows:
            try:
                data = decrypt_data(row[3])
            except Exception:
                data = "[Decryption Error]"

            self.chain.append(
                Block(
                    index=row[0],
                    previous_hash=row[1],
                    timestamp=row[2],
                    data=data,
                    block_hash=row[4],
                    owner=row[5]
                )
            )

    # -------------------------------------------------
    # HASH CALCULATION
    # -------------------------------------------------
    def _calculate_hash(self, index, previous_hash, timestamp, data, owner):
        content = f"{index}{previous_hash}{timestamp}{data}{owner}"
        return hashlib.sha256(content.encode()).hexdigest()

    # -------------------------------------------------
    # GENESIS BLOCK
    # -------------------------------------------------
    def _create_genesis_block(self):
        timestamp = str(datetime.now())
        encrypted = encrypt_data("Genesis Block")

        # Insert placeholder hash first
        cursor = self.conn.execute("""
            INSERT INTO blocks (previous_hash, timestamp, encrypted_data, block_hash, owner)
            VALUES (?, ?, ?, ?, ?)
        """, ("0", timestamp, encrypted, "PENDING", "system"))

        block_index = cursor.lastrowid

        hash_value = self._calculate_hash(
            block_index, "0", timestamp, "Genesis Block", "system"
        )

        # Update real hash
        self.conn.execute("""
            UPDATE blocks
            SET block_hash = ?
            WHERE block_index = ?
        """, (hash_value, block_index))
        self.conn.commit()

        self.chain.append(
            Block(
                index=block_index,
                previous_hash="0",
                timestamp=timestamp,
                data="Genesis Block",
                block_hash=hash_value,
                owner="system"
            )
        )

    # -------------------------------------------------
    # ADD LOG (NORMAL BLOCK)
    # -------------------------------------------------
    def add_log(self, log_data, username):
        prev = self.chain[-1]
        timestamp = str(datetime.now())
        encrypted = encrypt_data(log_data)

        # Insert row first (DB assigns index)
        cursor = self.conn.execute("""
            INSERT INTO blocks (previous_hash, timestamp, encrypted_data, block_hash, owner)
            VALUES (?, ?, ?, ?, ?)
        """, (prev.hash, timestamp, encrypted, "PENDING", username))

        block_index = cursor.lastrowid

        hash_value = self._calculate_hash(
            block_index, prev.hash, timestamp, log_data, username
        )

        # Update correct hash
        self.conn.execute("""
            UPDATE blocks
            SET block_hash = ?
            WHERE block_index = ?
        """, (hash_value, block_index))
        self.conn.commit()

        block = Block(
            index=block_index,
            previous_hash=prev.hash,
            timestamp=timestamp,
            data=log_data,
            block_hash=hash_value,
            owner=username
        )

        self.chain.append(block)
        return block

    # -------------------------------------------------
    # CHAIN INTEGRITY VERIFICATION
    # -------------------------------------------------
    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Check hash linkage
            if current.previous_hash != previous.hash:
                return False

            # Recalculate hash
            recalculated = self._calculate_hash(
                current.index,
                current.previous_hash,
                current.timestamp,
                current.data,
                current.owner
            )

            if current.hash != recalculated:
                return False

        return True

    # -------------------------------------------------
    # USER LOG FILTER
    # -------------------------------------------------
    def get_user_logs(self, username):
        return [b for b in self.chain if b.owner == username]
