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

        if not rows:
            self._create_genesis_block()
            return

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

        cursor = self.conn.execute("""
            INSERT INTO blocks (previous_hash, timestamp, encrypted_data, block_hash, owner)
            VALUES (?, ?, ?, ?, ?)
        """, ("0", timestamp, encrypted, "PENDING", "system"))

        block_index = cursor.lastrowid

        hash_value = self._calculate_hash(
            block_index,
            "0",
            timestamp,
            "Genesis Block",
            "system"
        )

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
    # ADD LOG BLOCK
    # -------------------------------------------------
    def add_log(self, log_data, username):

        prev = self.chain[-1]

        timestamp = str(datetime.now())

        encrypted = encrypt_data(log_data)

        cursor = self.conn.execute("""
            INSERT INTO blocks (previous_hash, timestamp, encrypted_data, block_hash, owner)
            VALUES (?, ?, ?, ?, ?)
        """, (prev.hash, timestamp, encrypted, "PENDING", username))

        block_index = cursor.lastrowid

        hash_value = self._calculate_hash(
            block_index,
            prev.hash,
            timestamp,
            log_data,
            username
        )

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

            if current.previous_hash != previous.hash:
                return False

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


    # -------------------------------------------------
    # CHAIN SUMMARY (FOR DASHBOARD)
    # -------------------------------------------------
    def get_chain_summary(self):

        total_blocks = len(self.chain)

        users = set(b.owner for b in self.chain if b.owner != "system")

        total_users = len(users)

        total_logs = total_blocks - 1 if total_blocks > 0 else 0

        return {
            "blocks": total_blocks,
            "users": total_users,
            "logs": total_logs
        }


    # -------------------------------------------------
    # RECENT BLOCKS (FOR ACTIVITY PANEL)
    # -------------------------------------------------
    def get_latest_blocks(self, limit=5):

        return self.chain[-limit:]


    # -------------------------------------------------
    # CHAIN DATA FOR VISUALIZATION
    # -------------------------------------------------
    def get_chain_for_visualization(self):

        data = []

        for block in self.chain:

            data.append({
                "index": block.index,
                "hash": block.hash,
                "previous_hash": block.previous_hash,
                "owner": block.owner
            })

        return data
