import sqlite3
import hashlib
from datetime import datetime
from modules.crypto_utils import encrypt_data, decrypt_data

DB_FILE = "data/blockchain.db"


# ---------------- BLOCK STRUCTURE ----------------

class Block:
    def __init__(self, index, previous_hash, timestamp, data, block_hash, owner):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = block_hash
        self.owner = owner


# ---------------- BLOCKCHAIN ----------------

class Blockchain:
    def __init__(self):
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
                    decrypted_data = decrypt_data(row[3])
                except Exception:
                    decrypted_data = "[Decryption Error]"

                block = Block(
                    index=row[0],
                    previous_hash=row[1],
                    timestamp=row[2],
                    data=decrypted_data,
                    block_hash=row[4],
                    owner=row[5]
                )
                self.chain.append(block)

    def _calculate_hash(self, index, previous_hash, timestamp, data, owner):
        value = f"{index}{previous_hash}{timestamp}{data}{owner}"
        return hashlib.sha256(value.encode()).hexdigest()

    def _create_genesis_block(self):
        timestamp = str(datetime.now())
        hash_value = self._calculate_hash(0, "0", timestamp, "Genesis Block", "system")
        encrypted_data = encrypt_data("Genesis Block")

        self.conn.execute("""
            INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)
        """, (0, "0", timestamp, encrypted_data, hash_value, "system"))
        self.conn.commit()

        genesis = Block(0, "0", timestamp, "Genesis Block", hash_value, "system")
        self.chain.append(genesis)

    def add_log(self, log_data: str, username: str):
        previous_block = self.chain[-1]
        index = len(self.chain)
        timestamp = str(datetime.now())
        encrypted_data = encrypt_data(log_data)
        hash_value = self._calculate_hash(
            index,
            previous_block.hash,
            timestamp,
            log_data,
            username
        )

        self.conn.execute("""
            INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)
        """, (
            index,
            previous_block.hash,
            timestamp,
            encrypted_data,
            hash_value,
            username
        ))
        self.conn.commit()

        block = Block(
            index,
            previous_block.hash,
            timestamp,
            log_data,
            hash_value,
            username
        )
        self.chain.append(block)

        return block

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            recalculated_hash = self._calculate_hash(
                current.index,
                current.previous_hash,
                current.timestamp,
                current.data,
                current.owner
            )

            if current.hash != recalculated_hash:
                return False

            if current.previous_hash != previous.hash:
                return False

        return True

    def get_user_logs(self, username: str):
        """
        Return decrypted logs belonging to a specific user.
        """
        return [block for block in self.chain if block.owner == username]
