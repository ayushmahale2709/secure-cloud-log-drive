from typing import List
from modules.blockchain import Block, Blockchain


def get_logs_for_user(blockchain: Blockchain, username: str) -> List[Block]:
    """
    Retrieve decrypted logs belonging to the authenticated user.
    """
    user_logs = []

    for block in blockchain.chain:
        if block.owner == username:
            user_logs.append(block)

    return user_logs


def format_log_for_display(block: Block) -> str:
    """
    Format log block data for UI display.
    """
    return f"""
Time      : {block.timestamp}
User      : {block.owner}
Block ID  : {block.index}
Log Data  : {block.data}
Hash      : {block.hash}
"""
