import collections


class SearchIndex:
    """
    Inverted index for fast keyword-based log search.
    """

    def __init__(self):
        self.index = collections.defaultdict(set)

    def index_log(self, log_text: str, block_index: int):
        """
        Index a log entry by splitting it into keywords.
        """
        words = log_text.lower().split()
        for word in words:
            self.index[word].add(block_index)

    def build_index(self, blockchain):
        """
        Build index from existing blockchain logs.
        """
        self.index.clear()
        for block in blockchain.chain:
            self.index_log(block.data, block.index)

    def search(self, query: str):
        """
        Search logs using AND-based keyword matching.
        """
        keywords = query.lower().split()

        if not keywords:
            return set()

        result = self.index.get(keywords[0], set()).copy()

        for word in keywords[1:]:
            result &= self.index.get(word, set())

        return result
