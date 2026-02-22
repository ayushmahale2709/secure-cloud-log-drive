import collections


class SearchIndex:
    """
    Inverted index for keyword-based log search.
    Supports AND / OR / NOT operations.
    """

    def __init__(self):
        self.index = collections.defaultdict(set)

    def index_log(self, log_text: str, block_index: int):
        words = log_text.lower().split()
        for word in words:
            self.index[word].add(block_index)

    def build_index(self, blockchain):
        self.index.clear()
        for block in blockchain.chain:
            self.index_log(block.data, block.index)

    def search(self, query: str, mode: str = "AND"):
        keywords = query.lower().split()

        if not keywords:
            return set()

        if mode == "AND":
            result = self.index.get(keywords[0], set()).copy()
            for word in keywords[1:]:
                result &= self.index.get(word, set())
            return result

        if mode == "OR":
            result = set()
            for word in keywords:
                result |= self.index.get(word, set())
            return result

        if mode == "NOT":
            base = self.index.get(keywords[0], set()).copy()
            for word in keywords[1:]:
                base -= self.index.get(word, set())
            return base

        return set()
