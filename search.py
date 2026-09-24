# Copyright (C) 2026  https://github.com/apadartha-code
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://gnu.org>.

import math
import re
from collections import defaultdict
from typing import List, Tuple, Dict, Set
from rapidfuzz import process, fuzz

class BM25InMemoryFuzzySearch:
    """
    An in-memory fuzzy search engine utilizing Okapi BM25 ranking.
    
    What BM25 does:
    1. Term Frequency Saturation (k1): Limits the impact of keyword repetition. 
       A word appearing 10 times does not score 10x higher than a word appearing once.
    2. Document Length Normalization (b): Penalizes long, wordy descriptions 
       and rewards short, concise records where the matched term forms a higher 
       percentage of the total content.
    3. Inverse Document Frequency (IDF): Automatically penalizes common words 
       and boosts unique or rare keywords.
       
    For further technical references on the mathematics of BM25, see:
    https://wikipedia.org
    """
    def __init__(self, min_ngram: int = 1, max_ngram: int = 2, k1: float = 1.5, b: float = 0.75):
        # Index structures
        self.inverted_index = defaultdict(set)      # keyword -> set of record_ids
        self.doc_lengths = defaultdict(int)         # record_id -> count of total tokens in doc
        self.term_df = defaultdict(int)             # keyword -> count of docs containing it
        self.term_freqs = defaultdict(lambda: defaultdict(int)) # record_id -> {keyword -> count}
        self.unique_keywords: List[str] = []
        
        # Configuration parameters
        self.min_ngram = min_ngram
        self.max_ngram = max_ngram
        self.k1 = k1                                # Controls term frequency saturation (usually 1.2 - 2.0)
        self.b = b                                  # Controls length normalization penalty (usually 0.75)
        
        # Base stop-words to clean noisy terms
        self.stop_words: Set[str] = {
            "a", "about", "above", "after", "again", "against", "all", "am", "an", 
            "and", "any", "are", "as", "at", "be", "because", "been", "before", 
            "being", "below", "between", "both", "but", "by", "can", "did", "do", 
            "does", "doing", "down", "during", "each", "few", "for", "from", 
            "further", "had", "has", "have", "having", "he", "her", "here", "hers", 
            "him", "himself", "his", "how", "i", "if", "in", "into", "is", "it", 
            "its", "itself", "me", "more", "most", "my", "myself", "no", "nor", 
            "not", "of", "off", "on", "once", "only", "or", "other", "our", "ours", 
            "ourselves", "out", "over", "own", "same", "she", "should", "so", "some", 
            "such", "than", "that", "the", "their", "theirs", "them", "themselves", 
            "then", "there", "these", "they", "this", "those", "through", "to", 
            "too", "under", "until", "up", "very", "was", "we", "were", "what", 
            "when", "where", "which", "while", "who", "whom", "why", "with", "you", 
            "your", "yours", "yourself", "yourselves"
        }

    def _tokenize(self, text: str) -> List[str]:
        """Normalize text, eliminate punctuation, filter stop words, and build n-grams."""
        clean_text = re.sub(r'[^\w\s]', '', text.lower())
        base_tokens = [w for w in clean_text.split() if w and w not in self.stop_words]
        
        if not base_tokens:
            return []
            
        generated_tokens = []
        for n in range(self.min_ngram, self.max_ngram + 1):
            for i in range(len(base_tokens) - n + 1):
                ngram = " ".join(base_tokens[i:i+n])
                generated_tokens.append(ngram)
                
        return generated_tokens

    def index_record(self, record_id: int, description: str):
        """Extract tokens, record exact frequencies, and index database record."""
        tokens = self._tokenize(description)
        if not tokens:
            return

        # Track total document length for length normalization
        self.doc_lengths[record_id] = len(tokens)
        unique_tokens = set(tokens)

        for token in tokens:
            self.term_freqs[record_id][token] += 1

        for token in unique_tokens:
            self.inverted_index[token].add(record_id)
            self.term_df[token] += 1
            
        self.unique_keywords = list(self.inverted_index.keys())

    def drop_record(self, record_id: int):
        """Clear out indices for the record."""
        if record_id not in self.term_freqs:
            return # Nothing to do.

        for token in self.term_freqs[record_id]:
            self.inverted_index[token].remove(record_id)
            self.term_df[token] -= 1

        del self.term_freqs[record_id]
        del self.doc_lengths[record_id]

    def search(self, search_string: str, limit: int = 5, score_cutoff: float = 70.0) -> List[Tuple[int, float]]:
        """Run fuzzy token exploration and apply Okapi BM25 equation scoring."""
        search_tokens = self._tokenize(search_string)
        if not search_tokens or not self.doc_lengths:
            return []

        total_docs = len(self.doc_lengths)
        avg_doc_len = sum(self.doc_lengths.values()) / total_docs
        record_scores = defaultdict(float)

        for token in search_tokens:
            # Fuzzy find relevant variations in database dictionary
            matches = process.extract(
                token, 
                self.unique_keywords, 
                scorer=fuzz.token_sort_ratio, 
                score_cutoff=score_cutoff,
                limit=3
            )
            
            for matched_keyword, fuzzy_score, _ in matches:
                df = self.term_df[matched_keyword]
                
                # BM25-specific IDF calculation (handles extreme cases smoothly)
                idf = math.log(1 + (total_docs - df + 0.5) / (df + 0.5))
                fuzzy_multiplier = fuzzy_score / 100.0

                for record_id in self.inverted_index[matched_keyword]:
                    # Fetch specific keyword recurrence metrics
                    tf = self.term_freqs[record_id][matched_keyword]
                    doc_len = self.doc_lengths[record_id]
                    
                    # Exact Okapi BM25 denominator component
                    denominator = tf + self.k1 * (1.0 - self.b + self.b * (doc_len / avg_doc_len))
                    
                    # Combine original formula properties scaled by the clarity of fuzzy match
                    bm25_score = idf * ((tf * (self.k1 + 1.0)) / denominator)
                    record_scores[record_id] += bm25_score * fuzzy_multiplier

        sorted_records = sorted(record_scores.items(), key=lambda x: x[1], reverse=True)
        return sorted_records[:limit]

# --- Verification & Example Usage ---
if __name__ == "__main__":
    test_BM25InMemoryFuzzySearch = False
    
    if test_BM25InMemoryFuzzySearch:
        engine = BM25InMemoryFuzzySearch(min_ngram=1, max_ngram=2)
        
        # Indexing sample records showing variations in keyword density and length
        engine.index_record(1, "Apple MacBook Pro laptop. High performance M3 chip laptop for developers.")
        engine.index_record(2, "MacBook Pro laptop.") # Much shorter document
        engine.index_record(3, "Cheap Apple iPhone 15 smartphone with camera.")
        
        # Execution Test 1: Testing phrase matching and stop word omission
        # "macbok pro" matches the bigram "macbook pro"
        print("Search: 'macbok pro'")
        for rid, score in engine.search("macbok pro", limit=3):
            print(f" -> Doc ID: {rid} | Match Strength Score: {score:.4f}")
        
        # Execution Test 2: Testing TF-IDF impact
        # "apple" is common to 1 & 2. "camera" is rare (only in 2). 
        # Record 2 floats to top because "camera" holds a much higher IDF score.
        print("\nSearch: 'aple camera'")
        for rid, score in engine.search("aple camera", limit=3):
            print(f" -> Doc ID: {rid} | Match Strength Score: {score:.4f}")
        
        # Execution Test: Document 2 wins out against Document 1 for "macbook" 
        # because Document 2 is concise, while Document 1 dilutes the keyword weight.
        print("\nSearch results for: 'macbook'")
        for rid, score in engine.search("macbook", limit=3):
            print(f" -> Doc ID: {rid} | BM25 Adjusted Score: {score:.4f}")
