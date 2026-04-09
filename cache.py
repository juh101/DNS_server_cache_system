import time
import json
from collections import OrderedDict

class DNSCache:
    def __init__(self, max_size=100):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.hits = 0
        self.misses = 0

    def get(self, domain):
        if domain in self.cache:
            response, expiry_time = self.cache[domain]
            if time.time() < expiry_time:
                self.cache.move_to_end(domain)
                self.hits += 1
                return response
            else:
                del self.cache[domain]
        self.misses += 1
        return None

    def set(self, domain, response, ttl=300):
        self.cache[domain] = (response, time.time() + ttl)
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)

    def set_negative(self, domain, ttl=60):
        self.cache[domain] = ("NXDOMAIN", time.time() + ttl)
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)

    def is_negative(self, domain):
        if domain in self.cache:
            response, expiry = self.cache[domain]
            if time.time() < expiry and response == "NXDOMAIN":
                return True
        return False

    def stats(self):
        total = self.hits + self.misses
        rate = round((self.hits / total) * 100, 1) if total > 0 else 0
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{rate}%"
        }

    def save_to_file(self, path="cache_state.json"):
        data = {
            "hits": self.hits,
            "misses": self.misses,
            "entries": [
                {
                    "domain": d,
                    "ttl_left": max(0, int(v[1] - time.time()))
                }
                for d, v in self.cache.items()
                if v[0] != "NXDOMAIN"
            ]
        }
        with open(path, "w") as f:
            json.dump(data, f)