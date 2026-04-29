import time
import json
import re
from collections import OrderedDict

TRUSTED_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1"}

def is_valid_ip(ip):
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if re.match(pattern, str(ip)):
        parts = str(ip).split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return False

def is_valid_domain(domain):
    pattern = r"^[a-zA-Z0-9\-\.]+$"
    return bool(re.match(pattern, domain))


class DNSCache:
    def __init__(self, max_size=100):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
        self.blocked_attempts = 0

        self.access_frequency = {}

    def _update_frequency(self, domain):
        self.access_frequency[domain] = self.access_frequency.get(domain, 0) + 1

    def get(self, domain):
        if domain in self.cache:
            response, expiry_time = self.cache[domain]

            if time.time() < expiry_time:
                self.cache.move_to_end(domain)
                self.hits += 1

                self._update_frequency(domain)

                return response
            else:
                del self.cache[domain]

        self.misses += 1
        return None

    def _adaptive_ttl(self, domain, base_ttl):
        """
        🔥 Intelligent TTL adjustment:
        - If domain is frequently accessed → increase TTL
        - Else → keep normal TTL
        """
        freq = self.access_frequency.get(domain, 0)

        if freq >= 5:
            new_ttl = base_ttl * 2
            print(f"[ADAPTIVE] High frequency for {domain} → TTL increased to {new_ttl}")
            return new_ttl

        elif freq >= 3:
            new_ttl = int(base_ttl * 1.5)
            print(f"[ADAPTIVE] Moderate frequency for {domain} → TTL increased to {new_ttl}")
            return new_ttl

        return base_ttl

    def set(self, domain, response, ttl=300, source_ip=None):

        if source_ip and source_ip not in TRUSTED_RESOLVERS:
            print(f"[BLOCKED] Untrusted source IP: {source_ip} for domain: {domain}")
            self.blocked_attempts += 1
            return False    

        if not is_valid_domain(domain):
            print(f"[BLOCKED] Malformed domain name: {domain}")
            self.blocked_attempts += 1
            return False

        if not is_valid_ip(response):
            print(f"[BLOCKED] Invalid IP response: {response} for domain: {domain}")
            self.blocked_attempts += 1
            return False

        existing = self.get(domain)
        if existing and existing != "NXDOMAIN":
            print(f"[BLOCKED] Attempt to overwrite valid cache entry for: {domain}")
            self.blocked_attempts += 1
            return False

        ttl = self._adaptive_ttl(domain, ttl)

        self.cache[domain] = (response, time.time() + ttl)

        self.access_frequency[domain] = self.access_frequency.get(domain, 0)

        if len(self.cache) > self.max_size:
            removed, _ = self.cache.popitem(last=False)
            self.access_frequency.pop(removed, None)

        print(f"[CACHED] {domain} -> {response} (TTL={ttl})")
        return True


    def set_negative(self, domain, ttl=60):
        if not is_valid_domain(domain):
            print(f"[BLOCKED] Malformed domain in negative cache: {domain}")
            self.blocked_attempts += 1
            return False

        ttl = self._adaptive_ttl(domain, ttl)

        self.cache[domain] = ("NXDOMAIN", time.time() + ttl)

        if len(self.cache) > self.max_size:
            removed, _ = self.cache.popitem(last=False)
            self.access_frequency.pop(removed, None)

        return True

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
            "hit_rate": f"{rate}%",
            "blocked_attempts": self.blocked_attempts
        }

    def save_to_file(self, path="cache_state.json"):
        data = {
            "hits": self.hits,
            "misses": self.misses,
            "blocked_attempts": self.blocked_attempts,
            "entries": [
                {
                    "domain": d,
                    "ttl_left": max(0, int(v[1] - time.time())),
                    "frequency": self.access_frequency.get(d, 0)
                }
                for d, v in self.cache.items()
                if v[0] != "NXDOMAIN"
            ]
        }
        with open(path, "w") as f:
            json.dump(data, f)