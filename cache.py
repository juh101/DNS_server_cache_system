import time
import json
import re
from collections import OrderedDict

# Trusted DNS resolvers only (Google + Cloudflare)
TRUSTED_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1"}

def is_valid_ip(ip):
    """Check if the IP is a properly formatted IPv4 address."""
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if re.match(pattern, str(ip)):
        parts = str(ip).split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return False

def is_valid_domain(domain):
    """Reject domains with suspicious or malformed characters."""
    pattern = r"^[a-zA-Z0-9\-\.]+$"
    return bool(re.match(pattern, domain))

class DNSCache:
    def __init__(self, max_size=100):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
        self.blocked_attempts = 0

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

    def set(self, domain, response, ttl=300, source_ip=None):
        #def 1 : only trust ips from trusted resolvers
        if source_ip and source_ip not in TRUSTED_RESOLVERS:
            print(f"[BLOCKED] Untrusted source IP: {source_ip} for domain: {domain}")
            self.blocked_attempts += 1
            return False    

        # Defense 2: Validate domain name format
        if not is_valid_domain(domain):
            print(f"[BLOCKED] Malformed domain name: {domain}")
            self.blocked_attempts += 1
            return False

        # Defense 3: Validate the IP address in the response
        if not is_valid_ip(response):
            print(f"[BLOCKED] Invalid IP response: {response} for domain: {domain}")
            self.blocked_attempts += 1
            return False

        # Defense 4: Don't overwrite an existing valid (non-expired) cache entry
        existing = self.get(domain)
        if existing and existing != "NXDOMAIN":
            print(f"[BLOCKED] Attempt to overwrite valid cache entry for: {domain}")
            self.blocked_attempts += 1
            return False

        self.cache[domain] = (response, time.time() + ttl)
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)
        print(f"[CACHED] {domain} -> {response}")
        return True


    def set_negative(self, domain, ttl=60):
         # Negative caching doesn't need IP validation (no IP involved)
        if not is_valid_domain(domain):
            print(f"[BLOCKED] Malformed domain in negative cache: {domain}")
            self.blocked_attempts += 1
            return False
        self.cache[domain] = ("NXDOMAIN", time.time() + ttl)
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)
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
                    "ttl_left": max(0, int(v[1] - time.time()))
                }
                for d, v in self.cache.items()
                if v[0] != "NXDOMAIN"
            ]
        }
        with open(path, "w") as f:
            json.dump(data, f)