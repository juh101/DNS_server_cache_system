import socket
import struct
import threading
import dns.message
import dns.rdatatype
import dns.rcode

from cache import DNSCache
from resolver import forward_query

HOST = '127.0.0.1'
PORT = 9053

TRUSTED_RESOLVERS = {'8.8.8.8', '1.1.1.1'}

cache = DNSCache()


def extract_domain(data):
    try:
        msg = dns.message.from_wire(data)
        return str(msg.question[0].name).rstrip('.')
    except:
        return None


def extract_ttl(data):
    try:
        msg = dns.message.from_wire(data)
        if msg.answer:
            return msg.answer[0].ttl
    except:
        pass
    return 300


def validate_response(query, response, source_ip):
    query_id = struct.unpack('!H', query[:2])[0]
    response_id = struct.unpack('!H', response[:2])[0]
    if query_id != response_id:
        print(f"  [SECURITY] Transaction ID mismatch — possible poisoning attempt!")
        return False
    if source_ip not in TRUSTED_RESOLVERS:
        print(f"  [SECURITY] Response from untrusted source: {source_ip}")
        return False
    return True


def handle_query(data, addr, sock):
    domain = extract_domain(data)
    if not domain:
        return

    if cache.is_negative(domain):
        print(f"  [NEG-HIT]  '{domain}' was previously not found — skipping lookup")
        return

    cached = cache.get(domain)
    if cached:
        print(f"  [CACHE HIT]  Found '{domain}' in cache — returning instantly")
        sock.sendto(cached, addr)
    else:
        print(f"  [CACHE MISS] '{domain}' not in cache — asking 8.8.8.8 ...")
        try:
            response, source_ip = forward_query(data)
            if validate_response(data, response, source_ip):
                msg = dns.message.from_wire(response)
                if msg.rcode() == dns.rcode.NXDOMAIN:
                    cache.set_negative(domain, ttl=60)
                    print(f"  [NXDOMAIN]   '{domain}' does not exist — cached for 60s")
                else:
                    ttl = extract_ttl(response)
                    cache.set(domain, response, ttl)
                    print(f"  [CACHED]     '{domain}' stored for {ttl}s")
                sock.sendto(response, addr)
            else:
                print(f"  [DROPPED]    Response for '{domain}' failed security check")
        except Exception as e:
            print(f"  [ERROR]      Could not resolve '{domain}': {e}")

    s = cache.stats()
    print(f"  [STATS]      Hits: {s['hits']}  Misses: {s['misses']}  Hit Rate: {s['hit_rate']}")
    print()


def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))

    print("=" * 50)
    print("   DNS Server started on 127.0.0.1:9053")
    print("   Waiting for queries from client...")
    print("=" * 50)
    print()

    while True:
        data, addr = sock.recvfrom(512)
        thread = threading.Thread(target=handle_query, args=(data, addr, sock))
        thread.daemon = True
        thread.start()


start_server()