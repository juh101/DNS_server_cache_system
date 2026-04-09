import socket
import dns.message
import dns.rdatatype


def query_dns(domain):
    try:
        q = dns.message.make_query(domain, dns.rdatatype.A)
        data = q.to_wire()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(data, ('127.0.0.1', 9053))
        response, _ = sock.recvfrom(512)
        sock.close()

        msg = dns.message.from_wire(response)

        ips = []
        for answer in msg.answer:
            for item in answer.items:
                if hasattr(item, 'address'):
                    ips.append(item.address)

        if ips:
            print(f"  IP Address(es) for '{domain}':")
            for ip in ips:
                print(f"    --> {ip}")
        else:
            print(f"  No IP found for '{domain}'")

    except socket.timeout:
        print(f"  [TIMEOUT] No response from DNS server — is server.py running?")
    except Exception as e:
        print(f"  [ERROR] {e}")


def main():
    print("=" * 50)
    print("   DNS Client")
    print("   Type a domain name to look up its IP")
    print("   Type 'quit' to exit")
    print("=" * 50)
    print()

    while True:
        domain = input("Enter domain (e.g. google.com): ").strip()

        if domain.lower() == 'quit':
            print("Exiting.")
            break

        if not domain:
            print("  Please enter a domain name.\n")
            continue

        print(f"\n  Looking up '{domain}' ...")
        query_dns(domain)
        print()


main()