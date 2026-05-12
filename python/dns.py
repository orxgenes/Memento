#!/usr/bin/env python3
import sys
import dns.resolver
import dns.reversename


class DNSClient:
    def __init__(self, dns_server=None):
        self.resolver = dns.resolver.Resolver()
        if dns_server:
            self.resolver.nameservers = [dns_server]

    def query(self, name, record_type="A"):
        try:
            return [r.to_text() for r in self.resolver.resolve(name, record_type)]
        except dns.resolver.NoAnswer:
            return ["No answer"]
        except dns.resolver.NXDOMAIN:
            return ["Domain does not exist"]
        except dns.resolver.Timeout:
            return ["Query timed out"]
        except Exception as e:
            return [f"Error: {e}"]

    def ptr(self, ip):
        try:
            rev = dns.reversename.from_address(ip)
            return [r.to_text() for r in self.resolver.resolve(rev, "PTR")]
        except Exception as e:
            return [f"Error: {e}"]

    def spf(self, domain):
        try:
            for r in self.resolver.resolve(domain, "TXT"):
                text = b"".join(r.strings).decode(errors="replace") if hasattr(r, "strings") else r.to_text().strip('"')
                if "v=spf1" in text.lower():
                    return SPFRecord(text)
            return None
        except Exception as e:
            return f"Error: {e}"


class SPFRecord:
    def __init__(self, raw):
        self.raw = raw
        self.ip4 = []
        self.ip6 = []
        self.includes = []
        self.a = []
        self.mx = []
        self.redirect = None
        self.policy = None
        self.parse()

    def parse(self):
        for token in self.raw.split()[1:]:
            q = "+"
            if token[0] in "+-~?":
                q, token = token[0], token[1:]

            if token.startswith("ip4:"):
                self.ip4.append(token[4:])
            elif token.startswith("ip6:"):
                self.ip6.append(token[4:])
            elif token.startswith("include:"):
                self.includes.append(token[8:])
            elif token == "a":
                self.a.append("<current-domain>")
            elif token.startswith("a:"):
                self.a.append(token[2:])
            elif token == "mx":
                self.mx.append("<current-domain>")
            elif token.startswith("mx:"):
                self.mx.append(token[3:])
            elif token.startswith("redirect="):
                self.redirect = token.split("=", 1)[1]
            elif token == "all":
                self.policy = q + "all"

    def __str__(self):
        out = [f"SPF: {self.raw}"]
        if self.ip4:
            out.append("IPv4: " + ", ".join(self.ip4))
        if self.ip6:
            out.append("IPv6: " + ", ".join(self.ip6))
        if self.includes:
            out.append("Includes: " + ", ".join(self.includes))
        if self.a:
            out.append("A: " + ", ".join(self.a))
        if self.mx:
            out.append("MX: " + ", ".join(self.mx))
        if self.redirect:
            out.append("Redirect: " + self.redirect)
        if self.policy:
            out.append("Policy: " + self.policy)
        return "\n".join(out)


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python dnslookup.py <domain> [type] [dns_server]")
        print("  python dnslookup.py --ptr <ip> [dns_server]")
        print("  python dnslookup.py --sfp <domain> [dns_server]")
        return

    cmd = sys.argv[1]

    if cmd == "--ptr":
        client = DNSClient(sys.argv[3] if len(sys.argv) > 3 else None)
        for r in client.ptr(sys.argv[2]):
            print(r)
        return

    if cmd == "--sfp":
        client = DNSClient(sys.argv[3] if len(sys.argv) > 3 else None)
        result = client.spf(sys.argv[2])
        if result is None:
            print("No SPF record found")
        else:
            print(result)
        return

    domain = sys.argv[1]
    record_type = sys.argv[2].upper() if len(sys.argv) > 2 else "A"
    dns_server = sys.argv[3] if len(sys.argv) > 3 else None

    client = DNSClient(dns_server)
    for r in client.query(domain, record_type):
        print(r)


if __name__ == "__main__":
    main()