#!/usr/bin/env python3

import argparse
import os
from impacket.ldap import ldap


def build_connection(target, base_dn, use_ldaps):

    proto = "ldaps" if use_ldaps else "ldap"

    return ldap.LDAPConnection(
        f"{proto}://{target}",
        base_dn
    )


def ldap_search(target, base_dn, username, password, ldap_filter, attributes, use_ldaps):

    conn = build_connection(target, base_dn, use_ldaps)

    conn.login(username, password)

    return conn.search(
        searchFilter=ldap_filter,
        attributes=attributes
    )


def main():

    parser = argparse.ArgumentParser(description="LDAP/LDAPS client using Impacket")

    parser.add_argument("-t", "--target", required=True, help="LDAP server / DC")
    parser.add_argument("-d", "--base-dn", required=True, help="Base DN (e.g. DC=example,DC=local)")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", default=os.getenv("LDAP_PASS"), help="Password (or LDAP_PASS env var)")
    parser.add_argument("-f", "--filter", required=True, help="LDAP filter")
    parser.add_argument("-a", "--attributes", nargs="+", default=["cn"], help="Attributes to retrieve")

    parser.add_argument("--ldaps", action="store_true", help="Use LDAPS instead of LDAP (port 636)")

    args = parser.parse_args()

    protocol = "LDAPS" if args.ldaps else "LDAP"
    print(f"[+] Using {protocol} against {args.target}")
    print(f"[+] Filter: {args.filter}")

    if not args.password:
        raise SystemExit("[-] Password required (use -p or LDAP_PASS)")

    try:

        results = ldap_search(
            target=args.target,
            base_dn=args.base_dn,
            username=args.username,
            password=args.password,
            ldap_filter=args.filter,
            attributes=args.attributes,
            use_ldaps=args.ldaps
        )

        print(f"\n[+] Results: {len(results)}\n")

        for entry in results:
            print(entry)

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()