import re

from nmap_fingerprinting import NmapServiceProbes


def main():
    banner = open("raw_http_requests.txt").read()
    http_server = re.search(r'''^HTTP/1\.1.*Server: Microsoft-IIS/([\d.]+)''',
                            banner)

    res = NmapServiceProbes()
    p = res.get_probe(80)

    for rule in p:
        f = rule.search_fingerprint(http_server)
        print(f)

    print("finished")


if __name__ == '__main__':
    main()
