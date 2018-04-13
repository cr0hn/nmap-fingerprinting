import os.path as op

from typing import List, Iterable
from collections import defaultdict

PROBE_REGEX = r'''(Probe)([\w\W]+)(Probe)'''
PORTS_FROM_SECTION = r'''(ports )([\w\d\-\,]+)'''
PAYLOAD_EXTRACTOR = \
    r"""(Probe)([\s]+)(TCP|UDP)([\s]+)([\w]+)([ q]+\|)(.*)(|)"""


class NmapMatcher:

    def __init__(self,
                 payload: str,
                 protocol: str,
                 service_name: str,
                 rules: List[str]):
        self._rules = rules
        self.payload = payload
        self.protocol = protocol
        self.service_type = service_name

    def search_fingerprint(self, banner: str):
        for r in self._rules:
            service_name, nmap_regex, post_rules = r

            # -------------------------------------------------------------------------
            # TODO: PARSE REGEX
            # -------------------------------------------------------------------------


class NmapServiceProbes:

    def __init__(self, nmap_file_path: str = None):
        self.nmap_file_path = nmap_file_path or self._resolve_nmap_file_path()

        self._test_by_ports_tcp = defaultdict(list)
        self._test_by_ports_udp = defaultdict(list)

        # Load data
        self._populate(self.nmap_file_path)

    def get_probe(self, port: int, proto: str = "TCP") -> NmapMatcher:
        """Return first probes for the given port / protocol"""
        return next(self.get_probes(port, proto))

    def get_probes(self, port: int, proto: str = "TCP") -> Iterable[NmapMatcher]:
        """
        Return all probes for the given port / protocol

        It returns an ITERATOR. This means that you can index it!!!

        >>> x = get_probes(80)[0]  # WRONG!
        >>> x = list(get_probes(80))[0]  # Good
        >>> for x in get_probes(80):  # Better
                print(x)

        """
        if proto.lower() == "tcp":
            f = self._test_by_ports_tcp
        else:
            f = self._test_by_ports_udp

        _port = str(port)
        for pk, p in f.items():
            if _port in pk:
                yield p

    def _build_key(self, proto: str, ports: List[str]) -> str:
        return f"{proto}::{'_'.join(str(x) for x in ports)}"

    def _populate(self, nmap_file_name: str):

        for x in self._parse_nmap_services(nmap_file_name):
            payload, service_proto, ports, service_name, found_rules = x

            key = self._build_key(service_proto, ports)

            if service_proto == "TCP":
                d = self._test_by_ports_tcp[key]
            else:
                d = self._test_by_ports_udp[key]

            d.append(
                NmapMatcher(
                    payload,
                    service_proto,
                    service_name,
                    found_rules)
            )

    def _resolve_nmap_file_path(self) -> str:
        here = op.dirname(__file__)

        return op.join(here, "nmap-service-probes")

    def _parse_nmap_services(self, file_path: str):
        """
        return format:

        [
            (proto, (port1, port2,...), service_name,
                [(
                    service_name,
                    match_rule
                    post_match_rule
                )]
            )
        ]
        """
        with open(file_path, "r") as f:
            nmap_content = f.read()

        nmap_content_splitted = nmap_content.splitlines()
        probe_init = get_next_probe(nmap_content_splitted, 0)

        while True:
            probe_end = get_next_probe(nmap_content_splitted,
                                       probe_init + 1 + len("Probe"))

            if probe_end == -1:
                break

            content = "\n".join(
                nmap_content_splitted[probe_init: probe_end])

            _, service_proto, service_type, payload = content.split(" ",
                                                                    maxsplit=3)
            #
            # Get ports
            #
            ports = []
            for line in nmap_content_splitted:
                if line.startswith("ports "):
                    _, _found_ports = line.split(" ")

                    ports = expand_ports(_found_ports)
                    break

            #
            # Get Matches: locate the first match
            #
            found_matches = []
            for match in content[content.find("match"):].splitlines():

                # Avoid comments
                if not match.startswith("match"):
                    continue

                #
                # Split parts
                #
                prefix, service_name, tmp_suffix = match.split(" ",
                                                               maxsplit=2)

                #
                # TODO: implement strange matches:
                # - match basestation m=^....
                #
                if tmp_suffix.startswith("m="):
                    continue

                _rule_init = tmp_suffix.find("|")
                _rule_end = tmp_suffix[_rule_init + 1:].find("|") + 2
                _rule_modificator, *post_rules = \
                    tmp_suffix[_rule_end + 1:].split(" ", maxsplit=1)

                #
                # Rule: "^SIP/2\.0 403 Forbidden\r\nContent-Type: ..."
                #
                rule = tmp_suffix[_rule_init + 1:_rule_end + 1]

                perl_regex = f"m|{rule}|{_rule_modificator}"

                #
                # Service name: "p/NEC SL1100 VoIP PBX/ d/PBX/"
                #
                found_matches.append((
                    service_name,
                    perl_regex,
                    post_rules
                ))

            # results.append([
            #     service_proto,
            #     ports,
            #     service_type,
            #     found_matches
            # ])
            yield payload, service_proto, ports, service_type, found_matches

            #
            # Calculate next
            #
            probe_init = probe_end

        # return results

    def get_testers(self, ports,) -> List[NmapMatcher]:
        pass

    def __iter__(self):
        return self

    def __next__(self):
        pass


#
# PCRE: https://pypi.python.org/pypi/python-pcre/0.6
#


#
# https://nmap.org/book/vscan-fileformat.html
#
def expand_ports(raw_ports: str) -> List[int]:
    """Parse port str in nmap, return port lists
    """
    results = []

    ports = raw_ports.split(',')

    for port in ports:
        if '-' in port:
            start, end = port.split('-')
            _ = [int(_) for _ in range(int(start), int(end) + 1)]
            results.extend(_)
        else:
            results.append(int(port))
    return list(set(results))


def get_next_probe(text: List, init: int = 0) -> int:
    for i, line in enumerate(text[init:]):
        if line.startswith("Probe"):
            return i + init

    return -1


__all__ = ("NmapServiceProbes", "NmapMatcher")
