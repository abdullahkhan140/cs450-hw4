"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": tmp})
            tmp = answer
    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response

answers_cache = {}
delegation_cache = {}
def lookup(target_name: dns.name.Name,
           qtype: dns.rdatatype.RdataType) -> dns.message.Message:
    tried = set()
    active = set()
    def addresses_for(zone):
        if zone == dns.name.root:
            yield from ROOT_SERVERS
            return
        servers = delegation_cache[zone]
        for addresses in servers.values():
            yield from addresses
        for hostname, addresses in servers.items():
            if addresses:
                continue
            reply = resolve(hostname, dns.rdatatype.A)
            if reply is None:
                continue
            for rrset in reply.answer:
                if rrset.rdtype == dns.rdatatype.A:
                    yield from (record.address for record in rrset)
    def ask_zone(query, zone):
        question = query.question[0]
        for server in addresses_for(zone):
            attempt = (question.name, question.rdtype, server)
            if attempt in tried:
                continue
            tried.add(attempt)
            try:
                reply = dns.query.udp(query, server, timeout=3)
            except (dns.exception.DNSException, OSError):
                continue
            if reply.flags & dns.flags.TC:
                continue
            status = reply.rcode()
            if status not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                continue
            for rrset in reply.answer:
                if (rrset.name == question.name
                        and rrset.rdtype in (question.rdtype, dns.rdatatype.CNAME)):
                    return reply
            for rrset in reply.authority:
                child = rrset.name
                if (status == dns.rcode.NOERROR
                        and rrset.rdtype == dns.rdatatype.NS
                        and child != zone and child.is_subdomain(zone)
                        and question.name.is_subdomain(child)):
                    cached = delegation_cache.get(child, {})
                    servers = {ns.target: cached.get(ns.target, ()) for ns in rrset}
                    for extra in reply.additional:
                        if (extra.rdtype == dns.rdatatype.A and extra.name in servers
                                and extra.name.is_subdomain(zone)):
                            servers[extra.name] = tuple(record.address for record in extra)

                    delegation_cache[child] = servers
                    answer = ask_zone(query, child)
                    if answer is not None:
                        return answer
                    break
            else:
                if reply.flags & dns.flags.AA:
                    return reply
        return None
    def resolve(name, kind):
        key = (name, kind)
        if key in answers_cache:
            return answers_cache[key]
        if key in active:
            return None
        active.add(key)
        try:
            query = dns.message.make_query(name, kind, flags=0, use_edns=0, payload=1232)
            zones = [zone for zone in delegation_cache if name.is_subdomain(zone)]
            zones.sort(key=lambda zone: len(zone.labels), reverse=True)
            for zone in [*zones, dns.name.root]:
                reply = ask_zone(query, zone)
                if reply is not None:
                    break
            else:
                return None
            answer = dns.message.make_response(query)
            answer.set_rcode(reply.rcode())
            records = {(rrset.name, rrset.rdtype): rrset for rrset in reply.answer}
            current = name
            seen = set()
            while (current, dns.rdatatype.CNAME) in records:
                if current in seen:
                    return None
                seen.add(current)
                alias = records[current, dns.rdatatype.CNAME]
                answer.answer.append(alias)
                current = alias[0].target
            if (current, kind) in records:
                answer.answer.append(records[current, kind])
            elif current != name:
                rest = resolve(current, kind)
                if rest is None:
                    return None
                answer.answer.extend(rest.answer)
                answer.set_rcode(rest.rcode())
            answers_cache[key] = answer
            return answer
        finally:
            active.remove(key)
    try:
        response = resolve(target_name, qtype)
    except RecursionError:
        response = None
    if response is None:
        query = dns.message.make_query(target_name, qtype, flags=0)
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        answers_cache[target_name, qtype] = response
    return response
def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """
    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))
def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        try:
            results = collect_results(a_domain_name)
        except (dns.exception.DNSException, ValueError):
            results = {}
        if any(results.values()):
            print_results(results)
        else:
            print(f"Host {a_domain_name} could not be resolved")
if __name__ == "__main__":
    main()
