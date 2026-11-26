"""Validated forwarding data and fixed dnsdist routing. No user-supplied Lua."""
import ipaddress
import json
import re

DEFAULT = {'enabled': False, 'upstreams': [], 'allowed_clients': ['127.0.0.0/8', '::1/128']}


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT) or type(value['enabled']) is not bool:
        raise ValueError('Invalid forwarding settings')
    if not isinstance(value['upstreams'], list) or len(value['upstreams']) > 4:
        raise ValueError('Choose up to four upstream DNS servers')
    seen = set()
    for peer in value['upstreams']:
        if not isinstance(peer, dict) or set(peer) != {'address', 'port'} or type(peer['port']) is not int or not 1 <= peer['port'] <= 65535:
            raise ValueError('Choose an IP address and a port from 1 to 65535')
        ip = ipaddress.ip_address(peer['address'])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or str(ip) == '255.255.255.255':
            raise ValueError('An upstream must be another DNS server, not localhost')
        identity = (str(ip), peer['port'])
        if identity in seen:
            raise ValueError('Duplicate upstream DNS server')
        seen.add(identity)
    if not isinstance(value['allowed_clients'], list) or not 1 <= len(value['allowed_clients']) <= 16:
        raise ValueError('Choose one to sixteen allowed private networks')
    for raw in value['allowed_clients']:
        network = ipaddress.ip_network(raw, strict=True)
        ip = network.network_address
        if not network.is_private or network.prefixlen == 0 or ip.is_unspecified or ip.is_multicast:
            raise ValueError('Only private or loopback client networks are allowed')
    if value['enabled'] and not value['upstreams']:
        raise ValueError('Choose an upstream before enabling forwarding')
    return value


def configuration(value, zones, listener="0.0.0.0:5353", backend_port=5354, preserve_source=False):
    validate(value)
    lines = ['setLocal(' + json.dumps(listener) + ')', 'setACL({"0.0.0.0/0", "::/0"})',
             'setSecurityPollSuffix("")', 'setServerPolicy(firstAvailable)', 'setServFailWhenNoServer(true)',
             f'local auth = newServer({{address="127.0.0.1:{backend_port}", pool="authoritative", useProxyProtocol={str(preserve_source).lower()}}})', 'auth:setUp()',
             'addAction(OrRule({NotRule(OpcodeRule(DNSOpcode.Query)), QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR)}), PoolAction("authoritative"))',
             'addAction(QClassRule(DNSClass.CHAOS), PoolAction("authoritative"))',
             'local owned = newSuffixMatchNode()']
    for zone in zones:
        if not isinstance(zone, str) or len(zone) > 254 or not re.fullmatch(r'(?:[a-z0-9_-]+\.)+|\.', zone):
            raise ValueError('Invalid authoritative zone name')
        lines.append('owned:add(newDNSName(' + json.dumps(zone) + '))')
    if zones:
        lines.append('addAction(SuffixMatchNodeRule(owned), PoolAction("authoritative"))')
    if value['enabled']:
        for i, peer in enumerate(value['upstreams']):
            ip = ipaddress.ip_address(peer['address'])
            address = ('[' + str(ip) + ']' if ip.version == 6 else str(ip)) + ':' + str(peer['port'])
            lines.append('newServer({address=' + json.dumps(address) + ', pool="upstream", order=' + str(i + 1) + ', checkName=".", checkType="SOA", mustResolve=false, checkInterval=2, maxCheckFailures=2})')
        lines.append('addAction(NetmaskGroupRule(' + ('{' + ','.join(json.dumps(n) for n in value['allowed_clients']) + '}') + '), PoolAction("upstream"))')
        lines.append('addAction(AllRule(), RCodeAction(DNSRCode.REFUSED))')
    else:
        lines.append('addAction(AllRule(), PoolAction("authoritative"))')
    return '\n'.join(lines) + '\n'
