"""A small pf-style evaluator over the intent's firewall rules.

Lets tests assert security invariants ("Guest can never reach the LAN")
against network/rules.yml on every change, before anything touches the
firewall.

Evaluation order:
  - only enabled rules on the packet's ingress interface, direction 'in'
  - evaluated in sequence order
  - a matching rule with quick=true decides immediately
  - a matching rule with quick=false is remembered; the LAST such match wins
  - no match -> default deny (OPNsense's implicit block)

Floating/group rules, states, gateways/policy routing, IPv6, scheduling and
the automatic anti-lockout rule are not modelled. This covers inter-VLAN
reachability; it does not replace testing on the firewall.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import Intent, Rule


@dataclass(frozen=True)
class Packet:
    in_interface: str  # lan / optN token
    source_ip: str
    destination_ip: str
    protocol: str = "tcp"  # tcp | udp | icmp | carp
    destination_port: int | None = None


@dataclass(frozen=True)
class Decision:
    action: str  # pass | block | reject (block = implicit default deny)
    rule: Rule | None  # None -> default deny

    @property
    def allowed(self) -> bool:
        return self.action == "pass"


class PolicyEvaluator:
    def __init__(self, intent: Intent):
        self.intent = intent
        self._interfaces = {interface.token: interface for interface in intent.interfaces}
        # "(self)": every address the firewall answers on
        self._self_ips = (
            {interface.address for interface in intent.interfaces if interface.address}
            | set(intent.vips)
            | {"127.0.0.1"}
        )

    # -- matching helpers --------------------------------------------------

    def _net_contains(self, token: str, address: str, invert: bool) -> bool:
        result = self._net_contains_plain(token, address)
        return (not result) if invert else result

    def _net_contains_plain(self, token: str, address: str) -> bool:
        parsed_address = ipaddress.ip_address(address)
        if token == "any":
            return True
        if token == "(self)":
            return address in self._self_ips
        if token.endswith("ip") and token[:-2] in self._interfaces:
            return address == self._interfaces[token[:-2]].address
        if token in self._interfaces:
            cidr = self._interfaces[token].cidr
            return bool(cidr) and parsed_address in ipaddress.ip_network(cidr)
        alias = self.intent.alias(token)
        if alias is not None:
            return any(
                parsed_address in ipaddress.ip_network(entry, strict=False)
                for entry in alias.content
                if _looks_like_net(entry)
            )
        if _looks_like_net(token):
            return parsed_address in ipaddress.ip_network(token, strict=False)
        return False

    def _port_matches(self, token: str, port: int | None) -> bool:
        if not token:
            return True
        if port is None:
            return False
        alias = self.intent.alias(token)
        entries = alias.content if alias is not None else [token]
        for entry in entries:
            if ":" in entry:
                range_start, range_end = entry.split(":")
                if int(range_start) <= port <= int(range_end):
                    return True
            elif entry.isdigit() and int(entry) == port:
                return True
        return False

    @staticmethod
    def _protocol_matches(rule_protocol: str, packet_protocol: str) -> bool:
        rule_protocol = rule_protocol.lower()
        if rule_protocol == "any":
            return True
        if rule_protocol == "tcp/udp":
            return packet_protocol in ("tcp", "udp")
        return rule_protocol == packet_protocol.lower()

    def _matches(self, rule: Rule, packet: Packet) -> bool:
        return (
            packet.in_interface in rule.interface
            and self._protocol_matches(rule.protocol, packet.protocol)
            and self._net_contains(rule.source_net, packet.source_ip, rule.source_invert)
            and self._net_contains(
                rule.destination_net, packet.destination_ip, rule.destination_invert
            )
            and self._port_matches(rule.destination_port, packet.destination_port)
        )

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, packet: Packet) -> Decision:
        last_match: Rule | None = None
        for rule in sorted(self.intent.rules, key=lambda candidate: candidate.sequence):
            if not rule.enabled or rule.direction != "in":
                continue
            if self._matches(rule, packet):
                if rule.quick:
                    return Decision(rule.action, rule)
                last_match = rule
        if last_match is not None:
            return Decision(last_match.action, last_match)
        return Decision("block", None)  # implicit default deny


def _looks_like_net(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False
