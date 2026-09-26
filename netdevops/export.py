"""Parse an OPNsense config.xml export into Intent data, and write intent YAML.

This is the adoption/resync path:

    netdevops import exports/raw/<export>.xml

Reads the API-managed ("Automation") firewall sections plus interface
definitions. Regenerating over an existing network/ directory and inspecting
`git diff` shows exactly what changed out-of-band on the firewall.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from .models import Alias, Intent, Interface, Rule, SnatRule

HEADER = (
    "# Source of truth for the OPNsense firewall policy.\n"
    "# Edit, open an MR, and apply with `netdevops apply`.\n"
    "# Regenerate from a fresh export with `netdevops import <export.xml>`.\n"
    "---\n"
)


def _text(element: ET.Element, tag: str, default: str = "") -> str:
    value = element.findtext(tag)
    return value if value is not None else default


def _flag(element: ET.Element, tag: str) -> bool:
    return _text(element, tag) == "1"


def parse_export(path: str | Path) -> Intent:
    root = ET.parse(path).getroot()

    aliases = []
    for alias_element in root.findall("OPNsense/Firewall/Alias/aliases/alias"):
        aliases.append(
            Alias(
                name=_text(alias_element, "name"),
                type=_text(alias_element, "type"),  # type: ignore[arg-type]
                content=[line for line in _text(alias_element, "content").split("\n") if line],
                description=_text(alias_element, "description"),
                enabled=_flag(alias_element, "enabled"),
            )
        )

    rules = []
    for rule_element in root.findall("OPNsense/Firewall/Filter/rules/rule"):
        rules.append(
            Rule(
                description=_text(rule_element, "description")
                or f"UNNAMED seq {_text(rule_element, 'sequence')}",
                interface=_text(rule_element, "interface").split(","),
                sequence=int(_text(rule_element, "sequence") or 0),
                action=_text(rule_element, "action"),  # type: ignore[arg-type]
                direction=_text(rule_element, "direction") or "in",
                ip_protocol=_text(rule_element, "ipprotocol") or "inet",  # type: ignore[arg-type]
                protocol=_text(rule_element, "protocol") or "any",
                source_net=_text(rule_element, "source_net") or "any",
                source_invert=_flag(rule_element, "source_not"),
                source_port=_text(rule_element, "source_port"),
                destination_net=_text(rule_element, "destination_net") or "any",
                destination_invert=_flag(rule_element, "destination_not"),
                destination_port=_text(rule_element, "destination_port"),
                quick=_flag(rule_element, "quick"),
                log=_flag(rule_element, "log"),
                enabled=_flag(rule_element, "enabled"),
            )
        )
    rules.sort(key=lambda rule: rule.sequence)

    snat_rules = []
    for snat_element in root.findall("OPNsense/Firewall/Filter/snatrules/rule"):
        snat_rules.append(
            SnatRule(
                description=_text(snat_element, "description")
                or f"UNNAMED snat seq {_text(snat_element, 'sequence')}",
                interface=_text(snat_element, "interface"),
                sequence=int(_text(snat_element, "sequence") or 0),
                ip_protocol=_text(snat_element, "ipprotocol") or "inet",  # type: ignore[arg-type]
                protocol=_text(snat_element, "protocol") or "any",
                source_net=_text(snat_element, "source_net") or "any",
                destination_net=_text(snat_element, "destination_net") or "any",
                target=_text(snat_element, "target"),
                log=_flag(snat_element, "log"),
                enabled=_flag(snat_element, "enabled"),
            )
        )
    snat_rules.sort(key=lambda snat_rule: snat_rule.sequence)

    interfaces = []
    interfaces_section = root.find("interfaces")
    if interfaces_section is not None:
        for interface_element in interfaces_section:
            token = interface_element.tag
            if token == "lo0" or not _flag(interface_element, "enable"):
                continue
            address = _text(interface_element, "ipaddr")
            prefix_length = _text(interface_element, "subnet")
            cidr = ""
            if address and prefix_length:
                cidr = str(ipaddress.ip_network(f"{address}/{prefix_length}", strict=False))
            interfaces.append(
                Interface(
                    token=token,
                    device=_text(interface_element, "if"),
                    name=_text(interface_element, "descr") or token.upper(),
                    cidr=cidr,
                    address=address,
                )
            )

    vips = []
    virtualip_section = root.find("virtualip")
    if virtualip_section is not None:
        for vip_element in virtualip_section:
            if _text(vip_element, "mode") == "carp" and _text(vip_element, "subnet"):
                vips.append(_text(vip_element, "subnet"))

    return Intent(
        aliases=aliases, rules=rules, snat_rules=snat_rules, interfaces=interfaces, vips=vips
    )


def write_intent(intent: Intent, directory: str | Path = "network") -> list[Path]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    output_files = {
        "aliases.yml": {"aliases": [alias.model_dump() for alias in intent.aliases]},
        "rules.yml": {"rules": [rule.model_dump() for rule in intent.rules]},
        "nat.yml": {"snat_rules": [snat_rule.model_dump() for snat_rule in intent.snat_rules]},
        "interfaces.yml": {
            "interfaces": [interface.model_dump() for interface in intent.interfaces],
            "vips": intent.vips,
        },
    }
    written_paths = []
    for filename, data in output_files.items():
        path = directory / filename
        body = yaml.safe_dump(data, sort_keys=False, default_flow_style=False, width=100)
        path.write_text(HEADER + body)
        written_paths.append(path)
    return written_paths
