"""Typed models for the network intent, with validation.

The YAML files under network/ deserialize into these models; anything that
loads is structurally valid. Cross-object rules (alias references, duplicate
match keys, sequence collisions) are enforced on the Intent container.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# Tokens OPNsense accepts natively as source/destination networks.
# "(self)" = every address owned by the firewall (interface addresses + VIPs).
BUILTIN_NETS = (
    {"any", "lan", "wan", "lanip", "wanip", "(self)"}
    | {f"opt{index}" for index in range(1, 17)}
    | {f"opt{index}ip" for index in range(1, 17)}
)

VALID_INTERFACES = {"lan", "wan"} | {f"opt{index}" for index in range(1, 17)}

PORT_RE = re.compile(r"^\d{1,5}(:\d{1,5})?$")
ALIAS_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,31}$")
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.-]+$")


def is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


class Alias(BaseModel):
    name: str
    type: Literal["host", "network", "port", "url", "urltable", "geoip", "mac", "external"]
    content: list[str] = Field(default_factory=list)
    description: str = ""
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not ALIAS_NAME_RE.match(value):
            raise ValueError(f"invalid alias name {value!r}")
        return value

    @model_validator(mode="after")
    def _validate_content(self) -> Alias:
        for entry in self.content:
            if self.type == "port" and not PORT_RE.match(entry):
                raise ValueError(f"alias {self.name}: invalid port entry {entry!r}")
            if self.type == "network" and not is_cidr(entry):
                raise ValueError(f"alias {self.name}: invalid network entry {entry!r}")
            if self.type == "host" and not (is_cidr(entry) or HOSTNAME_RE.match(entry)):
                raise ValueError(f"alias {self.name}: invalid host entry {entry!r}")
        return self


class Rule(BaseModel):
    description: str = Field(min_length=1)  # match key: must be unique per interface
    interface: list[str] = Field(min_length=1)
    sequence: int = Field(ge=1, le=999999)
    action: Literal["pass", "block", "reject"]
    direction: Literal["in", "out"] = "in"
    ip_protocol: Literal["inet", "inet6", "inet46"] = "inet"
    protocol: str = "any"
    source_net: str = "any"
    source_invert: bool = False
    source_port: str = ""
    destination_net: str = "any"
    destination_invert: bool = False
    destination_port: str = ""
    quick: bool = True
    log: bool = False
    enabled: bool = True

    @field_validator("interface")
    @classmethod
    def _validate_interfaces(cls, value: list[str]) -> list[str]:
        for interface_name in value:
            if interface_name not in VALID_INTERFACES:
                raise ValueError(f"unknown interface {interface_name!r}")
        return value

    @field_validator("source_port", "destination_port")
    @classmethod
    def _validate_ports(cls, value: str) -> str:
        # port aliases are validated at Intent level (need the alias table)
        if value and not PORT_RE.match(value) and not ALIAS_NAME_RE.match(value):
            raise ValueError(f"invalid port {value!r}")
        return value


class SnatRule(BaseModel):
    description: str = Field(min_length=1)
    interface: str
    sequence: int = Field(ge=1, le=999999)
    ip_protocol: Literal["inet", "inet6", "inet46"] = "inet"
    protocol: str = "any"
    source_net: str = "any"
    destination_net: str = "any"
    target: str
    log: bool = False
    enabled: bool = True


class Interface(BaseModel):
    """Documentation + policy-simulation data; not pushed to the firewall."""

    token: str  # lan / wan / optN, the identifier used in rules
    device: str = ""
    name: str = ""
    cidr: str = ""
    address: str = ""


class Intent(BaseModel):
    aliases: list[Alias] = Field(default_factory=list)
    rules: list[Rule] = Field(default_factory=list)
    snat_rules: list[SnatRule] = Field(default_factory=list)
    interfaces: list[Interface] = Field(default_factory=list)
    vips: list[str] = Field(default_factory=list)  # CARP VIPs, part of "(self)"

    @field_validator("vips")
    @classmethod
    def _validate_vips(cls, value: list[str]) -> list[str]:
        for address in value:
            ipaddress.ip_address(address)
        return value

    def alias(self, name: str) -> Alias | None:
        return next((alias for alias in self.aliases if alias.name == name), None)

    def _valid_net(self, value: str) -> bool:
        return value in BUILTIN_NETS or self.alias(value) is not None or is_cidr(value)

    @model_validator(mode="after")
    def _cross_checks(self) -> Intent:
        errors: list[str] = []

        alias_names = [alias.name for alias in self.aliases]
        for duplicate in {name for name in alias_names if alias_names.count(name) > 1}:
            errors.append(f"duplicate alias name {duplicate!r}")

        seen_match_keys: set[tuple[str, str]] = set()
        sequence_owners: dict[int, str] = {}
        for rule in self.rules:
            label = f"rule '{rule.description}'"
            for interface_name in rule.interface:
                match_key = (interface_name, rule.description)
                if match_key in seen_match_keys:
                    errors.append(
                        f"{label}: duplicate (interface={interface_name}, description) match key"
                    )
                seen_match_keys.add(match_key)
            if rule.sequence in sequence_owners:
                errors.append(
                    f"{label}: sequence {rule.sequence} already used by "
                    f"'{sequence_owners[rule.sequence]}'"
                )
            sequence_owners[rule.sequence] = rule.description

            for field_name in ("source_net", "destination_net"):
                value = getattr(rule, field_name)
                if not self._valid_net(value):
                    errors.append(
                        f"{label}: {field_name} {value!r} is not an alias, builtin, or CIDR"
                    )
            for field_name in ("source_port", "destination_port"):
                value = getattr(rule, field_name)
                if value and not PORT_RE.match(value):
                    port_alias = self.alias(value)
                    if port_alias is None or port_alias.type != "port":
                        errors.append(
                            f"{label}: {field_name} {value!r} is not a port/range or port alias"
                        )

        for snat_rule in self.snat_rules:
            label = f"snat '{snat_rule.description}'"
            for field_name in ("source_net", "destination_net"):
                value = getattr(snat_rule, field_name)
                if not self._valid_net(value):
                    errors.append(
                        f"{label}: {field_name} {value!r} is not an alias, builtin, or CIDR"
                    )
            if snat_rule.target and not self._valid_net(snat_rule.target):
                errors.append(
                    f"{label}: target {snat_rule.target!r} is not an alias, builtin, or IP"
                )

        if errors:
            raise ValueError("\n".join(errors))
        return self
