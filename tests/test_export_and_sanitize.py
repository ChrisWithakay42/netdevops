"""Export parsing and secret redaction, against the synthetic fixture."""

import xml.etree.ElementTree as ET

import pytest

from netdevops.export import parse_export, write_intent
from netdevops.intent import load_intent
from netdevops.sanitize import REDACTED, sanitize_file, sanitize_tree


def test_parse_export_counts(synthetic_export):
    intent = parse_export(synthetic_export)
    assert len(intent.aliases) == 2
    assert len(intent.rules) == 3
    assert len(intent.snat_rules) == 1
    # lo0 and disabled interfaces are excluded; only CARP VIPs are collected
    assert {interface.token for interface in intent.interfaces} == {"wan", "lan", "opt1"}
    assert intent.vips == ["192.168.1.2"]


def test_parse_export_field_fidelity(synthetic_export):
    intent = parse_export(synthetic_export)

    web_rule = next(rule for rule in intent.rules if rule.description == "Allow LAN web out")
    assert web_rule.destination_port == "_Web_Ports"
    assert web_rule.quick is True and web_rule.log is True

    unnamed_rule = next(rule for rule in intent.rules if rule.sequence == 200)
    assert unnamed_rule.description == "UNNAMED seq 200"
    assert unnamed_rule.destination_invert is True
    assert unnamed_rule.quick is False

    quic_rule = next(rule for rule in intent.rules if "QUIC" in rule.description)
    assert quic_rule.enabled is False
    assert quic_rule.action == "reject"

    lan_interface = next(
        interface for interface in intent.interfaces if interface.token == "lan"
    )
    assert lan_interface.cidr == "192.168.1.0/24"
    assert lan_interface.name == "LAN"  # empty descr falls back to the token


def test_import_roundtrip(synthetic_export, tmp_path):
    write_intent(parse_export(synthetic_export), tmp_path)
    reloaded = load_intent(tmp_path)
    assert len(reloaded.rules) == 3
    assert reloaded.vips == ["192.168.1.2"]


def test_sanitize_redacts_fixture_secrets(synthetic_export, tmp_path):
    sanitized_path = sanitize_file(synthetic_export, tmp_path)
    sanitized_text = sanitized_path.read_text()
    assert "$2y$" not in sanitized_text
    assert "fakecarppassword" not in sanitized_text
    assert "fakesyncpassword" not in sanitized_text
    assert "FAKESEED" not in sanitized_text
    assert "RkFLRS1QUklWQVRFLUtFWQ==" not in sanitized_text  # cert private key
    assert "UFVCTElDLUNFUlQtT0s=" in sanitized_text  # public cert kept


def test_sanitize_redacts_secret_tags():
    xml_text = (
        "<opnsense><system>"
        "<user><password>$2y$11$hash</password><otp_seed>ABC</otp_seed></user>"
        "</system>"
        "<hasync><password>plaintext!</password></hasync>"
        "<vip><password>carppw</password></vip>"
        "<cert><prv>LS0tBASE64</prv><crt>public-ok</crt></cert>"
        "</opnsense>"
    )
    tree = ET.ElementTree(ET.fromstring(xml_text))
    assert sanitize_tree(tree) == 5
    dumped = ET.tostring(tree.getroot(), encoding="unicode")
    assert "$2y$" not in dumped
    assert "public-ok" in dumped  # public cert kept
    assert dumped.count(REDACTED) == 5


def test_sanitize_file_refuses_leaky_output(tmp_path):
    # a bcrypt hash outside any known secret tag must trip the canary check
    source_path = tmp_path / "config.xml"
    source_path.write_text("<opnsense><oddtag>$2y$11$sneaky</oddtag></opnsense>")
    with pytest.raises(RuntimeError, match="sanitization incomplete"):
        sanitize_file(source_path, tmp_path / "out")
    assert not (tmp_path / "out" / "config.xml").exists()
