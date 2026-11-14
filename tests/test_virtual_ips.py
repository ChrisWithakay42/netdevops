"""IP-alias virtual IPs: model validation, diff, import."""

import pytest

from netdevops.diff import build_plan, live_vip_rows, vip_payload
from netdevops.export import parse_export
from netdevops.models import Intent, Interface, VirtualIP

DNS_VIP = VirtualIP(address="10.20.0.53/32", interface="lo0", description="DNS VIP")
ADM = Interface(token="opt5", name="ADM", cidr="10.20.50.0/24", address="10.20.50.1")

# vip_settings/get as the client flattens it
LIVE_DNS_VIP = {
    "nobind": "0",
    "mode": "ipalias",
    "interface": "lo0",
    "subnet": "10.20.0.53",
    "subnet_bits": "32",
    "descr": "DNS VIP",
}


def plan_for(intent, live_vips):
    return build_plan(intent, {}, {}, {}, live_vips=live_vip_rows(live_vips))


def test_vip_requires_prefix_length():
    with pytest.raises(ValueError):
        VirtualIP(address="10.20.0.53", interface="lo0")


def test_vip_accepts_loopback_interface():
    assert DNS_VIP.interface == "lo0"


def test_old_gateway_vip_must_keep_its_network_prefix():
    # 192.168.50.1/32 on ADM would leave no connected route to 192.168.50.0/29
    with pytest.raises(ValueError, match="prefix"):
        Intent(
            interfaces=[ADM],
            virtual_ips=[VirtualIP(address="192.168.50.1/32", interface="opt5")],
        )
    Intent(
        interfaces=[ADM],
        virtual_ips=[VirtualIP(address="192.168.50.1/29", interface="opt5")],
    )


def test_duplicate_vip_address_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        Intent(virtual_ips=[DNS_VIP, DNS_VIP])


def test_vip_payload_uses_combined_network_field():
    assert vip_payload(DNS_VIP) == {
        "mode": "ipalias",
        "interface": "lo0",
        "network": "10.20.0.53/32",
        "descr": "DNS VIP",
        "nobind": "0",
    }


def test_plan_creates_missing_vip():
    plan = plan_for(Intent(virtual_ips=[DNS_VIP]), {})
    assert [(change.kind, change.label) for change in plan.creates] == [
        ("vip", "10.20.0.53/32")
    ]


def test_plan_clean_when_live_matches():
    plan = plan_for(Intent(virtual_ips=[DNS_VIP]), {"u1": LIVE_DNS_VIP})
    assert plan.empty and not plan.unmanaged


def test_plan_ignores_carp_vips():
    carp = LIVE_DNS_VIP | {"mode": "carp", "subnet": "192.168.1.2"}
    plan = plan_for(Intent(), {"u1": carp})
    assert plan.empty and not plan.unmanaged


def test_vips_are_never_pruned():
    plan = plan_for(Intent(), {"u1": LIVE_DNS_VIP})
    assert [change.kind for change in plan.unmanaged] == ["vip"]
    assert plan.prunable() == []


def test_import_collects_ipalias_vips(synthetic_export):
    intent = parse_export(synthetic_export)
    assert intent.virtual_ips == [
        VirtualIP(address="192.168.1.3/32", interface="lan", description="DNS alias")
    ]


def test_nobind_is_managed():
    vip = VirtualIP(address="10.20.0.53/32", interface="lo0", description="DNS VIP", nobind=True)
    assert vip_payload(vip)["nobind"] == "1"
    assert vip_payload(DNS_VIP)["nobind"] == "0"
    live = LIVE_DNS_VIP | {"nobind": "0"}
    plan = plan_for(Intent(virtual_ips=[vip]), {"u1": live})
    assert [change.changed for change in plan.updates] == [["nobind"]]


def test_import_reads_nobind(synthetic_export, tmp_path):
    from netdevops.export import parse_export

    xml = synthetic_export.read_text().replace(
        "<descr>DNS alias</descr>", "<descr>DNS alias</descr>\n      <nobind>1</nobind>"
    )
    path = tmp_path / "config.xml"
    path.write_text(xml)
    (vip,) = parse_export(path).virtual_ips
    assert vip.nobind is True
