"""Client write guards: no set/del may reach a uuid the firewall doesn't hold.

OPNsense's setRule/setItem with an unknown uuid does not fail: it creates a
new object from model defaults. For a filter rule that default is
"pass in quick, any -> any, on every interface". The per-item getters can't
prove existence either: on 26.7, filter/getRule/<unknown> answers [] but
alias/getItem/<unknown> answers a populated template. So existence and
identity are read from the bulk listing (filter/get, alias/get, ...).
"""

import json

import httpx
import pytest

from netdevops.client import OPNsenseClient, WriteGuardError

GOOD_UUID = "cacee62f-8340-4b50-8349-3fc2da9e66d9"


def bulk(rules=None, snat=None, aliases=None, vips=None):
    return {
        "/api/firewall/filter/get": {
            "filter": {"rules": {"rule": rules or {}}, "snatrules": {"rule": snat or {}}}
        },
        "/api/firewall/alias/get": {"alias": {"aliases": {"alias": aliases or {}}}},
        "/api/interfaces/vip_settings/get": {"vip": {"vip": vips or {}}},
    }


def make_client(get_responses: dict[str, object], post_reply=None):
    """A client whose GETs answer from get_responses; every request is recorded."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=get_responses.get(request.url.path, {}))
        if post_reply is not None:
            return httpx.Response(200, json=post_reply)
        if "/del" in request.url.path:
            return httpx.Response(200, json={"result": "deleted"})
        return httpx.Response(200, json={"result": "saved", "uuid": GOOD_UUID})

    client = OPNsenseClient("fw.test", "key", "secret")
    client._http = httpx.Client(
        base_url="https://fw.test", transport=httpx.MockTransport(handler)
    )
    return client, requests


def posts(requests):
    return [request for request in requests if request.method == "POST"]


RULE_PAYLOAD = {"description": "Allow web", "action": "pass"}


@pytest.mark.parametrize("bad_uuid", ["", "not-a-uuid", "../addRule", GOOD_UUID + "x"])
def test_set_rule_rejects_malformed_uuid_without_any_request(bad_uuid):
    client, requests = make_client({})
    with pytest.raises(WriteGuardError):
        client.set_rule(bad_uuid, RULE_PAYLOAD)
    assert requests == []


def test_set_rule_refuses_when_uuid_is_unknown():
    other = "11111111-1111-4111-8111-111111111111"
    client, requests = make_client(bulk(rules={other: {"description": "Allow web"}}))
    with pytest.raises(WriteGuardError):
        client.set_rule(GOOD_UUID, RULE_PAYLOAD)
    assert posts(requests) == []


def test_set_rule_refuses_when_live_object_is_a_different_rule():
    client, requests = make_client(bulk(rules={GOOD_UUID: {"description": "Other"}}))
    with pytest.raises(WriteGuardError):
        client.set_rule(GOOD_UUID, RULE_PAYLOAD)
    assert posts(requests) == []


def test_set_rule_writes_when_identity_matches():
    client, requests = make_client(bulk(rules={GOOD_UUID: {"description": "Allow web"}}))
    client.set_rule(GOOD_UUID, RULE_PAYLOAD)
    (post,) = posts(requests)
    assert post.url.path == f"/api/firewall/filter/setRule/{GOOD_UUID}"
    assert json.loads(post.content) == {"rule": RULE_PAYLOAD}


def test_set_alias_ignores_per_item_template():
    # alias/getItem/<unknown> returns a populated template on 26.7; the guard
    # must not be fooled by it
    responses = bulk() | {
        f"/api/firewall/alias/getItem/{GOOD_UUID}": {"alias": {"name": "DNS_SERVER"}}
    }
    client, requests = make_client(responses)
    with pytest.raises(WriteGuardError):
        client.set_alias(GOOD_UUID, {"name": "DNS_SERVER"})
    assert posts(requests) == []


def test_set_snat_checks_description():
    client, requests = make_client(bulk(snat={GOOD_UUID: {"description": "Other"}}))
    with pytest.raises(WriteGuardError):
        client.set_snat(GOOD_UUID, {"description": "NAT out"})
    assert posts(requests) == []


def test_set_vip_checks_network():
    live_vip = {"subnet": "192.168.30.5", "subnet_bits": "32"}
    client, requests = make_client(bulk(vips={GOOD_UUID: live_vip}))
    with pytest.raises(WriteGuardError):
        client.set_vip(GOOD_UUID, {"network": "10.20.0.53/32"})
    assert posts(requests) == []
    client.set_vip(GOOD_UUID, {"network": "192.168.30.5/32"})
    assert len(posts(requests)) == 1


@pytest.mark.parametrize("method", ["del_rule", "del_alias", "del_snat", "del_vip"])
def test_deletes_refuse_unknown_uuid(method):
    client, requests = make_client(bulk())
    with pytest.raises(WriteGuardError):
        getattr(client, method)(GOOD_UUID)
    assert posts(requests) == []


def test_delete_must_report_deleted():
    client, _ = make_client(
        bulk(rules={GOOD_UUID: {"description": "x"}}), post_reply={"result": "not found"}
    )
    with pytest.raises(WriteGuardError):
        client.del_rule(GOOD_UUID)


def test_add_returns_new_uuid():
    client, _ = make_client({})
    assert client.add_rule(RULE_PAYLOAD) == GOOD_UUID


def test_add_without_uuid_in_reply_fails():
    client, _ = make_client({}, post_reply={"result": "saved"})
    with pytest.raises(WriteGuardError):
        client.add_alias({"name": "X"})


def test_tls_verification_is_on_by_default(monkeypatch):
    from netdevops.client import _ssl_verify_from_env

    monkeypatch.delenv("OPNSENSE_SSL_VERIFY", raising=False)
    assert _ssl_verify_from_env() is True


@pytest.mark.parametrize(
    "method", ["reconfigure_aliases", "reconfigure_vips", "apply_filter"]
)
def test_activation_must_report_ok(method):
    client, _ = make_client({}, post_reply={"status": "failed"})
    with pytest.raises(RuntimeError):
        getattr(client, method)()
    client, _ = make_client({}, post_reply={"status": "OK\n\n"})
    getattr(client, method)()
