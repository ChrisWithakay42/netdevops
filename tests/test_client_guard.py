"""Client write guards: no set/del may reach a uuid the firewall doesn't hold.

OPNsense's setRule/setItem with an unknown uuid does not fail: it creates a
new object from model defaults. For a filter rule that default is
"pass in quick, any -> any, on every interface". getRule/getItem with an
unknown uuid also answers 200, with an empty or template object. So the guard
must check the uuid's shape and the re-read object's identity, not the
status code.
"""

import json

import httpx
import pytest

from netdevops.client import OPNsenseClient, WriteGuardError

GOOD_UUID = "cacee62f-8340-4b50-8349-3fc2da9e66d9"


def make_client(get_responses: dict[str, object]):
    """A client whose GETs answer from get_responses; every request is recorded."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            body = get_responses.get(request.url.path, {})
            return httpx.Response(200, json=body)
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


@pytest.mark.parametrize("reply", [{}, [], {"rule": {}}, {"rule": []}])
def test_set_rule_refuses_when_uuid_is_unknown(reply):
    client, requests = make_client({f"/api/firewall/filter/getRule/{GOOD_UUID}": reply})
    with pytest.raises(WriteGuardError):
        client.set_rule(GOOD_UUID, RULE_PAYLOAD)
    assert posts(requests) == []


def test_set_rule_refuses_when_live_object_is_a_different_rule():
    reply = {"rule": {"description": "Some other rule", "action": "block"}}
    client, requests = make_client({f"/api/firewall/filter/getRule/{GOOD_UUID}": reply})
    with pytest.raises(WriteGuardError):
        client.set_rule(GOOD_UUID, RULE_PAYLOAD)
    assert posts(requests) == []


def test_set_rule_writes_when_identity_matches():
    reply = {"rule": {"description": "Allow web", "action": "block"}}
    client, requests = make_client({f"/api/firewall/filter/getRule/{GOOD_UUID}": reply})
    client.set_rule(GOOD_UUID, RULE_PAYLOAD)
    (post,) = posts(requests)
    assert post.url.path == f"/api/firewall/filter/setRule/{GOOD_UUID}"
    assert json.loads(post.content) == {"rule": RULE_PAYLOAD}


def test_set_alias_checks_name():
    reply = {"alias": {"name": "OTHER"}}
    client, requests = make_client({f"/api/firewall/alias/getItem/{GOOD_UUID}": reply})
    with pytest.raises(WriteGuardError):
        client.set_alias(GOOD_UUID, {"name": "DNS_SERVER"})
    assert posts(requests) == []


def test_set_snat_checks_description():
    client, requests = make_client({f"/api/firewall/source_nat/getRule/{GOOD_UUID}": {}})
    with pytest.raises(WriteGuardError):
        client.set_snat(GOOD_UUID, {"description": "NAT out"})
    assert posts(requests) == []


def test_set_vip_checks_network():
    reply = {"vip": {"network": "192.168.30.5/32", "mode": {"ipalias": {"selected": 1}}}}
    client, requests = make_client({f"/api/interfaces/vip_settings/getItem/{GOOD_UUID}": reply})
    with pytest.raises(WriteGuardError):
        client.set_vip(GOOD_UUID, {"network": "10.20.0.53/32"})
    assert posts(requests) == []


@pytest.mark.parametrize(
    "method, get_path",
    [
        ("del_rule", "/api/firewall/filter/getRule/"),
        ("del_alias", "/api/firewall/alias/getItem/"),
        ("del_snat", "/api/firewall/source_nat/getRule/"),
        ("del_vip", "/api/interfaces/vip_settings/getItem/"),
    ],
)
def test_deletes_refuse_unknown_uuid(method, get_path):
    client, requests = make_client({get_path + GOOD_UUID: {}})
    with pytest.raises(WriteGuardError):
        getattr(client, method)(GOOD_UUID)
    assert posts(requests) == []


def test_add_returns_new_uuid():
    client, _ = make_client({})
    assert client.add_rule(RULE_PAYLOAD) == GOOD_UUID


def test_add_without_uuid_in_reply_fails():
    def handler(request):
        return httpx.Response(200, json={"result": "saved"})

    client = OPNsenseClient("fw.test", "key", "secret")
    client._http = httpx.Client(base_url="https://fw.test", transport=httpx.MockTransport(handler))
    with pytest.raises(WriteGuardError):
        client.add_alias({"name": "X"})
