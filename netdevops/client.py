"""Thin OPNsense API client (firewall Automation endpoints, IP-alias VIPs,
config backup).

In an HA pair only the primary is ever targeted: OPNsense HA-sync (XMLRPC)
replicates aliases/rules/NAT to the secondary; pushing to both would fight
the sync.

Every set/del is guarded. OPNsense's setRule/setItem with an unknown uuid
silently creates a new object from model defaults (for a filter rule:
pass any -> any on every interface), and getRule/getItem answers 200 with an
or template object (on 26.7, alias/getItem/<unknown> returns a populated
template). So a write goes ahead only when the uuid is well-formed and the
bulk listing (alias/get, filter/get, vip_settings/get) holds it with the
identity the caller expects.

All read endpoints return the raw MVC model tree; `flatten_row` converts the
per-field {option: {value, selected}} structures into plain strings so the
diff engine can compare live state against intent.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import httpx

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class WriteGuardError(RuntimeError):
    """A write was refused because its target could not be proven to exist."""


def _ssl_verify_from_env() -> bool | str:
    """OPNSENSE_SSL_VERIFY: "1" (default), "0", or a path to the firewall's certificate.

    OPNsense ships a self-signed certificate, so the path form is how to keep
    verification on without a publicly trusted CA. "0" must be set explicitly:
    the API secret and backup's config.xml travel over this connection.
    """
    value = os.environ.get("OPNSENSE_SSL_VERIFY", "1")
    if value in ("0", "1"):
        return value == "1"
    if not Path(value).is_file():
        raise SystemExit(f"OPNSENSE_SSL_VERIFY: no such certificate file {value!r}")
    return value


class OPNsenseClient:
    def __init__(
        self, host: str, api_key: str, api_secret: str, ssl_verify: bool | str = False
    ):
        self.host = host
        self._http = httpx.Client(
            base_url=f"https://{host}",
            auth=(api_key, api_secret),
            verify=ssl_verify,
            timeout=30.0,
        )

    @classmethod
    def from_env(cls) -> OPNsenseClient:
        # No default for OPNSENSE_HOST: a forgotten environment variable
        # should fail here rather than target the wrong box.
        try:
            host = os.environ["OPNSENSE_HOST"]
            api_key = os.environ["OPNSENSE_API_KEY"]
            api_secret = os.environ["OPNSENSE_API_SECRET"]
        except KeyError as missing_variable:
            raise SystemExit(
                f"environment variable {missing_variable} is not set (see README)"
            ) from missing_variable
        return cls(
            host=host,
            api_key=api_key,
            api_secret=api_secret,
            ssl_verify=_ssl_verify_from_env(),
        )

    def _get(self, path: str) -> Any:
        response = self._http.get(path)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, payload: dict | None = None) -> Any:
        response = self._http.post(path, json=payload or {})
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict) and data.get("result") == "failed":
            raise RuntimeError(f"API rejected {path}: {data}")
        return data

    # -- reads ------------------------------------------------------------

    def get_aliases(self) -> dict[str, dict]:
        """uuid -> raw alias model."""
        tree = self._get("/api/firewall/alias/get")
        return tree.get("alias", {}).get("aliases", {}).get("alias", {}) or {}

    def get_filter_model(self) -> tuple[dict[str, dict], dict[str, dict]]:
        """(uuid -> raw filter rule, uuid -> raw snat rule)."""
        tree = self._get("/api/firewall/filter/get")
        filter_model = tree.get("filter", {})
        rules = filter_model.get("rules", {}).get("rule", {}) or {}
        snat_rules = filter_model.get("snatrules", {}).get("rule", {}) or {}
        return rules, snat_rules

    def get_vips(self) -> dict[str, dict]:
        """uuid -> raw virtual IP model (all modes; callers filter)."""
        tree = self._get("/api/interfaces/vip_settings/get")
        return tree.get("vip", {}).get("vip", {}) or {}

    # -- guarded writes ---------------------------------------------------

    _IDENTITY = {"alias": "name", "rule": "description", "snat": "description", "vip": "network"}

    def _bulk(self, kind: str) -> dict[str, dict]:
        if kind == "alias":
            return self.get_aliases()
        if kind in ("rule", "snat"):
            rules, snat_rules = self.get_filter_model()
            return rules if kind == "rule" else snat_rules
        return self.get_vips()

    def _require_existing(self, kind: str, uuid: str, payload: dict | None) -> None:
        """Refuse unless `uuid` is well-formed and in the bulk listing for `kind`.

        For a set, the live object's identity field must also equal the
        payload's, so a uuid that points at a different object is refused too.
        """
        if not UUID_RE.match(uuid or ""):
            raise WriteGuardError(f"refusing write: malformed uuid {uuid!r}")
        live = self._bulk(kind).get(uuid)
        if not isinstance(live, dict) or not live:
            raise WriteGuardError(f"refusing write: {kind} {uuid} does not exist")
        if payload is not None:
            row = flatten_row(live)
            key_field = self._IDENTITY[kind]
            if kind == "vip":
                row["network"] = f"{row.get('subnet', '')}/{row.get('subnet_bits', '')}"
            if row.get(key_field, "") != payload.get(key_field):
                raise WriteGuardError(
                    f"refusing write: {kind} {uuid} is {row.get(key_field, '')!r}, "
                    f"expected {payload.get(key_field)!r}"
                )

    def _delete(self, path: str) -> None:
        data = self._post(path)
        if not isinstance(data, dict) or data.get("result") != "deleted":
            raise WriteGuardError(f"{path}: delete not confirmed, reply {data!r}")

    def _add(self, path: str, body: dict) -> str:
        data = self._post(path, body)
        uuid = data.get("uuid") if isinstance(data, dict) else None
        if not UUID_RE.match(uuid or ""):
            raise WriteGuardError(f"{path}: no uuid in reply {data!r}")
        return uuid

    def add_alias(self, payload: dict) -> str:
        return self._add("/api/firewall/alias/addItem", {"alias": payload})

    def set_alias(self, uuid: str, payload: dict) -> None:
        self._require_existing("alias", uuid, payload)
        self._post(f"/api/firewall/alias/setItem/{uuid}", {"alias": payload})

    def del_alias(self, uuid: str) -> None:
        self._require_existing("alias", uuid, None)
        self._delete(f"/api/firewall/alias/delItem/{uuid}")

    def add_rule(self, payload: dict) -> str:
        return self._add("/api/firewall/filter/addRule", {"rule": payload})

    def set_rule(self, uuid: str, payload: dict) -> None:
        self._require_existing("rule", uuid, payload)
        self._post(f"/api/firewall/filter/setRule/{uuid}", {"rule": payload})

    def del_rule(self, uuid: str) -> None:
        self._require_existing("rule", uuid, None)
        self._delete(f"/api/firewall/filter/delRule/{uuid}")

    def add_snat(self, payload: dict) -> str:
        return self._add("/api/firewall/source_nat/addRule", {"rule": payload})

    def set_snat(self, uuid: str, payload: dict) -> None:
        self._require_existing("snat", uuid, payload)
        self._post(f"/api/firewall/source_nat/setRule/{uuid}", {"rule": payload})

    def del_snat(self, uuid: str) -> None:
        self._require_existing("snat", uuid, None)
        self._delete(f"/api/firewall/source_nat/delRule/{uuid}")

    def add_vip(self, payload: dict) -> str:
        return self._add("/api/interfaces/vip_settings/addItem", {"vip": payload})

    def set_vip(self, uuid: str, payload: dict) -> None:
        self._require_existing("vip", uuid, payload)
        self._post(f"/api/interfaces/vip_settings/setItem/{uuid}", {"vip": payload})

    def del_vip(self, uuid: str) -> None:
        self._require_existing("vip", uuid, None)
        self._delete(f"/api/interfaces/vip_settings/delItem/{uuid}")

    # -- activation -------------------------------------------------------

    def reconfigure_aliases(self) -> None:
        self._post("/api/firewall/alias/reconfigure")

    def reconfigure_vips(self) -> None:
        self._post("/api/interfaces/vip_settings/reconfigure")

    def apply_filter(self) -> None:
        """Load the saved filter + source NAT rules into pf."""
        self._post("/api/firewall/filter/apply")

    # -- backup -----------------------------------------------------------

    def download_config(self) -> bytes:
        response = self._http.get("/api/core/backup/download/this")
        response.raise_for_status()
        return response.content


def flatten_row(row: dict) -> dict:
    """Collapse OPNsense MVC field structures into plain string values.

    Select-style fields come back as {"optionKey": {"value": "...", "selected": 1}, ...};
    the flat value is the comma-joined selected option keys. Scalar fields pass through.
    """
    flat: dict[str, str] = {}
    for key, value in row.items():
        if isinstance(value, dict):
            selected = [
                option_name
                for option_name, option in value.items()
                if isinstance(option, dict) and option.get("selected")
            ]
            flat[key] = ",".join(selected)
        else:
            flat[key] = "" if value is None else str(value)
    return flat
