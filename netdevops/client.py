"""Thin OPNsense API client (firewall Automation endpoints + config backup).

Only the HA primary is ever targeted: OPNsense HA-sync (XMLRPC) replicates
aliases/rules/NAT to the secondary; pushing to both nodes would fight the sync.

All read endpoints return the raw MVC model tree; `flatten_row` converts the
per-field {option: {value, selected}} structures into plain strings so the
diff engine can compare live state against intent.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx


def _ssl_verify_from_env() -> bool | str:
    """OPNSENSE_SSL_VERIFY: "0"/"1", or a path to the firewall's certificate.

    OPNsense ships a self-signed certificate, so the path form is how to keep
    verification on without a publicly trusted CA.
    """
    value = os.environ.get("OPNSENSE_SSL_VERIFY", "0")
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

    # -- writes -----------------------------------------------------------

    def add_alias(self, payload: dict) -> None:
        self._post("/api/firewall/alias/addItem", {"alias": payload})

    def set_alias(self, uuid: str, payload: dict) -> None:
        self._post(f"/api/firewall/alias/setItem/{uuid}", {"alias": payload})

    def del_alias(self, uuid: str) -> None:
        self._post(f"/api/firewall/alias/delItem/{uuid}")

    def add_rule(self, payload: dict) -> None:
        self._post("/api/firewall/filter/addRule", {"rule": payload})

    def set_rule(self, uuid: str, payload: dict) -> None:
        self._post(f"/api/firewall/filter/setRule/{uuid}", {"rule": payload})

    def del_rule(self, uuid: str) -> None:
        self._post(f"/api/firewall/filter/delRule/{uuid}")

    def add_snat(self, payload: dict) -> None:
        self._post("/api/firewall/source_nat/addRule", {"rule": payload})

    def set_snat(self, uuid: str, payload: dict) -> None:
        self._post(f"/api/firewall/source_nat/setRule/{uuid}", {"rule": payload})

    def del_snat(self, uuid: str) -> None:
        self._post(f"/api/firewall/source_nat/delRule/{uuid}")

    def apply(self) -> None:
        """Activate pending alias + rule changes."""
        self._post("/api/firewall/alias/reconfigure")
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
