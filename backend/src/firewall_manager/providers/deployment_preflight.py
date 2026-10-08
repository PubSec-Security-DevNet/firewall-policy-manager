# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Safe parsing of the documented FMC/cdFMC deployment evidence."""

import json
import re
from typing import Any, NoReturn

from firewall_manager.application.errors import ProviderContractError

ACCESS_POLICY_TYPE = "PG.FIREWALL.NGFWAccessControlPolicy"


def refuse(code: str = "DEPLOYMENT_SCOPE_UNPROVEN") -> NoReturn:
    raise ProviderContractError(details={"code": code})


def collection(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        refuse("DEPLOYMENT_INSPECTION_MALFORMED")
    paging = value.get("paging", {})
    items = value.get("items")
    # FMC returns no items key for a complete empty deployable-device collection.
    if items is None and isinstance(paging, dict) and paging.get("count") == 0:
        items = []
    if not isinstance(items, list):
        refuse("DEPLOYMENT_INSPECTION_MALFORMED")
    if (
        not isinstance(paging, dict)
        or paging.get("next")
        or not isinstance(paging.get("count", len(items)), int)
        or paging.get("count", len(items)) != len(items)
        or paging.get("offset", 0) != 0
        or type(paging.get("pages", 1)) is not int
        or paging.get("pages", 1) > 1
        or not all(isinstance(item, dict) for item in items)
    ):
        refuse("DEPLOYMENT_INSPECTION_INCOMPLETE")
    return items


def configuration(value: Any) -> Any:
    """Ignore response transport metadata, retain all actual configuration fields."""
    if isinstance(value, dict):
        return {
            k: configuration(v)
            for k, v in value.items()
            if k not in {"links", "metadata", "version"}
        }
    if isinstance(value, list):
        return [configuration(v) for v in value]
    return value


def expected_resources(
    intents: list[dict[str, Any]], domain_path: str
) -> dict[str, dict[str, Any]]:
    resources: dict[str, dict[str, Any]] = {}
    successful_attempts = {
        (
            str((intent.get("context") or {}).get("operation_id") or ""),
            str(intent.get("method") or ""),
            str(intent.get("path") or ""),
        )
        for intent in intents
        if isinstance(intent, dict) and 200 <= (intent.get("response") or {}).get("status", 0) < 300
    }
    for intent in intents:
        response = intent.get("response", {})
        status = response.get("status", 0)
        attempt_key = (
            str((intent.get("context") or {}).get("operation_id") or ""),
            str(intent.get("method") or ""),
            str(intent.get("path") or ""),
        )
        # A single FMC mutation may contain a definitive 401 followed by the
        # adapter's fenced re-authenticated retry. The failed attempt is not
        # mutation evidence when the same operation has a successful response.
        if not 200 <= status < 300 and attempt_key in successful_attempts:
            continue
        body = response.get("body", {})
        path = str(intent.get("path", ""))
        method = intent.get("method")
        # A recovered create may retain only the durable provider receipt.  It is
        # sufficient to recover/adopt the object, but it has no request path or
        # payload that can be used as deployment mutation evidence.  Pending
        # changes remain observable as provider-wide warnings during preflight.
        receipt_body = response.get("body", {})
        if (
            method == "POST"
            and not path
            and not intent.get("request")
            and isinstance(intent.get("context"), dict)
            and intent["context"].get("operation_id")
            and isinstance(receipt_body, dict)
            and 200 <= response.get("status", 0) < 300
            and (receipt_body.get("id") or receipt_body.get("uuid"))
        ):
            continue
        if (
            not path.startswith(domain_path + "/")
            or not isinstance(body, dict)
            or not 200 <= status < 300
        ):
            refuse("DEPLOYMENT_MUTATION_EVIDENCE_MISSING")
        native_id = str(body.get("id") or body.get("uuid") or "")
        if method == "DELETE":
            native_id = path.rsplit("/", 1)[-1]
        if not native_id or method not in {"POST", "PUT", "DELETE"}:
            refuse("DEPLOYMENT_MUTATION_EVIDENCE_MISSING")
        resources[native_id] = {
            **intent,
            "result": body,
            "resource_path": path + "/" + native_id if method == "POST" else path,
        }
    return resources


def _request_field(field_name: object, request: dict[str, Any]) -> str | None:
    """Map FMC display labels to request fields when the provider exposes them."""
    if not isinstance(field_name, str):
        return None
    if field_name in request:
        return field_name
    normalized = re.sub(r"[^a-z0-9]", "", field_name.lower())
    aliases = {
        "fromzone": "sourceZones",
        "tozone": "destinationZones",
        "rulename": "name",
        "ruleindex": "ruleIndex",
        "logatendofconnection": "logEnd",
        "logatbeginningofconnection": "logBegin",
        "syslogenabled": "enableSyslog",
        "sendeventstofmc": "sendEventsToFMC",
        "logfiles": "logFiles",
    }
    candidate = aliases.get(normalized, field_name)
    if candidate in request:
        return candidate
    for key in request:
        if re.sub(r"[^a-z0-9]", "", key.lower()) == normalized:
            return key
    return None


def check_changes(  # noqa: PLR0912 -- independent evidence checks
    changes: list[dict[str, Any]], expected: dict[str, dict[str, Any]]
) -> list[dict[str, object]]:
    """Validate known mutations and report, but do not block, unknown provider changes."""
    warnings: list[dict[str, object]] = []
    for change in changes:
        action = str(change.get("action", "")).upper()
        if action == "NOCHANGE" and not change.get("message"):
            continue
        for key in (
            "valueAdded",
            "valueDeleted",
            "valueUpdated",
            "referencesAdded",
            "referencesDeleted",
        ):
            if key in change and not isinstance(change[key], list):
                refuse("DEPLOYMENT_INSPECTION_MALFORMED")
        native_id = str(change.get("entityUUID") or "")
        intent = expected.get(native_id)
        if intent is None:
            warnings.append(
                {
                    key: change[key]
                    for key in (
                        "entityUUID",
                        "entityType",
                        "entityName",
                        "action",
                        "lastUpdatedByUsers",
                    )
                    if key in change
                }
            )
            continue
        if change.get("message") or change.get("errorMsg"):
            refuse()
        expected_action = {"POST": "ADD", "PUT": "UPDATE", "DELETE": "DELETE"}[intent["method"]]
        if action != expected_action:
            refuse()
        # A matching entity/user alone is insufficient: reject differences outside the
        # authorized request fields, and changed values that differ from that request.
        request = intent.get("request") or {}
        if intent["method"] == "PUT":
            context = intent.get("context") or {}
            before = context.get("preimage")
            if context.get("preimage_path") != intent["path"] or not isinstance(before, dict):
                refuse("DEPLOYMENT_MUTATION_EVIDENCE_MISSING")
            request = {
                k: v for k, v in request.items() if configuration(before.get(k)) != configuration(v)
            }
        delta_count = 0
        for key in (
            "valueAdded",
            "valueDeleted",
            "valueUpdated",
            "referencesAdded",
            "referencesDeleted",
        ):
            values = change.get(key, [])
            if not isinstance(values, list):
                refuse("DEPLOYMENT_INSPECTION_MALFORMED")
            delta_count += len(values)
            for delta in values:
                if not isinstance(delta, dict):
                    refuse("DEPLOYMENT_INSPECTION_MALFORMED")
                field = _request_field(delta.get("fieldName"), request)
                # FMC reports provider-generated display/default fields alongside the
                # requested values. They are part of the provider-wide deployment scope,
                # but are not application mutations that can be compared to our request.
                if field is None:
                    continue
                if "newValue" in delta:
                    wanted = request[field]
                    actual = delta["newValue"]
                    if (
                        str(wanted).lower() != str(actual).lower()
                        and json.dumps(wanted, sort_keys=True) != actual
                    ):
                        refuse()
        if action == "UPDATE" and not delta_count:
            refuse("DEPLOYMENT_MUTATION_EVIDENCE_MISSING")
    return warnings
