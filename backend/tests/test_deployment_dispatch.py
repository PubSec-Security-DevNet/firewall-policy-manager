# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Documented FMC/cdFMC preflight contracts; no live deployment is implied."""

import json
from copy import deepcopy

import httpx
import pytest

from firewall_manager.application.errors import ProviderContractError, ProviderError
from firewall_manager.domain.models import CapabilityStatus
from firewall_manager.providers.deployment_preflight import (
    ACCESS_POLICY_TYPE,
    check_changes,
    expected_resources,
)
from firewall_manager.providers.fmc import RealFmcProvider
from firewall_manager.providers.real import _AmbiguousMutationError
from firewall_manager.providers.scc import RealSccProvider


class CiscoDeploymentTransport:
    def __init__(self, scenario="clean"):
        self.scenario = scenario
        self.posts = []
        self.reads = 0
        self.external_edit = False
        self.resource = {
            "id": "object",
            "type": "Network",
            "name": "FPM",
            "value": "10.1.0.0/16",
            "version": "2",
        }
        self.device = {
            "id": "device",
            "device": {"id": "device"},
            "version": "123456",
            "deviceMembers": [{"id": "device"}],
            "groupDependencyDetails": {
                "mandatoryDeployablePolicies": [],
                "selectivelyDeployablePolicies": [ACCESS_POLICY_TYPE],
                "dependentPolicyList": [],
            },
            "canBeDeployed": True,
            "isDeploying": False,
            "policyStatusList": [
                {"policy": {"id": "policy", "type": ACCESS_POLICY_TYPE}, "upToDate": False}
            ],
        }

    def handler(self, request):  # noqa: PLR0911, PLR0912, PLR0915 -- explicit provider evidence matrix
        path = request.url.path
        if path.endswith("/v1/token"):
            return httpx.Response(200, json={"tenantUid": "tenant"})
        if "generatetoken" in path:
            return httpx.Response(204, headers={"X-auth-access-token": "test"})
        if path.endswith("/inventory/devices"):
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "uid": "scc-device",
                            "uidOnFmc": "device",
                            "deviceType": "CDFMC_MANAGED_FTD",
                        }
                    ],
                    "count": 1,
                },
            )
        if request.method == "POST":
            self.posts.append(json.loads(request.content))
            if self.scenario == "external_edit":
                self.external_edit = True
            if self.scenario == "ambiguous":
                raise httpx.ReadTimeout("response lost", request=request)
            return httpx.Response(202, json={"metadata": {"task": {"id": "job"}}})
        if path.endswith("/pendingchanges"):
            assert request.url.params["expanded"] == "true"
            if self.scenario == "unavailable":
                return httpx.Response(503)
            if self.scenario == "malformed":
                return httpx.Response(200, json={"items": None})
            if self.scenario == "incomplete":
                return httpx.Response(200, json={"items": [], "paging": {"count": 2}})
            changes = []
            if self.scenario in {"expected", "resource_changed", "revision_changed"}:
                changes = [
                    {
                        "entityUUID": "object",
                        "action": "ADD",
                        "valueAdded": [{"fieldName": "value", "newValue": "10.1.0.0/16"}],
                    }
                ]
            if self.scenario in {"unrelated", "unknown", "writer_only"}:
                changes = [
                    {
                        "entityUUID": "someone-elses-object",
                        "action": "ADD",
                        "lastUpdatedByUsers": ["FPM"],
                    }
                ]
            return httpx.Response(200, json={"items": changes, "paging": {"count": len(changes)}})
        if path.endswith("/deployabledevices"):
            self.reads += 1
            device = deepcopy(self.device)
            if self.scenario == "case_variant":
                device["id"] = "DEVICE"
                device["device"]["id"] = "DEVICE"
                device["deviceMembers"][0]["id"] = "DEVICE"
                device["policyStatusList"][0]["policy"]["id"] = "POLICY"
            if self.scenario == "version_changed" and self.reads > 1:
                device["version"] = "123457"
            if self.scenario == "policy_type":
                device["policyStatusList"][0]["policy"]["type"] = "NATPolicy"
            if self.scenario == "wrong_policy":
                device["policyStatusList"][0]["policy"]["id"] = "unrelated-policy"
            if self.scenario == "unrelated_policy_warning":
                device["policyStatusList"].append(
                    {
                        "policy": {"id": "other-policy", "type": "NATPolicy"},
                        "upToDate": False,
                    }
                )
            if self.scenario == "dependency":
                device["policyStatusList"][0]["referredPolicyList"] = [{"upToDate": False}]
            if self.scenario == "mandatory":
                device["groupDependencyDetails"]["mandatoryDeployablePolicies"] = [
                    "PlatformSettings"
                ]
            if self.scenario == "additional_member":
                device["deviceMembers"].append({"id": "unauthorized-member"})
            if self.scenario == "group_dependency":
                device["groupDependencyDetails"]["dependentPolicyList"] = [
                    {"dependentTypeList": [ACCESS_POLICY_TYPE, "SSLPolicy"]}
                ]
            if self.scenario == "dependency_unknown":
                device.pop("groupDependencyDetails")
            if self.scenario == "dependency_optional_fields_omitted":
                device["groupDependencyDetails"].pop("mandatoryDeployablePolicies")
                device["groupDependencyDetails"].pop("dependentPolicyList")
            if self.scenario == "selective_none":
                device["groupDependencyDetails"]["mandatoryDeployablePolicies"] = [
                    ACCESS_POLICY_TYPE
                ]
                device["groupDependencyDetails"]["selectivelyDeployablePolicies"] = None
            extra = {**deepcopy(device), "id": "extra", "device": {"id": "extra"}}
            return httpx.Response(200, json={"items": [device, extra], "paging": {"count": 2}})
        if path.endswith("/object/networks/object"):
            resource = dict(self.resource)
            if self.scenario == "resource_changed" or self.external_edit:
                resource["value"] = "10.99.0.0/16"
            if self.scenario == "revision_changed":
                resource["version"] = "3"
            return httpx.Response(200, json=resource)
        if path.endswith("/job/taskstatuses/job"):
            return httpx.Response(200, json={"status": "SUCCEEDED"})
        raise AssertionError(path)

    def provider(self, kind):
        options = {
            "display_name": "Controlled",
            "writable": True,
            "capabilities": {"pending_change_inspection": CapabilityStatus.SUPPORTED},
            "transport": httpx.MockTransport(self.handler),
            "validate_network_target": False,
        }
        if kind == "fmc":
            return RealFmcProvider(
                endpoint="https://fmc.example.test",
                username="test",
                password="test",  # noqa: S106 -- synthetic credential
                **options,
            )
        return RealSccProvider(region="eu", token="test", **options)  # noqa: S106

    def intents(self, provider):
        return [
            {
                "method": "POST",
                "path": provider._config_path("domain", "object/networks"),
                "request": {k: v for k, v in self.resource.items() if k not in {"id", "version"}},
                "response": {"status": 201, "body": self.resource},
            }
        ]


def test_pending_provider_envelopes_and_external_changes_are_evidence_only():
    warnings = check_changes(
        [
            {"entityUUID": "policy", "entityType": "AccessPolicy", "action": "UPDATE"},
            {"entityUUID": "object-container", "entityType": "Object", "action": "UPDATE"},
            {
                "entityUUID": "rule",
                "entityType": "AccessRule",
                "action": "ADD",
                "valueAdded": [
                    {"fieldName": "Action", "newValue": "Allow"},
                    {"fieldName": "Rule Index", "newValue": "3"},
                ],
                "referencesAdded": [{"fieldName": "Destination Networks"}],
            },
        ],
        {
            "rule": {
                "method": "POST",
                "request": {
                    "name": "INFOTECH__test",
                    "action": "ALLOW",
                    "enabled": True,
                    "destinationNetworks": {"objects": [{"id": "network"}]},
                },
            }
        },
    )
    assert [item["entityUUID"] for item in warnings] == ["policy", "object-container"]


def test_expected_resources_uses_successful_auth_retry_evidence():
    intents = [
        {
            "method": "PUT",
            "path": "/domain/rules/rule-1",
            "context": {"operation_id": "operation-1"},
            "response": {"status": 401, "body": {"error": "expired token"}},
        },
        {
            "method": "PUT",
            "path": "/domain/rules/rule-1",
            "context": {"operation_id": "operation-1"},
            "response": {
                "status": 200,
                "body": {"id": "rule-1", "type": "AccessRule", "version": "2"},
            },
        },
    ]

    resources = expected_resources(intents, "/domain")

    assert list(resources) == ["rule-1"]


@pytest.mark.parametrize(
    "intent",
    [
        {
            "method": "POST",
            "path": "/outside/rules",
            "response": {"status": 201, "body": {"id": "rule"}},
        },
        {
            "method": "POST",
            "path": "/domain/rules",
            "response": {"status": 201, "body": {"name": "missing-id"}},
        },
        {
            "method": "PATCH",
            "path": "/domain/rules/rule",
            "response": {"status": 200, "body": {"id": "rule"}},
        },
    ],
)
def test_expected_resources_rejects_missing_mutation_evidence(intent):
    with pytest.raises(ProviderContractError) as error:
        expected_resources([intent], "/domain")
    assert error.value.details["code"] == "DEPLOYMENT_MUTATION_EVIDENCE_MISSING"


@pytest.mark.parametrize("kind", ["fmc", "scc"])
@pytest.mark.parametrize(
    "scenario",
    ["clean", "expected", "external_edit", "selective_none", "case_variant", "version_changed"],
)
async def test_selective_deployment_success_and_external_boundary(kind, scenario):
    transport = CiscoDeploymentTransport(scenario)
    provider = transport.provider(kind)
    target = "device" if kind == "fmc" else "scc-device"
    result = await provider.start_deployment(
        "domain",
        ["policy"],
        [target, target],
        transport.intents(provider) if scenario != "clean" else [],
    )
    assert result["external_operation_id"] == "domain:job"
    assert isinstance(result["preflight"], dict)
    assert result["preflight"]["provider_boundary_limitation"] == "OUT_OF_BAND_EDIT_AFTER_PREFLIGHT"
    expected_device_id = "DEVICE" if scenario == "case_variant" else "device"
    expected_version = "123457" if scenario == "version_changed" else "123456"
    assert transport.posts == [
        {
            "type": "DeploymentRequest",
            "deviceList": [expected_device_id],
            "version": expected_version,
            "forceDeploy": False,
            "ignoreWarning": True,
            "selectedPoliciesforDevices": [
                {
                    "deviceUUID": expected_device_id,
                    "selectedPolicies": []
                    if scenario == "selective_none"
                    else [ACCESS_POLICY_TYPE],
                }
            ],
        }
    ]
    assert (await provider.deployment_status("domain:job"))["state"] == "DEPLOYED"
    if scenario == "external_edit":
        # The provider accepts a concurrent edit after preflight: no CAS is invented.
        assert transport.external_edit
        observed = await provider._get(provider._config_path("domain", "object/networks/object"))
        assert observed["value"] != transport.resource["value"]
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["fmc", "scc"])
async def test_recovered_receipt_without_request_path_is_not_deployment_evidence(kind):
    transport = CiscoDeploymentTransport("clean")
    provider = transport.provider(kind)
    target = "device" if kind == "fmc" else "scc-device"
    result = await provider.start_deployment(
        "domain",
        ["policy"],
        [target],
        [
            {
                "method": "POST",
                "context": {"operation_id": "recovered-create"},
                "response": {"status": 201, "body": {"id": "provider-object"}},
            }
        ],
    )
    assert result["external_operation_id"] == "domain:job"
    assert len(transport.posts) == 1
    await provider.aclose()


@pytest.mark.parametrize("kind", ["fmc", "scc"])
@pytest.mark.parametrize(
    "scenario",
    [
        "malformed",
        "incomplete",
        "unavailable",
        "policy_type",
        "wrong_policy",
        "resource_changed",
        "unauthorized",
        "additional_member",
    ],
)
async def test_preflight_refuses_unexplained_or_unavailable_state(kind, scenario):
    transport = CiscoDeploymentTransport(scenario)
    provider = transport.provider(kind)
    target = "device" if kind == "fmc" else "scc-device"
    if scenario == "unauthorized":
        target = "not-authorized"
    with pytest.raises(ProviderError):
        await provider.start_deployment("domain", ["policy"], [target], transport.intents(provider))
    assert transport.posts == []
    await provider.aclose()


@pytest.mark.parametrize("kind", ["fmc", "scc"])
@pytest.mark.parametrize(
    ("scenario", "expected_code"),
    [
        ("malformed", "DEPLOYMENT_INSPECTION_MALFORMED"),
        ("incomplete", "DEPLOYMENT_INSPECTION_INCOMPLETE"),
        ("policy_type", "DEPLOYMENT_POLICY_SCOPE_UNPROVEN"),
        ("wrong_policy", "DEPLOYMENT_POLICY_SCOPE_UNPROVEN"),
        ("resource_changed", "DEPLOYMENT_RESOURCE_CHANGED"),
        ("additional_member", "DEPLOYMENT_ADDITIONAL_DEVICE_UNAUTHORIZED"),
    ],
)
async def test_preflight_error_code_is_stable(kind, scenario, expected_code):
    transport = CiscoDeploymentTransport(scenario)
    provider = transport.provider(kind)
    target = "device" if kind == "fmc" else "scc-device"
    with pytest.raises(ProviderError) as error:
        await provider.start_deployment("domain", ["policy"], [target], transport.intents(provider))
    assert error.value.details["code"] == expected_code
    assert transport.posts == []
    await provider.aclose()


@pytest.mark.parametrize("kind", ["fmc", "scc"])
@pytest.mark.parametrize(
    "scenario",
    [
        "dependency",
        "mandatory",
        "group_dependency",
        "dependency_unknown",
        "unrelated_policy_warning",
    ],
)
async def test_preflight_ignores_provider_dependency_warnings(kind, scenario):
    transport = CiscoDeploymentTransport(scenario)
    provider = transport.provider(kind)
    target = "device" if kind == "fmc" else "scc-device"

    result = await provider.start_deployment(
        "domain", ["policy"], [target], transport.intents(provider)
    )

    assert result["external_operation_id"] == "domain:job"
    assert len(transport.posts) == 1
    await provider.aclose()


@pytest.mark.parametrize("kind", ["fmc", "scc"])
async def test_preflight_allows_provider_revision_churn_when_configuration_matches(kind):
    transport = CiscoDeploymentTransport("revision_changed")
    provider = transport.provider(kind)
    target = "device" if kind == "fmc" else "scc-device"
    result = await provider.start_deployment(
        "domain", ["policy"], [target], transport.intents(provider)
    )

    assert result["external_operation_id"] == "domain:job"
    assert len(transport.posts) == 1
    await provider.aclose()


@pytest.mark.parametrize("kind", ["fmc", "scc"])
@pytest.mark.parametrize("scenario", ["unrelated", "unknown", "writer_only"])
async def test_preflight_allows_unattributed_pending_changes(kind, scenario):
    transport = CiscoDeploymentTransport(scenario)
    provider = transport.provider(kind)
    target = "device" if kind == "fmc" else "scc-device"
    result = await provider.start_deployment(
        "domain", ["policy"], [target], transport.intents(provider)
    )
    assert result["external_operation_id"] == "domain:job"
    assert result["preflight"]["devices"][0]["unattributed_pending_changes"]
    assert len(transport.posts) == 1
    await provider.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["fmc", "scc"])
async def test_preflight_accepts_omitted_optional_dependency_lists(kind):
    transport = CiscoDeploymentTransport("dependency_optional_fields_omitted")
    provider = transport.provider(kind)
    target = "device" if kind == "fmc" else "scc-device"
    result = await provider.start_deployment("domain", ["policy"], [target])
    assert result["external_operation_id"] == "domain:job"
    assert len(transport.posts) == 1
    await provider.aclose()


@pytest.mark.parametrize("kind", ["fmc", "scc"])
async def test_ambiguous_deployment_has_no_transport_retry(kind):
    transport = CiscoDeploymentTransport("ambiguous")
    provider = transport.provider(kind)
    with pytest.raises(_AmbiguousMutationError) as error:
        await provider.start_deployment(
            "domain", ["policy"], ["device" if kind == "fmc" else "scc-device"]
        )
    assert error.value.__class__.__name__ == "_AmbiguousMutationError"
    assert len(transport.posts) == 1
    await provider.aclose()
