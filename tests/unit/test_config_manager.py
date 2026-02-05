# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit Tests for config Manager functions."""

from typing import Any
from unittest.mock import PropertyMock

from opensearch_single_kernel.common.constants import DeploymentType, StartMode, State
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    PeerClusterConfig,
)
from opensearch_single_kernel.utils.config import YamlConfigSetter
from tests.unit.helpers import (
    config_path,
    opensearch_yml,
    sec_conf_yml,
    seed_unicast_hosts,
)


def test_set_client_auth(harness, mocker):
    """Test setting the client authentication config."""
    yaml_conf_setter = YamlConfigSetter(harness.charm.workload)
    yaml_conf_setter.base_path = config_path / "tmp"

    def authc() -> dict[str, Any]:
        return security_conf["config"]["dynamic"]["authc"]

    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    security_conf = yaml_conf_setter.load(sec_conf_yml)

    # check initial stage
    assert "plugins.security.ssl.http.clientauth_mode" not in opensearch_conf
    assert authc()["basic_internal_auth_domain"]["http_enabled"]
    assert not authc()["clientcert_auth_domain"]["http_enabled"]
    assert not authc()["clientcert_auth_domain"]["transport_enabled"]

    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.seed_hosts",
        return_value=seed_unicast_hosts,
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.yaml_setter",
        return_value=yaml_conf_setter,
        new_callable=PropertyMock,
    )
    # configure host and network hosts
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.network_hosts",
        return_value=["10.10.10.10"],
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.host_ip",
        return_value="20.20.20.20",
        new_callable=PropertyMock,
    )
    # call method
    harness.charm.config_manager.set_client_auth()

    # check the changes
    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    security_conf = yaml_conf_setter.load(sec_conf_yml)

    assert opensearch_conf["plugins.security.ssl.http.clientauth_mode"] == "OPTIONAL"
    assert authc()["basic_internal_auth_domain"]["http_enabled"]
    assert authc()["clientcert_auth_domain"]["http_enabled"]
    assert authc()["clientcert_auth_domain"]["transport_enabled"]


# TODO: Add tests related to configuring tls


def test_set_node_and_cleanup_if_bootstrapped(harness, mocker):
    """Test setting the core config of a node."""
    yaml_conf_setter = YamlConfigSetter(harness.charm.workload)
    yaml_conf_setter.base_path = config_path / "tmp"
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    app = App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name)
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(
            cluster_name="logs",
            init_hold=False,
            roles=["cluster_manager", "data"],
            profile="production",
        ),
        start=StartMode.WITH_PROVIDED_ROLES,
        pending_directives=[],
        app=App(model_uuid="model-uuid", name="opensearch"),
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        state=DeploymentState(value=State.ACTIVE),
    )
    mocker.patch(
        "opensearch_single_kernel.workload.vm.VMWorkload.get_host_public_ip",
        return_value="30.30.30.30",
    )

    mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.yaml_setter",
        return_value=yaml_conf_setter,
        new_callable=PropertyMock,
    )
    # configure host and network hosts
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.network_hosts",
        return_value=["10.10.10.10"],
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.seed_hosts",
        return_value=config_path / "unicast_hosts.txt",
        new_callable=PropertyMock,
    )

    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.host_ip",
        return_value="20.20.20.20",
        new_callable=PropertyMock,
    )
    harness.charm.config_manager.set_node(
        app=app,
        cluster_name="opensearch-dev",
        unit_name=harness.charm.state.unit_name,
        roles=["cluster_manager", "data"],
        cm_names=["cm1"],
        cm_ips=["20.20.20.20"],
        contribute_to_bootstrap=True,
        node_temperature="hot",
    )
    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    assert opensearch_conf["cluster.name"] == "opensearch-dev"
    assert opensearch_conf["node.name"] == harness.charm.state.unit_name
    assert opensearch_conf["node.attr.temp"] == "hot"
    assert opensearch_conf["node.attr.app_id"] == app.id
    assert opensearch_conf["network.host"] == ["_site_", "10.10.10.10"]
    assert opensearch_conf["network.publish_host"] == "20.20.20.20"
    assert opensearch_conf["http.publish_host"] == "30.30.30.30"
    assert opensearch_conf["node.roles"] == ["cluster_manager", "data"]
    assert opensearch_conf["discovery.seed_providers"] == "file"
    assert opensearch_conf["cluster.initial_cluster_manager_nodes"] == ["cm1"]
    assert not opensearch_conf["plugins.security.disabled"]
    assert opensearch_conf["plugins.security.ssl.http.enabled"]
    assert opensearch_conf["plugins.security.ssl.transport.enforce_hostname_verification"]

    # test cleanup_conf_if_bootstrapped
    harness.charm.config_manager.cleanup_initial_cluster_managers()
    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    assert "cluster.initial_cluster_manager_nodes" not in opensearch_conf

    # test unicast_hosts content
    with open(config_path / ("tmp/" + seed_unicast_hosts), "r") as f:
        stored = set([line.strip() for line in f.readlines()])
        expected = {"20.20.20.20"}
        assert stored == expected
