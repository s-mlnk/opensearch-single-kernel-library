#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Config manager."""

import logging
from collections import namedtuple
from functools import cached_property
from typing import Any

from pydantic import ValidationError

from opensearch_single_kernel.common.constants import (
    GENERATED_ROLES,
    CertType,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
)
from opensearch_single_kernel.core.models import App, Node, OpenSearchProfile
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.helpers import normalized_tls_subject
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ConfigManager(BaseManager):
    """OpenSearch Config Manager."""

    CONFIG_YML = "opensearch.yml"
    SECURITY_CONFIG_YML = "opensearch-security/config.yml"
    JVM_OPTIONS = "jvm.options"

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "config_manager"

    @property
    def yaml_setter(self):
        """Return the yaml_setter."""
        return YamlConfigSetter(self.workload)

    def load_node(self):
        """Load the opensearch.yml config of the node."""
        return self.yaml_setter.load(self.CONFIG_YML)

    def set_node(
        self,
        app: App,
        cluster_name: str,
        unit_name: str,
        roles: list[str],
        cm_names: list[str],
        cm_ips: list[str],
        contribute_to_bootstrap: bool,
        node_temperature: str | None = None,
    ) -> None:
        """Set base config for each node in the cluster."""
        self.yaml_setter.put(self.CONFIG_YML, "cluster.name", cluster_name)
        self.yaml_setter.put(self.CONFIG_YML, "node.name", unit_name)
        self.yaml_setter.put(
            self.CONFIG_YML, "network.host", ["_site_"] + self.state.network_hosts
        )
        if self.state.host_ip:
            self.yaml_setter.put(self.CONFIG_YML, "network.publish_host", self.state.host_ip)
        public_address = self.workload.get_host_public_ip() or self.state.network_ingress_address
        self.yaml_setter.put(self.CONFIG_YML, "http.publish_host", public_address)

        self.yaml_setter.put(self.CONFIG_YML, "node.roles", roles, inline_array=len(roles) == 0)
        if node_temperature:
            self.yaml_setter.put(self.CONFIG_YML, "node.attr.temp", node_temperature)
        else:
            self.yaml_setter.delete(self.CONFIG_YML, "node.attr.temp")

        # Set the current app full id
        self.yaml_setter.put(self.CONFIG_YML, "node.attr.app_id", app.id)

        # This allows the new CMs to be discovered automatically (hot reload of unicast_hosts.txt)
        self.yaml_setter.put(self.CONFIG_YML, "discovery.seed_providers", "file")
        self.add_seed_hosts(cm_ips)

        if "cluster_manager" in roles and contribute_to_bootstrap:  # cluster NOT bootstrapped yet
            self.yaml_setter.put(
                self.CONFIG_YML, "cluster.initial_cluster_manager_nodes", cm_names
            )

        self.yaml_setter.put(self.CONFIG_YML, "path.data", str(self.workload.paths.data))
        self.yaml_setter.put(self.CONFIG_YML, "path.logs", str(self.workload.paths.logs))

        self.yaml_setter.replace(self.JVM_OPTIONS, "=logs/", f"={self.workload.paths.logs}/")

        self.yaml_setter.put(self.CONFIG_YML, "plugins.security.disabled", False)
        self.yaml_setter.put(self.CONFIG_YML, "plugins.security.ssl.http.enabled", True)
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.ssl.transport.enforce_hostname_verification",
            True,
        )

        # security plugin rest API access
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.restapi.roles_enabled",
            ["all_access", "security_rest_api_access"],
        )
        # to use the PUT and PATCH methods of the security rest API
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.unsupported.restapi.allow_securityconfig_modification",
            True,
        )

        # enable hot reload of TLS certs (without restarting the node)
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.ssl_cert_reload_enabled",
            True,
        )

    def cleanup_initial_cluster_managers(self):
        """Update the opensearch.yaml by deleting initiali_cluster_manager_nodes."""
        self.yaml_setter.delete(self.CONFIG_YML, "cluster.initial_cluster_manager_nodes")

    def set_client_auth(self):
        """Configure TLS and basic http for clients."""
        # The security plugin will accept TLS client certs if certs but doesn't require them
        # TODO this may be set to REQUIRED if we want to ensure certs provided by the client app
        self.yaml_setter.put(
            self.CONFIG_YML, "plugins.security.ssl.http.clientauth_mode", "OPTIONAL"
        )

        self.yaml_setter.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/basic_internal_auth_domain/http_enabled",
            True,
        )

        self.yaml_setter.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/clientcert_auth_domain/http_enabled",
            True,
        )

        self.yaml_setter.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/clientcert_auth_domain/transport_enabled",
            True,
        )

        self.yaml_setter.append(
            self.JVM_OPTIONS,
            "-Djdk.tls.client.protocols=TLSv1.2",
        )

    def update_host_if_needed(self) -> bool:
        """Update the opensearch config with the current network hosts, after having started.

        Returns: True if host updated, False otherwise.
        """
        NetworkHost = namedtuple("NetworkHost", ["entry", "old", "new"])

        node = self.yaml_setter.load(self.CONFIG_YML)
        result = False
        for host in [
            NetworkHost(
                "network.host",
                set(node.get("network.host", [])),
                set(["_site_"] + self.state.network_hosts),
            ),
            NetworkHost(
                "network.publish_host",
                node.get("network.publish_host"),
                self.state.host_ip,
            ),
            NetworkHost(
                "http.publish_host",
                node.get("http.publish_host"),
                self.workload.get_host_public_ip() or self.state.network_ingress_address,
            ),
        ]:
            if not host.old:
                # Unit not configured yet
                continue

            if host.old != host.new:
                logger.info(f"Updating {host.entry} from: {host.old} - to: {host.new}")
                self.yaml_setter.put(self.CONFIG_YML, host.entry, host.new)
                result = True

        return result

    def reconfigure_unit(self) -> bool:
        """Reconfigure unit based on the nodes_config.

        Returns if opensearch.yml on the unit was reconfigured, in which case a restart will
        be required.
        """
        if not (nodes_config := self.state.application.get_object("nodes_config")):
            return False

        nodes_config = {name: Node.from_dict(node) for name, node in nodes_config.items()}

        # update (append) CM IPs
        self.add_seed_hosts(
            [node.ip for node in list(nodes_config.values()) if node.is_cm_eligible()]
        )

        if not (new_node_conf := nodes_config.get(self.state.unit_name)):
            # the conf could not be computed / broadcast, because this node is
            # "starting" and is not online "yet" - either barely being configured (i.e. TLS)
            # or waiting to start.
            return False

        current_conf = self.yaml_setter.load(self.CONFIG_YML)
        stored_roles = current_conf["node.roles"] or ["coordinating"]
        new_conf_roles = new_node_conf.roles or ["coordinating"]
        if (
            sorted(stored_roles) == sorted(new_conf_roles)
            and current_conf.get("node.attr.temp") == new_node_conf.temperature
        ):
            # no conf change (roles for now)
            return False
        return True

    def add_seed_hosts(self, cm_ips: list[str]):
        """Add CM nodes ips / host names to the seed host list of this unit."""
        cm_ips_set = set(cm_ips)

        # only update the file if there is data to update
        if cm_ips_set:
            lines = "\n".join([entry for entry in cm_ips_set if entry.strip()])
            self.workload.write_text(f"{lines}\n", self.workload.paths.seed_hosts)

    def set_admin_tls_conf(self, secrets: dict[str, Any]):
        """Configures the admin certificate."""
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.authcz.admin_dn/{}",
            normalized_tls_subject(secrets["subject"]),
        )

    def set_node_tls_conf(self, cert_type: CertType, truststore_pwd: str, keystore_pwd: str):
        """Configures TLS for nodes."""
        target_conf_layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"

        for store_type, cert in [("keystore", target_conf_layer), ("truststore", "ca")]:
            self.yaml_setter.put(
                self.CONFIG_YML,
                f"plugins.security.ssl.{target_conf_layer}.{store_type}_type",
                "PKCS12",
            )

            self.yaml_setter.put(
                self.CONFIG_YML,
                f"plugins.security.ssl.{target_conf_layer}.{store_type}_filepath",
                f"{self.workload.paths.certs_relative}/{cert if cert == 'ca' else cert_type.val}.p12",
            )

        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{target_conf_layer}.keystore_alias",
            cert_type.val,
        )
        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{target_conf_layer}.keystore_keypassword",
            keystore_pwd,
        )

        for store_type, pwd in [
            ("keystore", keystore_pwd),
            ("truststore", truststore_pwd),
        ]:
            self.yaml_setter.put(
                self.CONFIG_YML,
                f"plugins.security.ssl.{target_conf_layer}.{store_type}_password",
                pwd,
            )

        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{target_conf_layer}.enabled_protocols",
            "TLSv1.2",
        )

    def set_profile_configuration_if_needed(
        self, current_profile: OpenSearchProfile, config_profile: OpenSearchProfile
    ) -> bool:
        """Configure the profile and return whether restart is needed or not"""
        logger.debug("current profile: %s, config profile: %s", current_profile, config_profile)
        if current_profile is None or current_profile != config_profile:
            self.set_jvm_heap_size(
                config_profile.get_jvm_heap_size(self.workload.meminfo()["MemTotal"])
            )

            # store profile in unit state
            self.state.server.profile = config_profile
            return True
        return False

    def set_jvm_heap_size(self, heap_size_in_kb: int):
        """Apply the performance profile's jvm heap size to the opensearch config."""
        self.yaml_setter.replace(
            self.JVM_OPTIONS,
            "-Xms[0-9]+[kmgKMG]",
            f"-Xms{str(heap_size_in_kb)}k",
            regex=True,
        )

        self.yaml_setter.replace(
            self.JVM_OPTIONS,
            "-Xmx[0-9]+[kmgKMG]",
            f"-Xmx{str(heap_size_in_kb)}k",
            regex=True,
        )

    def add_cm_addresses_to_conf(self):
        """Add the new IP addresses of the current CM units."""
        try:
            # fetch nodes
            nodes = self._nodes(
                use_localhost=self.opensearch_client.is_node_up(), hosts=self.alt_hosts
            )
            # update (append) CM IPs
            self.add_seed_hosts([node.ip for node in nodes if node.is_cm_eligible()])
        except OpenSearchHttpError:
            return

    @cached_property
    def current_node(self) -> Node:  # noqa: C901
        """Return the current node.

        First we try to get it from the OpenSearch API, if not available we build it
        from the opensearch.yml config.
        """
        try:
            node_id = self.opensearch_client.get_node_id(self.state.unit_name)
            unit_id = self.state.server.unit_id
            return self.opensearch_client.get_current_node(node_id, unit_id, self.alt_hosts)

        except OpenSearchHttpError:
            # we try to get the most accurate description of the node from the static config
            conf = self.yaml_setter.load(self.CONFIG_YML)

            # also, if possible we rely on the Deployment Description (databag)
            deployment_desc = self.state.application.deployment_desc

            # Application Priority: Deployment Description
            # Reason: No reason to re-construct the App object
            #  - it's available 99% of scenarios
            #  - it's the same object as a re-constructed one (i.e. no dynamic changes on App)
            if deployment_desc is None:
                try:
                    app = App(id=conf.get("node.attr.app_id"))
                except ValidationError:
                    raise OpenSearchError("Can not determine app details.")
            else:
                app = deployment_desc.app

            # Roles (Temperature) Priority: local config
            # Reason:
            #  - Deployment Description is holding "expected state" (that may not be applied)
            #  - Static config holds the currently applied settings
            try:
                roles = conf["node.roles"]
            except KeyError:
                if deployment_desc:
                    if deployment_desc.start == StartMode.WITH_PROVIDED_ROLES:
                        roles = deployment_desc.config.roles
                    else:
                        roles = GENERATED_ROLES
                else:
                    raise OpenSearchError("Can not determine roles.")

            temperature = None
            try:
                temperature = conf["node.attr.temp"]
            except KeyError:
                if deployment_desc:
                    temperature = deployment_desc.config.data_temperature

            return Node(
                # NOTE: We are NOT using self._charm.unit_name, as it refers to deployment_desc()
                # that is not to be assumed to be always available at this point
                name=self.state.unit_name,
                roles=roles,
                ip=self.state.host_ip,
                app=app,
                unit_number=self.state.server.unit_id,
                temperature=temperature,
            )
