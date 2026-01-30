#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Config manager."""

import logging
from typing import Any

import yaml

from opensearch_single_kernel.common.constants import CertType, Scope
from opensearch_single_kernel.core.models import Node, OpenSearchProfile
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.cluster import ClusterManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.helpers import (
    deployment_type,
    normalized_tls_subject,
)
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ConfigManager:
    """OpenSearch Config Manager."""

    CONFIG_YML = "opensearch.yml"
    SECURITY_CONFIG_YML = "opensearch-security/config.yml"
    JVM_OPTIONS = "jvm.options"

    def __init__(
        self,
        state: ClusterState,
        workload: BaseWorkload,
        cluster_manager: ClusterManager,
    ):
        self.state = state
        self.workload = workload
        self.cluster_manager = cluster_manager

    def render_opensearch_config(self) -> bool:
        content = yaml.dump(
            self._opensearch_static_config()
            | self._opensearch_general_config()
            | self._opensearch_host_config()
            | self._openseearch_temperature_config()
            | self._opensearch_manager_config()
            | self._opensearch_admin_tls_config()
            | self._opensearch_tls_config(CertType.UNIT_HTTP)
            | self._opensearch_tls_config(CertType.UNIT_TRANSPORT)
        )

        if (
            self.workload.paths.opensearch_config.exists()
            and self.workload.paths.opensearch_config.read_text() == content
        ):
            return False

        self.workload.paths.opensearch_config.write_text(content)
        return True

    @staticmethod
    def _opensearch_static_config() -> dict[str, Any]:
        return {
            # This allows the new CMs to be discovered automatically (hot reload of unicast_hosts.txt)
            "discovery.seed_providers": "file",
            "plugins.security.disabled": False,
            "plugins.security.ssl.http.enabled": True,
            "plugins.security.ssl.transport.enforce_hostname_verification": True,
            # enable hot reload of TLS certs (without restarting the node)
            "plugins.security.ssl_cert_reload_enabled": True,
            # to use the PUT and PATCH methods of the security rest API
            "plugins.security.unsupported.restapi.allow_securityconfig_modification": True,
            # security plugin rest API access
            "plugins.security.restapi.roles_enabled": [
                "all_access",
                "security_rest_api_access",
            ],
            # The security plugin will accept TLS client certs if certs but doesn't require them
            # TODO this may be set to REQUIRED if we want to ensure certs provided by the client app
            "plugins.security.ssl.http.clientauth_mode": "OPTIONAL",
        }

    def _opensearch_general_config(self) -> dict[str, Any]:
        return (
            {
                "cluster.name": deployment_desc.config.cluster_name,
                "node.name": self.state.unit_name,
                "network.host": sorted(["_site_", *self.state.network_hosts]),
                "http.publish_host": self.workload.get_host_public_ip()
                or self.state.network_ingress_address,
                "node.roles": sorted(self.state.computed_roles()),
                "node.attr.app_id": deployment_desc.app.id,  # Set the current app full id
                "path.data": self.workload.paths.data.as_posix(),
                "path.logs": self.workload.paths.logs.as_posix(),
                "path.home": self.workload.paths.home.as_posix(),
            }
            if (deployment_desc := self.state.application.deployment_desc)
            else {}
        )

    def _opensearch_host_config(self) -> dict[str, Any]:
        return {"network.publish_host": self.state.host_ip} if self.state.host_ip else {}

    def _openseearch_temperature_config(self) -> dict[str, Any]:
        return (
            {"node.attr.temp": self._opensearch_data_temperature}
            if self._opensearch_data_temperature
            else {}
        )

    def _opensearch_manager_config(self) -> dict[str, Any]:
        if not self.state.application.deployment_desc:
            return {}

        nodes = self.cluster_manager.get_nodes(False)
        computed_roles = self.state.computed_roles()
        cm_names = self.cluster_manager.get_cluster_managers_names(nodes)
        cm_ips = self.cluster_manager.get_cluster_managers_ips(nodes)

        self.cluster_manager.configure_bootstrap_contributors(computed_roles, cm_names, cm_ips)

        self.set_node(
            cm_ips=list(set(cm_ips)),
        )

        return (
            {
                "cluster.initial_cluster_manager_nodes": cm_names,
            }
            if "cluster_manager" in computed_roles and self.state.server.is_bootstrap_contributor
            else {}
        )

    def _opensearch_admin_tls_config(self) -> dict[str, Any]:
        return (
            {"plugins.security.authcz.admin_dn": [self._opensearch_tls_subject]}
            if self._opensearch_tls_subject
            else {}
        )

    def _opensearch_tls_config(self, cert_type: CertType) -> dict[str, Any]:
        layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"

        return (
            {
                f"plugins.security.ssl.{layer}.keystore_type": "PKCS12",
                f"plugins.security.ssl.{layer}.keystore_filepath": f"{self.workload.paths.certs_relative}/{cert_type}.p12",
                f"plugins.security.ssl.{layer}.truststore_type": "PKCS12",
                f"plugins.security.ssl.{layer}.truststore_filepath": f"{self.workload.paths.certs_relative}/ca.p12",
                f"plugins.security.ssl.{layer}.keystore_alias": cert_type.val,
                f"plugins.security.ssl.{layer}.keystore_keypassword": keystore_pwd,
                f"plugins.security.ssl.{layer}.keystore_password": keystore_pwd,
                f"plugins.security.ssl.{layer}.truststore_password": truststore_pwd,
                f"plugins.security.ssl.{layer}.enabled_protocols": "TLSv1.2",
            }
            if (truststore_pwd := self._opensearch_truststore_pwd())
            and (keystore_pwd := self._opensearch_keystore_pwd(cert_type))
            else {}
        )

    @property
    def _opensearch_data_temperature(self) -> str | None:
        return (
            deployment_desc.config.data_temperature
            if (deployment_desc := self.state.application.deployment_desc)
            else None
        )

    @property
    def _opensearch_tls_subject(self) -> str | None:
        return (
            normalized_tls_subject(admin_secrets["subject"])
            if (
                admin_secrets := self.state.secrets.get_object(
                    Scope.APP, CertType.APP_ADMIN.val, peek=True
                )
            )
            and "subject" in admin_secrets
            else None
        )

    def _opensearch_truststore_pwd(self) -> str | None:
        return (
            truststore_pwd
            if (
                admin_secrets := self.state.secrets.get_object(
                    Scope.APP, CertType.APP_ADMIN.val, peek=True
                )
            )
            and (truststore_pwd := admin_secrets.get("truststore-password"))
            else None
        )

    def _opensearch_keystore_pwd(self, cert_type: CertType) -> str | None:
        return (
            keystore_pwd
            if (cert_secret := self.state.secrets.get_object(Scope.UNIT, cert_type.val, peek=True))
            and (keystore_pwd := cert_secret.get("keystore-password"))
            else None
        )

    @property
    def yaml_setter(self):
        """Return the yaml_setter."""
        return YamlConfigSetter(self.workload.paths.conf)

    def set_node(
        self,
        cm_ips: list[str],
    ) -> None:
        """Set base config for each node in the cluster."""
        self.add_seed_hosts(cm_ips)

        self.yaml_setter.replace(self.JVM_OPTIONS, "=logs/", f"={self.workload.paths.logs}/")

    def set_client_auth(self):
        """Configure TLS and basic http for clients."""

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
            self.workload.paths.seed_hosts.write_text(f"{lines}\n")

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
