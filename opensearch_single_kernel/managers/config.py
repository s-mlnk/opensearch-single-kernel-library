#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Config manager."""

import logging
from functools import cached_property
from typing import Any

import yaml
from pydantic import ValidationError

from opensearch_single_kernel.common.constants import (
    GENERATED_ROLES,
    CertType,
    Scope,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
)
from opensearch_single_kernel.core.models import App, Node, OpenSearchProfile
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.managers.cluster import ClusterManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.helpers import (
    normalized_tls_subject,
)
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ConfigManager(BaseManager):
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

    @property
    def yaml_setter(self) -> YamlConfigSetter:
        """Get YamlConfigSetter."""
        return YamlConfigSetter(self.workload)

    def update_opensearch_config(
        self,
        roles: list[str] | None = None,
        cm_names: list[str] | None = None,
        cm_ips: list[str] | None = None,
    ) -> bool:
        """Reconcile opensearch config using values from application state.

        Updates opensearch.yml config file and assures
        jvm.options & opensearch-security/config.yml are populated with right static options.

        Args:
            roles: override roles got from nodes_config.
            cm_names: cluster manager nodes for bootstrapping.
            cm_ips: override seed_hosts got from nodes_config.

        Returns:
            whether the opensearch.yml config was changed.
        """
        if roles is None:
            roles = self._opensearch_roles()

        content = yaml.dump(
            self._opensearch_static_config()
            | self._opensearch_general_config(roles)
            | self._opensearch_host_config()
            | self._openseearch_temperature_config()
            | self._opensearch_manager_config(roles=roles, cm_names=cm_names)
            | self._opensearch_admin_tls_config()
            | self._opensearch_tls_config(CertType.UNIT_HTTP)
            | self._opensearch_tls_config(CertType.UNIT_TRANSPORT)
        )

        self._update_static_jvm_options()
        self._update_static_security_options()

        if cm_ips:
            self._update_seed_hosts(cm_ips)
        else:
            self.update_nodes_config()

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
            # This allows the new CMs to be discovered automatically
            # (hot reload of unicast_hosts.txt)
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
            # TODO this may be REQUIRED if we want to ensure certs provided by the client app
            "plugins.security.ssl.http.clientauth_mode": "OPTIONAL",
        }

    def _opensearch_general_config(self, roles: list[str]) -> dict[str, Any]:
        return (
            {
                "cluster.name": deployment_desc.config.cluster_name,
                "node.name": self.state.unit_name,
                "network.host": ["_site_", *sorted(self.state.network_hosts)],
                "http.publish_host": self.workload.get_host_public_ip()
                or self.state.network_ingress_address,
                "node.roles": sorted(roles),
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

    def _opensearch_manager_config(
        self,
        roles: list[str],
        cm_names: list[str] | None = None,
    ) -> dict[str, Any]:
        return (
            {
                "cluster.initial_cluster_manager_nodes": cm_names,
            }
            if "cluster_manager" in roles and self.state.server.is_bootstrap_contributor
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
        if node := self._opensearch_node_config():
            return node.temperature

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

    def _opensearch_nodes_config(self) -> dict[str, Node] | None:
        if not (nodes_config := self.state.application.nodes_config):
            return None

        return {name: Node.from_dict(node) for name, node in nodes_config.items()}

    def _opensearch_node_config(self) -> Node | None:
        return (
            new_node_conf
            if (nodes_config := self._opensearch_nodes_config())
            and (new_node_conf := nodes_config.get(self.state.unit_name))
            else None
        )

    def _opensearch_roles(self) -> list[str]:
        if node := self._opensearch_node_config():
            return node.roles or ["coordinating"]

        if self.state.application.deployment_desc:
            return self.state.computed_roles()

        return ["coordinating"]

    def load_node(self):
        """Load the opensearch.yml config of the node."""
        return self.yaml_setter.load(self.CONFIG_YML)

    def _update_static_jvm_options(self):
        self.yaml_setter.replace(self.JVM_OPTIONS, "=logs/", f"={self.workload.paths.logs}/")
        self.yaml_setter.append(
            self.JVM_OPTIONS,
            "-Djdk.tls.client.protocols=TLSv1.2",
        )

    def _update_static_security_options(self):
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

    def update_nodes_config(self) -> None:
        """Update seed hosts config file with values got from nodes_config."""
        if nodes_config := self._opensearch_nodes_config():
            self._update_seed_hosts(
                [node.ip for node in list(nodes_config.values()) if node.is_cm_eligible()]
            )

    def _update_seed_hosts(self, cm_ips: list[str] | None) -> None:
        """Add CM nodes ips / host names to the seed host list of this unit."""
        # only update the file if there is data to update
        if not cm_ips:
            return
        cm_ips_set = set(cm_ips)
        lines = "\n".join([entry for entry in cm_ips_set if entry.strip()])
        self.workload.write_text(f"{lines}\n", self.workload.paths.seed_hosts)

    def update_profile_configuration(self, profile: OpenSearchProfile) -> bool:
        """Configure the profile and return whether restart is needed or not"""
        current_profile = self.state.server.profile
        logger.debug("current profile: %s, config profile: %s", current_profile, profile)
        if current_profile is None or current_profile != profile:
            self._update_jvm_heap_size(
                profile.get_jvm_heap_size(self.workload.meminfo()["MemTotal"])
            )
            self.state.server.profile = profile
            return True
        return False

    def _update_jvm_heap_size(self, heap_size_in_kb: int):
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
