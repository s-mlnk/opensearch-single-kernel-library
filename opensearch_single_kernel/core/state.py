#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Object representing the global state of OpenSearch Charm."""

import json
import logging
import socket
from typing import TYPE_CHECKING, Any

from ops import Application, JujuVersion, Object, Relation, Unit

from opensearch_single_kernel.common.constants import (
    GENERATED_ROLES,
    NODE_LOCK_RELATION,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    PEER_RELATION,
    PERFORMANCE_PROFILE,
    TLS_RELATION,
    StartMode,
    Substrates,
)
from opensearch_single_kernel.core.models import (
    DeploymentDescription,
    DeploymentType,
    Model,
    OpenSearchProfile,
    PeerClusterApp,
    PerformanceType,
    ProductionProfile,
    TestingProfile,
)
from opensearch_single_kernel.core.relations import (
    PeerCluster,
    PeerClusterData,
    PeerClusterOrchestratorData,
    RelationDataStore,
    RelationState,
)
from opensearch_single_kernel.core.secrets import OpenSearchSecrets
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    DataPeerData,
    DataPeerUnitData,
)
from opensearch_single_kernel.utils.helpers import format_unit_name

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


logger = logging.getLogger(__name__)


class OpenSearchServer(RelationState):
    """State/Relation data collection for an opensearch unit"""

    def __init__(
        self, relation: Relation | None, data_interface: DataPeerUnitData, component: Unit
    ):
        super().__init__(relation, data_interface, component)
        self.unit = component

    @property
    def unit_id(self) -> int:
        """The id of the unit from the unit name."""
        return int(self.unit.name.split("/")[1])

    @property
    def profile(self) -> OpenSearchProfile | None:
        """Current profile of the unit"""
        if profile_str := self.relation_data.get(PERFORMANCE_PROFILE, None):
            return (
                ProductionProfile()
                if PerformanceType(profile_str) == PerformanceType.PRODUCTION
                else TestingProfile()
            )
        return None

    @profile.setter
    def profile(self, profile_value: OpenSearchProfile):
        """Set current profile of the unit."""
        self.relation_data.update({PERFORMANCE_PROFILE: profile_value.type.value})

    @property
    def is_app_leader(self) -> bool:
        """Check if the current unit is the leader of the application."""
        return self.unit.is_leader()

    @property
    def is_bootstrap_contributor(self) -> bool:
        """Get value of 'bootstrap_contributor'"""
        return self.relation_data.get("bootstrap_contributor", "") == "True"

    @is_bootstrap_contributor.setter
    def is_bootstrap_contributor(self, value: bool):
        """Set the value of 'bootstrap_contributor' in application state."""
        self.update({"bootstrap_contributor": str(value)})

    @property
    def is_cluster_manager_removed(self) -> bool:
        """Get value of 'cluster_manager_removed'"""
        return self.relation_data.get("cluster_manager_removed", "") == "True"

    @is_cluster_manager_removed.setter
    def is_cluster_manager_removed(self, value: bool):
        """Set value of 'cluster_manager_removed'"""
        self.update({"cluster_manager_removed": str(value)})

    @property
    def started(self) -> str:
        """Get the value of 'started' key from unit data bag"""
        return self.relation_data.get("started", "")

    @property
    def tls_ca_renewing(self) -> bool:
        """Return value of 'tls_ca_renewing' from unit state"""
        return self.relation_data.get("tls_ca_renewing", "") == "True"

    @tls_ca_renewing.setter
    def tls_ca_renewing(self, value: bool):
        """Update value of tls_ca_renewing from unit state."""
        self.update({"tls_ca_renewing": str(value)})

    @property
    def tls_ca_renewed(self) -> bool:
        """Get the value of 'tls_ca_renewed' from unit data bag"""
        return self.relation_data.get("tls_ca_renewed", "") == "True"

    @tls_ca_renewed.setter
    def tls_ca_renewed(self, value: bool):
        """Update value of 'tls_ca_renewed'"""
        self.update({"tls_ca_renewed": str(value)})

    @property
    def tls_configured(self) -> bool:
        """Get the value of 'tls_configured' from unit data bag."""
        return self.relation_data.get("tls_configured", "") == "True"

    @tls_configured.setter
    def tls_configured(self, value: bool):
        """Update the value of 'tls_configured'"""
        self.update({"tls_configured": str(value)})

    @property
    def update_ts(self) -> str:
        """Get the value of 'update-ts' from the unit databag."""
        return self.relation_data.get("update-ts", "")

    @update_ts.setter
    def update_ts(self, timestamp: int):
        """Update the value of 'update-ts' in the unit databag."""
        self.update({"update-ts": str(timestamp)})

    @property
    def certs_exp_checked_at(self) -> str:
        """Get the value of 'certs_exp_checked_at' from unit data bag."""
        return self.relation_data.get("certs_exp_checked_at", "1970-01-01 00:00:00")

    @certs_exp_checked_at.setter
    def certs_exp_checked_at(self, value: str):
        """Update the value of 'certs_exp_checked_at'"""
        self.update({"certs_exp_checked_at": value})


class OpenSearchApplication(RelationState):
    """An OpenSearch Application is a charm application with a given role.

    In OpenSearch a cluster can be formed using one or more applications.
    This class defines state/relation data for a single opensearch application.
    """

    def __init__(
        self, relation: Relation | None, data_interface: DataPeerData, component: Application
    ):
        super().__init__(relation, data_interface, component)
        self.app = component

    def get_object(self, key: str) -> dict[str, Any] | None:
        """Get dict / json object from the relation data store."""
        data = self.relation_data.get(key)
        if data is None:
            return None

        return json.loads(data)

    def put_object(self, key: str, value: dict[str, Any], merge: bool = False) -> None:
        """Put dict / json object into relation data store."""
        if merge:
            stored = self.get_object(key)

            if stored is not None:
                stored.update(value)
                value = stored

        sorted_value = Model.sort_payload(value)

        payload_str = None
        if value is not None:
            payload_str = json.dumps(
                sorted_value, default=RelationDataStore._default_encoder, sort_keys=True
            )

        self.update({key: payload_str})

    @property
    def name(self) -> str:
        """Return the name of the Application."""
        return self.app.name

    @property
    def is_admin_user_initialized(self) -> bool:
        """Return the value of 'admin_user_initialized' in application state."""
        return self.relation_data.get("admin_user_initialized", "") == "True"

    @property
    def bootstrap_contributors_count(self) -> int:
        """Get the value of 'bootstrap_contributors_count'"""
        return int(self.relation_data.get("bootstrap_contributors_count", 0))

    @bootstrap_contributors_count.setter
    def bootstrap_contributors_count(self, value: int):
        """Set value of bootstrap contributors count in application state."""
        self.update({"bootstrap_contributors_count": str(value)})

    @is_admin_user_initialized.setter
    def is_admin_user_initialized(self, value: bool):
        """Update the value of 'admin_user_initialized' in application state."""
        self.update({"admin_user_initialized": str(value)})

    @property
    def is_security_index_initialised(self) -> bool:
        """Return the value of 'security_index_initialised' in application state."""
        return self.relation_data.get("security_index_initialised", "") == "True"

    @is_security_index_initialised.setter
    def is_security_index_initialised(self, value: bool):
        """Update the value of 'security_index_initialised' in application state."""
        self.update({"security_index_initialised": str(value)})

    @property
    def nodes_config(self) -> dict:
        """Return the value of 'nodes_config' in application state"""
        nodes_config = self.get_object("nodes_config")
        if not nodes_config:
            return {}
        return nodes_config

    @property
    def bootstrapped(self) -> bool:
        """Return the value of 'bootstrapped' in application state"""
        return self.relation_data.get("bootstrapped", "") == "True"

    @property
    def deployment_desc(self) -> DeploymentDescription | None:
        """Return the deployment description object if any."""
        current_deployment_desc = self.get_object("deployment-description")
        if not current_deployment_desc:
            return None
        return DeploymentDescription.from_dict(current_deployment_desc)

    @property
    def cluster_fleet_apps(self) -> dict[str, PeerClusterApp]:
        """Get the cluster fleet applications."""
        cluster_fleet_apps = json.loads(self.relation_data.get("cluster_fleet_apps", "{}")) or {}
        return {id: PeerClusterApp.from_dict(app) for id, app in cluster_fleet_apps.items()}

    def apps_in_fleet(self) -> list[PeerClusterApp]:
        """Returns list of apps in cluster fleet"""
        cluster_fleet_apps = self.get_object("cluster_fleet_apps")
        if not cluster_fleet_apps:
            cluster_fleet_apps = {}
        elif not json.loads(cluster_fleet_apps):
            cluster_fleet_apps = json.loads(cluster_fleet_apps)
        return [PeerClusterApp.from_dict(app) for app in cluster_fleet_apps.values()]

    @property
    def update_ts(self) -> str:
        """Get the value of 'update-ts' from the application databag."""
        return self.relation_data.get("update-ts", "")

    @update_ts.setter
    def update_ts(self, timestamp: int):
        """Update the value of 'update-ts' in the application databag."""
        self.update({"update-ts": str(timestamp)})

    def is_data_role_in_cluster_fleet_apps(self) -> bool:
        """Look for data-role through all the roles of all the nodes in all applications"""
        data_apps_in_fleet = [app for app in self.apps_in_fleet() if "data" in app.roles]
        return data_apps_in_fleet and any(app.planned_units > 0 for app in data_apps_in_fleet)


class ClusterState(Object):
    """The global OpenSearch Cluster State ."""

    def __init__(self, charm: "OpenSearchBaseCharm", substrate: Substrates):
        super().__init__(charm, "cluster_state")
        self.config = charm.config
        self.substrate = substrate

        # Secrets  FIXME: Handle this separately.
        self.secrets = OpenSearchSecrets(charm, peer_relation=PEER_RELATION)

        # TODO: Add secrets
        self.peer_app_interface = DataPeerData(model=charm.model, relation_name=PEER_RELATION)
        self.peer_unit_interface = DataPeerUnitData(model=charm.model, relation_name=PEER_RELATION)

    # -- Relations

    @property
    def peer_relation(self) -> Relation | None:
        """Get charm peer relation."""
        return self.model.get_relation(PEER_RELATION)

    @property
    def node_lock_relation(self) -> Relation | None:
        """Get Node Lock Peer Relation."""
        return self.model.get_relation(NODE_LOCK_RELATION)

    @property
    def tls_relation(self) -> Relation | None:
        """Get TLS relation."""
        return self.model.get_relation(TLS_RELATION)

    @property
    def peer_cluster_relation(self) -> Relation | None:
        """The 'peer-cluster' relation that the charm is requiring."""
        return self.model.get_relation(PEER_CLUSTER_RELATION)

    @property
    def peer_cluster_orchestrator_relation(self) -> Relation | None:
        """The 'peer-cluster-orchestrator' relation that the charm is requiring."""
        return self.model.get_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION)

    @property
    def peer_cluster_orchestrator(self) -> PeerCluster:
        """The State for the requirer side of the 'peer-cluster-orchestrator' relation.."""
        return PeerCluster(
            relation=self.peer_cluster_relation,
            data_interface=PeerClusterData(self.model, PEER_CLUSTER_RELATION),
            component=self.model.app,
        )

    @property
    def peer_cluster(self) -> PeerCluster:
        """State for the provider side of the 'peer-cluster-orchestrator' relation."""
        return PeerCluster(
            relation=self.peer_cluster_orchestrator_relation,
            data_interface=PeerClusterOrchestratorData(
                self.model, PEER_CLUSTER_ORCHESTRATOR_RELATION
            ),
            component=self.model.app,
        )

    # -- Core Components

    @property
    def server(self) -> OpenSearchServer:
        """Get the opensearch unit state."""
        return OpenSearchServer(
            relation=self.peer_relation,
            data_interface=self.peer_unit_interface,
            component=self.model.unit,
        )

    @property
    def application(self) -> OpenSearchApplication:
        """Get the opensearch application state."""
        return OpenSearchApplication(
            relation=self.peer_relation,
            data_interface=self.peer_app_interface,
            component=self.model.app,
        )

    # -- Cluster State Properties

    @property
    def unit_name(self):
        """Name of the current unit."""
        return format_unit_name(self.model.unit, app=self.application.deployment_desc.app)

    @property
    def planned_units(self) -> int:
        """Return the planned units for the charm."""
        return self.model.app.planned_units()

    @property
    def host_ip(self) -> str:
        """Fetches the IP address of the current unit."""
        address = self.model.get_binding(PEER_RELATION).network.bind_address
        return str(address)

    @property
    def network_hosts(self) -> list[str]:
        """All HTTP/Transport hosts for the current node."""
        return [socket.getfqdn(), self.host_ip]

    @property
    def port(self) -> int:
        """Return Port of OpenSearch unit."""
        return 9200

    def unit_ip(self, unit: Unit) -> str | None:
        """Returns the ip address of a given unit."""
        # check if host is current host
        if unit == self.model.unit:
            return self.host_ip

        if self.peer_relation:
            private_address = self.peer_relation.data[unit].get("private-address")
            if private_address:
                return str(private_address)

    def get_unit(self, name: str):
        """Get unit by name"""
        return self.model.get_unit(name)

    @property
    def is_tls_full_configured_in_cluster(self) -> bool:
        """Check if TLS is configured in all the units of the current cluster."""
        if not self.peer_relation:
            return False
        for unit in self.all_units:
            if (
                self.peer_relation.data[unit].get("tls_configured") != "True"
                or "tls_ca_renewing" in self.peer_relation.data[unit]
                or "tls_ca_renewed" in self.peer_relation.data[unit]
            ):
                return False
        return True

    @property
    def ca_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        rotation_happening = False
        rotation_complete = True

        # check current unit
        logger.debug(
            "current unit tls_ca_renewing:%s | tls_ca_renewed:%s",
            self.server.tls_ca_renewing,
            self.server.tls_ca_renewed,
        )
        if self.server.tls_ca_renewing:
            rotation_happening = True
        if not self.server.tls_ca_renewed:
            logger.debug(
                f"TLS CA rotation ongoing in unit: {self.model.unit.name}, will not update tls certificates."
            )
            rotation_complete = False
        # TODO: Support peer cluster and peer cluster orchestrator
        for relation_type in [
            PEER_RELATION,
            # PeerClusterRelationName,
            # PeerClusterOrchestratorRelationName,
        ]:
            for relation in self.model.relations[relation_type]:
                for unit in relation.units:
                    logger.debug(
                        f"Checking unit {unit} in relation {relation}: \
                            tls_ca_renewing: {relation.data[unit].get('tls_ca_renewing')} \
                            | tls_ca_renewed: {relation.data[unit].get('tls_ca_renewed')}"
                    )
                    if relation.data[unit].get("tls_ca_renewing"):
                        rotation_happening = True

                    if not relation.data[unit].get("tls_ca_renewed"):
                        logger.debug(
                            f"TLS CA rotation ongoing in unit {unit}, will not update tls certificates."
                        )
                        rotation_complete = False
        logger.debug(
            "CA rotation happening in cluster: %s | \
                rotation complete in cluster: %s | return value: %s \
                ",
            rotation_happening,
            rotation_complete,
            not rotation_happening or rotation_complete,
        )
        # if no unit is renewing the CA, or all of them renewed it, the rotation is complete
        return not rotation_happening or rotation_complete

    def ca_and_certs_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        rotation_complete = True

        # the current unit is not in the relation.units list
        # if tls is not configured or in the middle of rotation, return False
        if not self.server.tls_configured or (
            self.server.tls_ca_renewing and not self.server.tls_ca_renewed
        ):
            logger.debug("TLS CA and/or Cert rotation ongoing on this unit.")
            return False

        for relation_type in [
            PEER_RELATION
            # PeerClusterRelationName,
            # PeerClusterOrchestratorRelationName,
        ]:
            for relation in self.model.relations[relation_type]:
                logger.debug(f"Checking relation {relation}: units: {relation.units}")
                for unit in relation.units:

                    if relation.data[unit].get("tls_configured") != "True" or (
                        relation.data[unit].get("tls_ca_renewing", False)
                        and not relation.data[unit].get("tls_ca_renewed", False)
                    ):
                        logger.debug(
                            f"TLS CA and or Cert rotation not complete for unit {unit}: {relation} \
                                | tls_ca_renewing: {relation.data[unit].get('tls_ca_renewing')} \
                                | tls_ca_renewed: {relation.data[unit].get('tls_ca_renewed')} \
                                | tls_configured: {relation.data[unit].get('tls_configured')}"
                        )
                        rotation_complete = False
                        break
        return rotation_complete

    def reset_ca_rotation_state(self) -> None:
        """Handle internal flags during CA rotation routine."""
        if not self.server.tls_ca_renewing:
            # if the CA is not being renewed we don't have to do anything here
            return

        # if this flag is set, the CA rotation routine is complete for this unit
        if self.server.tls_ca_renewed and self.ca_and_certs_rotation_complete_in_cluster():
            # both CA rotation and certs rotation completed in the cluster
            self.server.update({"tls_ca_renewing": None})
            self.server.update({"tls_ca_renewed": None})
            # TODO: Handle large deployment
            # self.update_tls_flag_to_peer_cluster_relation(
            # flag="tls_ca_renewing", operation="remove"
            # )
            # self.update_tls_flag_to_peer_cluster_relation(
            #    flag="tls_ca_renewed", operation="remove"
            # )
            return

        # this means only the CA rotation completed, still need to create certificates
        self.server.tls_ca_renewed = True
        # TODO: Handle large deployment
        # self.update_tls_flag_to_peer_cluster_relation(flag="tls_ca_renewed", operation="add")

    @property
    def network_ingress_address(self) -> str:
        """Get the public ip address of the unit."""
        return str(self.model.get_binding(PEER_RELATION).network.ingress_address)

    @property
    def units_ips(self) -> dict[str, str]:
        """Returns the mapping "unit id / ip address" of all units."""
        unit_ip_map = {}
        if not self.peer_relation:
            return unit_ip_map

        for unit in self.peer_relation.units:
            unit_id = unit.name.split("/")[1]
            unit_ip_map[unit_id] = self.unit_ip(unit)

        # Sometimes the above command doesn't get the current node,
        # so ensure we get this unit's ip.
        unit_ip_map[self.model.unit.name.split("/")[1]] = self.host_ip

        return unit_ip_map

    @property
    def all_units(self) -> list[Unit]:
        """Fetch the list of units for the current app."""
        if not self.peer_relation:
            return []
        return list(self.peer_relation.units.union({self.server.unit}))

    @property
    def implements_secrets(self):
        """Property to cache results from a Juju call."""
        return JujuVersion.from_environ().has_secrets

    @property
    def model_uuid(self):
        """UUID of the Charm Model."""
        return self.model.uuid

    # TODO: Once we handle large deployment we will add a separate
    # state object for peer cluster and peer cluster orchestrator
    @property
    def current_peer_cluster_app(self) -> PeerClusterApp:
        """Return the current peer cluster App."""
        deployment_desc = self.application.deployment_desc
        logger.info(f"Current deployment desc {deployment_desc}")
        return PeerClusterApp(
            app=deployment_desc.app,
            planned_units=self.planned_units,
            units=[format_unit_name(u, app=deployment_desc.app) for u in self.all_units],
            roles=(
                deployment_desc.config.roles
                if deployment_desc.start == StartMode.WITH_PROVIDED_ROLES
                else GENERATED_ROLES
            ),
        )

    def computed_roles(self) -> list[str]:
        """Return computed_roles"""
        if (
            deployment_desc := self.application.deployment_desc
        ).start == StartMode.WITH_PROVIDED_ROLES:
            computed_roles = deployment_desc.config.roles
        else:
            computed_roles = GENERATED_ROLES

        # If the failover orchestrator is the only data node in the cluster, remove the
        # cluster-manager role from it to avoid it bootstrapping the cluster
        # which is the responsibility of the main orchestrator
        # who then broadcasts `security_index_initialized` to the peer clusters.
        if (
            self.model.unit.is_leader()
            and self._is_failover_and_sole_data_app()
            and not self.application.is_security_index_initialised
        ):
            self.server.is_cluster_manager_removed = True
            computed_roles.remove("cluster_manager")

        if computed_roles == ["coordinating"]:
            computed_roles = []  # to mark a node as dedicated coordinating only, we clear the list
        return computed_roles

    def _is_failover_and_sole_data_app(self) -> bool:
        """Check if the current node is a failover and the only data node in the cluster."""
        deployment_desc = self.application.deployment_desc
        cluster_fleet_apps = self.application.cluster_fleet_apps or {}
        return (
            # data node in a failover orchestrator deployment
            deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR
            and (
                "data" in deployment_desc.config.roles
                or deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            )
            # No pure data nodes in the cluster
            and not any(
                self.application.name != cluster_fleet_apps[app].get("app", {}).get("name")
                and "data" in cluster_fleet_apps[app].get("roles", [])
                and "cluster_manager" not in cluster_fleet_apps[app].get("roles", [])
                for app in cluster_fleet_apps
            )
        )
