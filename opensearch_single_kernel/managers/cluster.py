#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Cluster manager."""

import logging
import time
from datetime import datetime

from shortuuid import ShortUUID
from tenacity import (
    Retrying,
    stop_after_attempt,
    wait_exponential,
)

from opensearch_single_kernel.common.constants import (
    CLUSTER_MANAGER_ROLE_REMOVAL_FORBIDDEN,
    CLUSTER_MANAGER_VOTING_ROLES_PROVIDED_INVALID,
    GENERATED_ROLES,
    OPENSEARCH_HTTP_PORT,
    PEER_CLUSTER_NO_RELATION,
    PEER_CLUSTER_WRONG_RELATION,
    CertType,
    DeploymentType,
    Directive,
    Scope,
    StartMode,
    State,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchNotFullyReadyError,
    OpenSearchProvidedRolesException,
    OpenSearchStartTimeoutError,
)
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    Node,
    PeerClusterConfig,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.helpers import deployment_type
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ClusterManager(BaseManager):
    """OpenSearch Cluster Manager.

    This manager is responsible for the different operations regarding configuring and
    managing opensearch cluster.
    """

    CONFIG_YML = "opensearch.yml"

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "cluster_manager"
        self.yaml_setter = YamlConfigSetter(self.workload)

    def start(self, wait_until_http_200: bool = True):
        """Start the opensearch service."""

        def _is_connected():
            return (
                self.opensearch_client.is_node_up()
                if wait_until_http_200
                else self.is_opensearch_started
            )

        if self.is_opensearch_started:
            return

        # start the opensearch service
        self.workload.start_service()

        start = datetime.now()
        while not (connected := _is_connected()) and (datetime.now() - start).seconds < 180:
            time.sleep(3)
        if not connected:
            logger.debug(f"waited {datetime.now() - start} opensearch did not start")
            raise OpenSearchStartTimeoutError()

    def reconcile_cluster_config(self) -> bool:
        """Init, or updates / recomputes current peer cluster related config if applies.

        Returns whether the deployment description has changed (Not the first time setup).
        """
        logger.debug("Running peer cluster manager reconcile function")
        user_config = self._user_config()
        if not (current_deployment_desc := self.state.application.deployment_desc):
            # new cluster
            deployment_desc = self._new_cluster_setup(user_config)
            logger.debug("New deployment_desc from new cluster setup: %s", deployment_desc)
            self.state.application.put_object("deployment-description", deployment_desc.to_dict())
            return False
        # update cluster deployment desc
        logger.debug("Existing deployment_desc before cluster setup: %s", current_deployment_desc)
        deployment_desc = self._existing_cluster_setup(user_config, current_deployment_desc)
        logger.debug("Existing deployment_desc after cluster setup: %s", deployment_desc)
        if current_deployment_desc == deployment_desc:
            return False

        # TODO: Should we add an entry on DeploymentDesc "errors" to reflect on status?
        self.state.application.put_object("deployment-description", deployment_desc.to_dict())

        # TODO: once peer clusters relation implemented, we should apply all directives
        #  + removing them from queue. We currently only apply the status.
        return True

    def recompute_roles_if_needed(self):
        """Recompute node roles:self-healing that didn't trigger leader related event occurred."""
        try:
            if not (nodes := self.get_nodes(self.opensearch_client.is_node_up())):
                return

            if len(nodes) < self.state.planned_units:
                return

            self.compute_and_broadcast_updated_topology(nodes)
        except OpenSearchHttpError:
            pass

    def _new_cluster_setup(self, config: PeerClusterConfig) -> DeploymentDescription:
        """Build deployment description of a new cluster."""
        logger.debug("New cluster setup")
        directives = []
        deployment_state = DeploymentState(value=State.ACTIVE)
        if config.init_hold:
            # checks if peer cluster relation is set
            if not self.state.peer_cluster_relation:
                deployment_state = DeploymentState(
                    value=State.BLOCKED_WAITING_FOR_RELATION, message=PEER_CLUSTER_NO_RELATION
                )
                directives.append(Directive.SHOW_STATUS)
                directives.append(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)

            directives.append(
                Directive.VALIDATE_CLUSTER_NAME
                if config.cluster_name
                else Directive.INHERIT_CLUSTER_NAME
            )

            start_mode = (
                StartMode.WITH_PROVIDED_ROLES if config.roles else StartMode.WITH_GENERATED_ROLES
            )
            return DeploymentDescription(
                app=App(model_uuid=self.state.model_uuid, name=self.state.application.name),
                config=config,
                start=start_mode,
                pending_directives=directives,
                typ=deployment_type(config, start_mode),
                state=deployment_state,
            )

        cluster_name_autogenerated = False
        if not (cluster_name := config.cluster_name.strip()):
            cluster_name = f"{self.state.application.name}-{ShortUUID().random(length=4)}".lower()
            cluster_name_autogenerated = True

        if not config.roles:
            start_mode = StartMode.WITH_GENERATED_ROLES
        else:
            start_mode = StartMode.WITH_PROVIDED_ROLES
            if "cluster_manager" not in config.roles:
                deployment_state = DeploymentState(
                    value=State.BLOCKED_CANNOT_START_WITH_ROLES,
                    message=PEER_CLUSTER_WRONG_RELATION,
                )
                directives.append(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)
                directives.append(Directive.SHOW_STATUS)

        return DeploymentDescription(
            app=App(model_uuid=self.state.model_uuid, name=self.state.application.name),
            config=PeerClusterConfig(
                cluster_name=cluster_name,
                init_hold=config.init_hold,
                roles=config.roles,
                data_temperature=config.data_temperature,
            ),
            start=start_mode,
            pending_directives=directives,
            typ=deployment_type(config, start_mode),
            state=deployment_state,
            cluster_name_autogenerated=cluster_name_autogenerated,
        )

    def _existing_cluster_setup(
        self, config: PeerClusterConfig, prev_deployment: DeploymentDescription
    ) -> DeploymentDescription:
        """Build deployment description of an existing (started or not) cluster."""
        logger.debug(
            "Found deployment description using existing cluster setup. deployment desc: %s",
            prev_deployment,
        )
        directives = prev_deployment.pending_directives
        deployment_state = prev_deployment.state
        try:
            self._pre_validate_roles_change(
                new_roles=config.roles, prev_roles=prev_deployment.config.roles
            )
            if prev_deployment.state.value == State.BLOCKED_CANNOT_APPLY_NEW_ROLES:
                deployment_state = DeploymentState(value=State.ACTIVE, message="")
                directives.append(Directive.SHOW_STATUS)
            # todo: should we further handle states here?
        except OpenSearchProvidedRolesException as e:
            logger.error(e)
            directives.append(Directive.SHOW_STATUS)
            deployment_state = DeploymentState(
                value=State.BLOCKED_CANNOT_APPLY_NEW_ROLES, message=str(e)
            )

        start_mode = (
            StartMode.WITH_PROVIDED_ROLES if config.roles else StartMode.WITH_GENERATED_ROLES
        )
        if (
            not config.init_hold
            and prev_deployment.state.value == State.BLOCKED_CANNOT_START_WITH_ROLES
            and (start_mode == StartMode.WITH_GENERATED_ROLES or "cluster_manager" in config.roles)
        ):
            deployment_state = DeploymentState(value=State.ACTIVE, message="")
            directives.append(Directive.SHOW_STATUS)
            directives.remove(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)

        dep_type = deployment_type(config, start_mode, prev_deployment.typ)
        return DeploymentDescription(
            app=prev_deployment.app,
            config=PeerClusterConfig(
                cluster_name=prev_deployment.config.cluster_name,
                init_hold=prev_deployment.config.init_hold,
                roles=config.roles,
                data_temperature=config.data_temperature,
            ),
            start=start_mode,
            state=deployment_state,
            typ=dep_type,
            pending_directives=list(set(directives)),
            cluster_name_autogenerated=prev_deployment.cluster_name_autogenerated,
            promotion_time=(
                prev_deployment.promotion_time
                if dep_type == DeploymentType.MAIN_ORCHESTRATOR
                else None
            ),
        )

    def _pre_validate_roles_change(self, new_roles: list[str], prev_roles: list[str]):
        """Validate that the config changes of roles are allowed to happen."""
        if sorted(prev_roles) == sorted(new_roles):
            # nothing changed, leave
            return

        if not new_roles:
            # user requests the auto-generation logic of roles, this will have the
            # cluster_manager role generated, so nothing to validate
            return

        # if prev_roles None, means auto-generated roles, and will therefore include the cm role
        # for all the units up to the latest if even number of units, which will be voting_only
        prev_roles = set(prev_roles or GENERATED_ROLES)
        new_roles = set(new_roles)

        if "cluster_manager" in new_roles and "voting_only" in new_roles:
            # Invalid combination of roles - we cannot have both roles set to a node
            raise OpenSearchProvidedRolesException(CLUSTER_MANAGER_VOTING_ROLES_PROVIDED_INVALID)

        if "cluster_manager" in prev_roles and "cluster_manager" not in new_roles:
            # user requests a forbidden removal of "cluster_manager" role from node
            raise OpenSearchProvidedRolesException(CLUSTER_MANAGER_ROLE_REMOVAL_FORBIDDEN)

        # TODO: enable this check once we have peer cluster relation implemented

        # if "data" in prev_roles and "data" not in new_roles:
        # this is dangerous as this might induce downtime + error on start when data on disk
        # we need to check if there are other sub-clusters with the data roles
        # if not self.is_consumer():
        # raise OpenSearchProvidedRolesException(DataRoleRemovalForbidden)

        # todo guarantee unicity of unit names on peer_relation_joined
        # current_cluster_units = [
        # format_unit_name(unit, app=self.deployment_desc().app)
        # for unit in all_units(self._charm)
        # ]
        # all_nodes = ClusterTopology.nodes(
        #    self._charm.opensearch, self._opensearch.is_node_up(), self._charm.alt_hosts
        # )
        # other_clusters_data_nodes = [
        # node
        # for node in ClusterTopology.nodes_by_role(all_nodes)["data"]
        # if node.name not in current_cluster_units
        # ]
        # if not other_clusters_data_nodes:
        # raise OpenSearchProvidedRolesException(DataRoleRemovalForbidden)

    def _user_config(self):
        """Build a user provided config object."""
        return PeerClusterConfig(
            cluster_name=self.state.config.get("cluster_name"),
            init_hold=self.state.config.get("init_hold", False),
            roles=[
                option.strip().lower()
                for option in self.state.config.get("roles", "").split(",")
                if option
            ],
        )

    def update_bootstrap_state(self, cleanup_application: bool = False):
        """Clean up bootstrap state and remove initial_cluster_manager_nodes from config"""
        if cleanup_application:
            self.state.application.update({"bootstrapped": "True"})
        self.state.server.update({"bootstrap_contributor": None})

    def should_initialise_security_index(self) -> bool:
        """Returns whether the unit should initialise the security index."""
        return not self.state.application.is_security_index_initialised and (
            "data" in self.state.application.deployment_desc.config.roles
            or self.state.application.deployment_desc.start == StartMode.WITH_GENERATED_ROLES
        )

    def wait_opensearch_part_of_cluster(self):
        """Wait for opensearch to become part of the cluster."""
        # Get online nodes
        try:
            nodes = self.get_nodes(use_localhost=self.opensearch_client.is_node_up())
        except OpenSearchHttpError as e:
            logger.info("Failed to get online nodes")
            raise e

        for node in nodes:
            if node.name == self.state.unit_name:
                break
        else:
            raise OpenSearchNotFullyReadyError("Node online but not in cluster.")

    def initialise_security_index(self):
        """Initialise security Index.

        This function is called after opensearch has started.

        Run the security_admin script, it creates and initializes the opendistro_security index.

        IMPORTANT: must only run once per cluster, otherwise the index gets overrode
        """
        admin_secrets = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        args = [
            f"-cd {self.workload.paths.conf}/opensearch-security/",
            f"-cn {self.state.application.deployment_desc.config.cluster_name}",
            f"-h {self.state.host_ip}",
            f"-ts {self.workload.paths.certs}/ca.p12",
            f"-tspass {admin_secrets['truststore-password']}",
            "-tsalias ca",
            "-tst PKCS12",
            f"-ks {self.workload.paths.certs}/{CertType.APP_ADMIN}.p12",
            f"-kspass {admin_secrets['keystore-password']}",
            f"-ksalias {CertType.APP_ADMIN}",
            "-kst PKCS12",
        ]

        admin_key_pwd = admin_secrets.get("key-password", None)
        if admin_key_pwd is not None:
            args.append(f"-keypass {admin_key_pwd}")

        self.workload.run_script(
            "plugins/opensearch-security/tools/securityadmin.sh", " ".join(args)
        )
        self._put_security_index_initialised()

    def check_if_can_start(self) -> bool:
        """Apply the directives computed by the opensearch peer cluster manager."""
        if not (deployment_desc := self.state.application.deployment_desc):
            # the deployment description hasn't finished being computed by the leader
            return False

        # check possibility to start
        logger.debug("Checking if cluster can start with deploy desc: %s", deployment_desc)
        if self.check_blocking_directives(deployment_desc):
            try:
                self.get_nodes(False)
            except OpenSearchHttpError:
                return False
            return True
        return False

    def _put_security_index_initialised(self):
        """Set the security index initialized flag."""
        # TODO: Add peer cluster updates here we need to update relations
        self.state.application.is_security_index_initialised = True

    def wait_for_opensearch_up(self):
        """Wait for opensearch to be fully ready."""
        # it sometimes takes a few seconds before the node is fully "up" otherwise a 503 error
        # may be thrown when calling a node - we want to ensure this node is perfectly ready
        # before marking it as ready
        for attempt in Retrying(
            stop=stop_after_attempt(5),
            wait=wait_exponential(multiplier=2, min=2, max=10),
            reraise=True,
        ):
            with attempt:
                if not self.opensearch_client.is_node_up():
                    raise OpenSearchNotFullyReadyError("Node started but not fully ready yet.")

    def check_blocking_directives(
        self, deployment_desc: DeploymentDescription | None = None
    ) -> bool:
        """Return If we have any blocking directives."""
        if not (deployment_desc := deployment_desc or self.state.application.deployment_desc):
            return False

        blocking_directives = [
            Directive.WAIT_FOR_PEER_CLUSTER_RELATION,
            Directive.RECONFIGURE,
            Directive.VALIDATE_CLUSTER_NAME,
            Directive.INHERIT_CLUSTER_NAME,
        ]
        logger.debug("Directives: %s", deployment_desc.pending_directives)
        for directive in deployment_desc.pending_directives:
            if directive in blocking_directives:
                logger.debug("blocking directive %s", directive)
                return False

        return True

    def get_nodes(self, use_localhost: bool) -> list[Node]:
        """Fetch the list of nodes of the cluster, depending on the requester."""
        if self.state.planned_units == 0 and not self.state.application.deployment_desc:
            # This app is going away and the -broken event already happened
            return []

        # This means it's the first unit on the cluster.
        if self.state.application.deployment_desc.start == StartMode.WITH_PROVIDED_ROLES:
            computed_roles = self.state.application.deployment_desc.config.roles
        else:
            computed_roles = GENERATED_ROLES

        if (
            self.state.server.is_app_leader
            and "data" in computed_roles
            and not self.state.application.is_security_index_initialised
        ):
            return []
        return self._nodes(use_localhost, self.alt_hosts)

    def clear_directive(self, directive: Directive):
        """Remove directive after having applied it."""
        if not (deployment_desc := self.state.application.deployment_desc):
            return

        if directive not in deployment_desc.pending_directives:
            return

        deployment_desc.pending_directives.remove(directive)
        logger.debug("Clearing directive %s. DeploymentDesc: %s", directive, deployment_desc)
        self.state.application.put_object("deployment-description", deployment_desc.to_dict())

    def compute_and_broadcast_updated_topology(self, current_nodes: list[Node]) -> bool:
        """Compute cluster topology and broadcast node configs (roles for now) to change if any.

        Returns whether a nodes_config object has been updated or not.
        """
        if not current_nodes:
            return False

        current_reported_nodes = {
            name: Node.from_dict(node)
            for name, node in (self.state.application.nodes_config or {}).items()
        }

        if (
            deployment_desc := self.state.application.deployment_desc
        ).start == StartMode.WITH_GENERATED_ROLES:
            updated_nodes = self.recompute_nodes_conf(
                app_id=deployment_desc.app.id, nodes=current_nodes
            )
        else:
            updated_nodes = {}
            for node in current_nodes:
                roles = node.roles
                temperature = node.temperature

                # only change the roles of the nodes of the current cluster
                if node.app.id == deployment_desc.app.id:
                    roles = deployment_desc.config.roles
                    temperature = deployment_desc.config.data_temperature

                updated_nodes[node.name] = Node(
                    name=node.name,
                    roles=roles,
                    ip=node.ip,
                    app=node.app,
                    unit_number=node.unit_number,
                    temperature=temperature,
                )

        if current_reported_nodes == updated_nodes:
            return False

        self.state.application.put_object("nodes_config", updated_nodes)
        return True

    def configure_bootstrap_contributors(
        self,
        computed_roles: list[str],
        cm_names: list[str],
        cm_ips: list[str],
    ) -> bool:
        """Configure application state with bootstrap contributors.

        This function takes the computed rolesn cluster managers names and ips,
        it configure the application state and return whether the current unit contribute
        to bootstrap.
        """
        contribute_to_bootstrap = False
        if "cluster_manager" in computed_roles:
            cm_names.append(self.state.unit_name)
            cm_ips.append(self.state.host_ip)

            if (
                self.state.application.deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
                and not self.state.application.bootstrapped
            ):
                cms_in_bootstrap = self.state.application.bootstrap_contributors_count
                if cms_in_bootstrap < self.state.planned_units:
                    contribute_to_bootstrap = True

                    if self.state.server.is_app_leader:
                        self.state.application.bootstrap_contributors_count = cms_in_bootstrap + 1

                    # indicates that this unit is part of the "initial cm nodes"
                    self.state.server.is_bootstrap_contributor = True
        return contribute_to_bootstrap

    @property
    def is_opensearch_started(self) -> bool:
        """Returns whether OpenSearch has started."""
        reachable = self.workload.is_reachable(self.state.host_ip, OPENSEARCH_HTTP_PORT)
        if not reachable:
            logger.debug("Cannot connect to the OpenSearch server...")

        return reachable

    @property
    def roles(self) -> list[str]:
        """Get the list of the roles assigned to this node."""
        try:
            return self.opensearch_client.get_roles(self.state.unit_name, self.alt_hosts)
        except OpenSearchHttpError:
            return self.yaml_setter.load("opensearch.yml")["node.roles"]

    def recompute_nodes_conf(self, app_id: str, nodes: list[Node]) -> dict[str, Node]:
        """Recompute the configuration of all the nodes (cluster set to auto-generate roles)."""
        if not nodes:
            return {}
        logger.debug(f"Roles before re-balancing {({node.name: node.roles for node in nodes})=}")
        nodes_by_name = {}
        current_cluster_nodes = []
        for node in nodes:
            if node.app.id == app_id:
                current_cluster_nodes.append(node)
            else:
                # Leave node unchanged
                nodes_by_name[node.name] = node
        for node in current_cluster_nodes:
            nodes_by_name[node.name] = Node(
                name=node.name,
                # we do this in order to remove any non-default role / add any missing default role
                roles=GENERATED_ROLES,
                ip=node.ip,
                app=node.app,
                unit_number=node.unit_number,
                temperature=node.temperature,
            )
        logger.debug(
            f"Roles after re-balancing {({name: node.roles for name, node in nodes_by_name.items()})=}"
        )
        return nodes_by_name

    def cleanup_on_last_unit_removal(self):
        """Clean up cluster state on last unit removal."""
        if self.state.peer_relation:
            self.state.application.update({"bootstrap_contributors_count": None})
            self.state.application.update({"nodes_config": None})
            # we delete the security index initialised and bootstrapped flags
            # if there are no data units left in all cluster
            if not self.state.application.is_data_role_in_cluster_fleet_apps:
                self.state.application.update({"is_security_index_initialised": None})
                self.state.application.update({"bootstrapped": None})
        # TODO: Large Deployment
        # if self.opensearch_peer_cm.is_provider():
        #    self.peer_cluster_provider.refresh_relation_data(event, can_defer=False)
        #    logger.debug("demoting main orchestrator")
        #    self.opensearch_peer_cm.demote_deployment_type()
        #    self.peers_data.delete(Scope.APP, "orchestrators")
        #    self.peer_cluster_provider.clean_all_relation_data()
        # elif self.opensearch_peer_cm.is_consumer():
        #    self.peer_cluster_requirer.refresh_requirer_relation_data()

    def flush_translog_to_disk(self) -> None:
        """Flush OpenSearch translog to disk."""
        if self.opensearch_client.is_node_up():
            try:
                self.opensearch_client.request("POST", "/_flush")
            except OpenSearchHttpError:
                # if it's a failed attempt we move on
                pass

    @property
    def needs_start_after_host_reboot(self) -> bool:
        """Start Process Edge Case.

        This handles an edge case where the charm is a cluster manager
        the unit is marked as started but service couldn't start
        """
        return (
            self.state.server.started
            and "cluster_manager" in self.roles
            and not self.workload.is_service_started()
        )

    def can_service_start(self) -> bool:
        """Return if the opensearch service can start."""
        if not (deployment_desc := self.state.application.deployment_desc):
            return False

        if not self.check_blocking_directives(deployment_desc):
            return False

        if not self.state.application.is_admin_user_initialized:
            return False

        return True

    def is_started(self) -> bool:
        """Return whether the opensearch service is started."""
        reachable = self.workload.is_reachable(self.state.host_ip, OPENSEARCH_HTTP_PORT)
        if not reachable:
            logger.debug("Cannot connect to the OpenSearch server...")

        return reachable

    def stop_workload(self) -> None:
        """Stop the opensearch service."""
        self.workload.stop()
        start = datetime.now()
        while self.is_started() and (datetime.now() - start).seconds < 60:
            time.sleep(3)

        self.state.server.update({"started": None})

    def apply_upstream_fixes(self):
        """This changes the replication factor of some core indices."""
        # Bug https://github.com/opensearch-project/OpenSearch/issues/8862
        # Introduced in: 2.9.0
        target_indices = [
            ".plugins-ml-config",
            ".opensearch-sap-log-types-config",
            ".opensearch-sap-pre-packaged-rules-config",
        ]
        for index in target_indices:
            try:
                self.opensearch_client.apply_no_replication_to_index(index)
            except OpenSearchHttpError as e:
                if e.response_code != 404:
                    continue
