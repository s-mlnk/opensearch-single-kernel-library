#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for General OpenSearch charm events."""

import logging
import time
from datetime import datetime
from time import time_ns
from typing import TYPE_CHECKING

from ops import (
    BlockedStatus,
    ConfigChangedEvent,
    InstallEvent,
    LeaderElectedEvent,
    Object,
    RelationChangedEvent,
    RelationCreatedEvent,
    RelationDepartedEvent,
    RelationJoinedEvent,
    SecretChangedEvent,
    StartEvent,
    StorageDetachingEvent,
    UpdateStatusEvent,
)

from opensearch_single_kernel.common.constants import (
    COS_USER,
    KIBANA_SERVER_USER,
    NODE_LOCK_RELATION,
    OPENSEARCH_STORAGE_NAME,
    OPENSEARCH_SYSTEM_USERS,
    PEER_RELATION,
    CertType,
    DeploymentType,
    Directive,
    HealthColors,
    Scope,
    StartMode,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchHAError,
    OpenSearchHttpError,
    OpenSearchInstallError,
    OpenSearchMissingError,
    OpenSearchNotFullyReadyError,
    OpenSearchStartError,
    OpenSearchStartTimeoutError,
    OpenSearchStopError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.core.models import DeploymentDescription, Node
from opensearch_single_kernel.events.custom_events import (
    RestartOpenSearch,
    StartOpenSearch,
)
from opensearch_single_kernel.utils.helpers import format_unit_name
from opensearch_single_kernel.utils.status import Status

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class OpenSearchEventsHandler(Object):
    """Class implementing OpenSearch Charm events handling."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, key="opensearch_events")
        self.charm = charm

        # --- OpenSearch charm events ---
        self.framework.observe(self.charm.on.install, self._on_install)
        self.framework.observe(self.charm.on.start, self._on_start)
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)
        self.framework.observe(
            self.charm.on[NODE_LOCK_RELATION].relation_changed, self._on_node_lock_relation_changed
        )
        self.framework.observe(self.charm.on.leader_elected, self._on_leader_elected)
        self.framework.observe(self.charm.on.config_changed, self._on_config_changed)
        self.framework.observe(self.charm.on.update_status, self._on_update_status)
        self.framework.observe(
            self.charm.on[PEER_RELATION].relation_created, self._on_peer_relation_created
        )
        self.framework.observe(
            self.charm.on[PEER_RELATION].relation_joined, self._on_peer_relation_joined
        )
        self.framework.observe(
            self.charm.on[PEER_RELATION].relation_changed, self._on_peer_relation_changed
        )
        self.framework.observe(
            self.charm.on[PEER_RELATION].relation_departed, self._on_peer_relation_departed
        )

        self.framework.observe(
            self.charm.on[OPENSEARCH_STORAGE_NAME].storage_detaching,
            self._on_opensearch_data_storage_detaching,
        )

        # --- OpenSearch Custom events ---
        self.framework.observe(self.charm.start_opensearch_event, self._on_start_opensearch)
        self.framework.observe(self.charm.restart_opensearch_event, self._on_restart_opensearch)

        # Ensure that only one instance of the `_on_peer_relation_changed` handler exists
        # in the deferred event queue
        self._is_peer_rel_changed_deferred = False

    def _on_peer_relation_created(self, event: RelationCreatedEvent):
        """Event received by the new node joining the cluster."""
        # TODO: Handle upgrades
        # if self.upgrade_in_progress:
        # logger.warning(
        #    "Adding units during an upgrade is not supported. The charm may be in a broken,
        #  unrecoverable state"
        # )

    def _on_peer_relation_joined(self, event: RelationJoinedEvent):
        """Event received by all units when a new node joins the cluster."""
        # TODO: Handle upgrades
        # if self.upgrade_in_progress:
        #    logger.warning(
        #        "Adding units during an upgrade is not supported. The charm may be in a broken,
        #  unrecoverable state"
        #    )

    def _on_peer_relation_changed(self, event: RelationChangedEvent):  # noqa C901
        """Handle peer relation changes."""
        if self.charm.cluster_manager.opensearch_client.is_node_up():
            health = self.charm.status.apply_health(app=self.charm.unit.is_leader())
            if self._is_peer_rel_changed_deferred:
                # We already deferred this event during this Juju event. Retry on the next
                # Juju event.
                return

            if health in [HealthColors.UNKNOWN, HealthColors.YELLOW_TEMP]:
                # we defer because we want the temporary status to be updated
                logger.debug("Cluster health temp yellow or unknown. Deferring event.")
                event.defer()
                # If the handler is called again within this Juju hook, we will abandon the event
                self._is_peer_rel_changed_deferred = True

        # we want to have the most up-to-date info broadcasted to related sub-clusters
        # if self.opensearch_peer_cm.is_provider():
        # self.peer_cluster_provider.refresh_relation_data(event, can_defer=False)

        # update any orchestrators about planned units
        # if self.opensearch_peer_cm.is_consumer():
        # self.peer_cluster_requirer.refresh_requirer_relation_data()

        # for relation in self.model.relations.get(ClientRelationName, []):
        # self.opensearch_provider.update_endpoints(relation)

        # register new cm addresses on every node
        self.charm.config_manager.add_cm_addresses_to_conf()

        if self.charm.unit.is_leader():
            # Recompute the node roles in case self-healing didn't trigger leader related event
            self.charm.cluster_manager.recompute_roles_if_needed()
            # TODO: Handle once large deployments are implemented
            # if self.peers_data.get(Scope.APP, "missing_relations"):
            # for failover promotions: this flag indicates that the user needs
            # to relate integrators to this new main orchestrator
            # self.peer_cluster_provider.check_credentials_with_missing_relations()
            # if self.model.relations[PeerClusterRelationName]:
            # self.peer_cluster_requirer.apply_orchestrator_status()
        elif event.relation.data.get(event.app):
            # if app_data + app_data["nodes_config"]: Reconfigure + restart node on the unit
            if self.charm.config_manager.reconfigure_unit():
                self.charm.status.set(CharmStatuses.WAITING_TO_START)
                logger.debug("Restarting opensearch due to reconfiguring node roles")
                self.charm._restart_opensearch_event.emit()

        # check requirements
        if self.charm.state.application.deployment_desc:
            self.check_profile_missing_requirements()

        if not (unit_data := event.relation.data.get(event.unit)):
            return

        if self.charm.state.application.deployment_desc:
            current_node = self.charm.config_manager.current_node
            self.charm.exclusions_manager.cleanup(
                Scope.APP if self.charm.unit.is_leader() else Scope.UNIT,
                current_node,
            )

        if self.charm.unit.is_leader() and unit_data.get("bootstrap_contributor"):
            contributor_count = self.charm.state.application.bootstrap_contributors_count
            self.charm.state.application.bootstrap_contributors_count = contributor_count + 1

    def _on_peer_relation_departed(self, event: RelationDepartedEvent):
        """Relation departed event."""
        # TODO: Handle upgrades
        # if self.upgrade_in_progress:
        #    logger.warning(
        #        "Removing units during an upgrade is not supported. The charm may be in a broken,
        #  unrecoverable state"
        #    )
        if not (self.charm.unit.is_leader() and len(event.relation.units) > 0):
            return

        if not self.charm.cluster_manager.opensearch_client.is_node_up():
            logger.debug("Node is not up. Deferring event.")
            event.defer()
            return

        # Now, we register in the leader application the presence of departing unit's name
        # We need to save them as we have a count limit
        if (
            not (deployment_desc := self.charm.state.application.deployment_desc)
            or not event.departing_unit
        ):
            # No deployment description present
            # that happens in the very last stages of the application removal
            return

        current_app = deployment_desc.app
        remaining_nodes = [
            node
            for node in self.charm.cluster_manager.get_nodes(True)
            if node.name != format_unit_name(event.departing_unit, app=current_app)
        ]

        self.charm.status.apply_health(wait_for_green_first=True, unit=False)

        n_units = sum(1 for node in remaining_nodes if node.app.id == current_app.id)
        if n_units == self.app.planned_units():
            self.charm.cluster_manager.compute_and_broadcast_updated_topology(remaining_nodes)
        else:
            logger.debug(
                f"Waiting for units to leave: expecting {self.app.planned_units()}, currently {n_units}. Deferring event."
            )
            event.defer()
        self.charm.exclusions_manager.add_to_cleanup_list(
            unit_name=format_unit_name(event.departing_unit.name, deployment_desc.app),
            scope=Scope.APP if self.charm.unit.is_leader() else Scope.UNIT,
        )

    def _on_opensearch_data_storage_detaching(self, event: StorageDetachingEvent):  # noqa: C901
        """Triggered when removing unit, Prior to the storage being detached."""
        # TODO: Warning in case of upgrade in progress

        # acquire lock to ensure only 1 unit removed at a time
        # Closes canonical/opensearch-operator#378
        if self.charm.app.planned_units() > 1 and not self.charm.lock_manager.acquired:
            # Raise uncaught exception to prevent Juju from removing unit
            raise Exception("Unable to acquire lock: Another unit is starting or stopping.")

        # if the leader is departing, and this hook fails "leader elected" won"t trigger,
        # so we want to re-balance the node roles from here
        if self.charm.unit.is_leader():
            if self.charm.app.planned_units() <= 1 and (
                self.charm.cluster_manager.opensearch_client.is_node_up()
                or self.charm.cluster_manager.alt_hosts
            ):
                remaining_nodes = [
                    node
                    for node in self.charm.cluster_manager.get_nodes(
                        self.charm.cluster_manager.opensearch_client.is_node_up()
                    )
                    if node.name
                    != format_unit_name(
                        self.charm.unit.name, app=self.charm.state.application.deployment_desc.app
                    )
                ]
                self.charm.cluster_manager.compute_and_broadcast_updated_topology(remaining_nodes)
            elif self.charm.app.planned_units() == 0:
                # This is the last unit being removed
                # We want to clean things up in case of a cold start later
                self.charm.cluster_manager.cleanup_on_last_unit_removal()

            # No cluster managers left in the cluster fleet
            # raise so we do not lose the cluster state
            # TODO:

            # we attempt to flush the translog to disk
            self.charm.cluster_manager.flush_translog_to_disk()

            try:
                self.stop_opensearch()
                if self.charm.cluster_manager.alt_hosts:
                    # There is enough peers available for us to try removing the unit
                    current_node = self.charm.config_manager.current_node
                    scope = Scope.APP if self.charm.unit.is_leader() else Scope.UNIT
                    self.charm.exclusions_manager.delete_current(current_node, scope)
                # safeguards in case planned_units > 0
                if self.charm.app.planned_units() > 0:
                    # check cluster status
                    if self.charm.cluster_manager.alt_hosts:
                        health_color = self.charm.status.apply_health(
                            wait_for_green_first=True, use_localhost=False, unit=False
                        )
                        if health_color == HealthColors.RED:
                            raise OpenSearchHAError(CharmStatuses.CLUSTER_HEALTH_RED.value.message)
                    else:
                        raise OpenSearchHAError(CharmStatuses.CLUSTER_HEALTH_UNKNOWN.value.message)
            finally:
                if self.charm.app.planned_units() > 1 and (
                    self.charm.cluster_manager.opensearch_client.is_node_up()
                    or self.charm.cluster_manager.alt_hosts
                ):
                    # release lock
                    self.charm.lock_manager.release()

    def _on_update_status(self, event: UpdateStatusEvent):  # noqa: C901
        """On update status event.

        We want to periodically check for the following:
        1- The profile requirements are still met
        2- Do we have users that need to be deleted, and if so we need to delete them.
        3- every 6 hours check if certs are expiring soon (in 7 days),
            as a safeguard in case relation broken. As there will be data loss
            without the user noticing in case the cert of the unit transport layer expires.
            So we want to stop opensearch in that case, since it cannot be recovered from.
        """
        if not self.charm.state.application.deployment_desc:
            logger.debug("Deployment description not yet computed")
            return

        if self.check_profile_missing_requirements():
            return

        # if node already shutdown - leave
        if not self.charm.cluster_manager.opensearch_client.is_node_up():
            return

        # review available CMs
        # TODO:
        # self._add_cm_addresses_to_conf()

        # if there are exclusions to be removed
        # each unit should check its own exclusions' list
        # self.opensearch_exclusions.cleanup()
        if (
            health := self.charm.status.apply_health(
                wait_for_green_first=True, app=self.charm.unit.is_leader()
            )
        ) not in [
            HealthColors.GREEN,
            HealthColors.IGNORE,
        ]:
            logger.warning(f"Update status: exclusions updated and cluster health is {health}.")

            if health == HealthColors.UNKNOWN:
                return

        # TODO: Handle client relations updates
        # for relation in self.model.relations.get(ClientRelationName, []):
        # self.opensearch_provider.update_endpoints(relation)

        # deployment_desc = self.charm.state.application.deployment_desc
        # if self.upgrade_in_progress:
        # logger.debug(
        # "Skipping `remove_lingering_users_and_roles()` because upgrade is in-progress"
        # )
        # elif (
        #    self.unit.is_leader()
        #    and deployment_desc
        #    and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
        # ):
        #    self.opensearch_provider.remove_lingering_relation_users_and_roles()

        # If the unit reloads its certs but the other units are not ready yet
        # we need to wait for them all to be ready before deleting the old CA
        if (
            self.charm.tls_manager.read_stored_ca(self.charm.tls_manager.OLD_CA_ALIAS)
            and self.charm.state.ca_and_certs_rotation_complete_in_cluster()
        ):
            logger.debug("update_status: Detected CA rotation complete in cluster")
            self.charm.tls_manager.finalize_ca_certs_rotation()
        # If relation not broken - leave
        if self.charm.state.tls_relation is not None:
            return

        # handle when/if certificates are expired
        certs = self.charm.tls_manager.check_certs_expiration()
        if certs:
            missing = [cert.val for cert in certs.keys()]
            self.charm.status.set(
                CharmStatuses.TLS_CERTS_EXPIRATION_ERROR,
                dynamic_message=f"The certificates: {', '.join(missing)} need to be refreshed.",
            )

            # stop opensearch in case the Node-transport certificate expires.
            if certs.get(CertType.UNIT_TRANSPORT) is not None:
                try:
                    self.stop_opensearch()
                except OpenSearchStopError:
                    event.defer()
                    return
        self.charm.state.server.certs_exp_checked_at = datetime.now().strftime(
            self.charm.tls_manager.CERTS_EXPIRATION_DATE_FORMAT
        )

    def _on_install(self, event: InstallEvent) -> None:
        """Event handler for install event."""
        if self.charm.substrate == Substrates.VM:
            self.charm.status.set(CharmStatuses.INSTALL_IN_PROGRESS)
            try:
                self.charm.workload.install()
                self.charm.status.clear(CharmStatuses.INSTALL_IN_PROGRESS)
            except OpenSearchInstallError:
                self.charm.status.set(CharmStatuses.INSTALL_ERROR)

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """On config changed event. Useful for IP changes or for user provided config changes."""
        if self.charm.config_manager.update_host_if_needed():
            # This happens when the unit IP has changed
            self.charm.tls_events.on_unit_ip_changed(event)

        if self.charm.unit.is_leader():
            if self.charm.cluster_manager.reconcile_cluster_config():
                if (
                    self.charm.state.application.deployment_desc.start
                    == StartMode.WITH_GENERATED_ROLES
                ):
                    # trigger roles change on the leader, other units will have their
                    # peer-rel-changed event triggered
                    self.trigger_peer_rel_changed(on_other_units=False, on_current_unit=True)
                self.apply_status_from_deployment_desc(
                    self.charm.state.application.deployment_desc
                )

            # TODO: Handle cluster change to main orchestrator
            # This case is when the user change roles on runtime of init_hold / roles.
        if not self.charm.state.application.deployment_desc:
            logger.debug("Deployment description not yet computed, deferring event.")
            event.defer()
            return

        # TODO: Handle upgrade in progress

        try:
            config_profile = self.charm.profiles_manager.config_profile
            current_profile = self.charm.state.server.profile
            self.charm.status.clear(CharmStatuses.INVALID_PROFILE_CONFIG_OPTION)
        except ValueError:
            logger.error(
                "Invalid profile configuration. Value: %s", self.charm.state.config.get("profile")
            )
            self.charm.status.set(CharmStatuses.INVALID_PROFILE_CONFIG_OPTION)
            return

        if self.check_profile_missing_requirements():
            event.defer()
            return

        profile_restart_needed = self.charm.config_manager.set_profile_configuration_if_needed(
            current_profile, config_profile
        )
        if self.charm.cluster_manager.workload.is_service_started() and profile_restart_needed:
            logger.debug(
                "Restarting opensearch due to config change: profile_restart_needed=%s",
                profile_restart_needed,
            )
            self.charm.restart_opensearch_event.emit()

    def _on_leader_elected(self, event: LeaderElectedEvent) -> None:  # noqa: C901
        """Handle leader election event."""
        # We check if the current unit is the leader, in case where the leader elected event
        # was deferred, then juju proceeded with a new leader election, and this now deferred-event
        # was emitted in a non-juju leader unit (previous leader)
        if not self.charm.unit.is_leader():
            return

        if not (deployment_desc := self.charm.state.application.deployment_desc):
            event.defer()
            return

        if self.charm.state.application.is_security_index_initialised:
            # Leader election event happening after a previous leader got killed
            if not self.charm.cluster_manager.opensearch_client.is_node_up():
                event.defer()
                return

            if self.charm.status.apply_health(unit=False) in [
                HealthColors.UNKNOWN,
                HealthColors.YELLOW_TEMP,
            ]:
                event.defer()
                return
            nodes = self.charm.cluster_manager.get_nodes(True)
            if self.charm.cluster_manager.compute_and_broadcast_updated_topology(nodes):
                # Nodes Config updated, we would need to reconfigure and restart
                if self.charm.config_manager.reconfigure_unit():
                    # Restart needed
                    self.charm.status.set(CharmStatuses.WAITING_TO_START)
                    logger.debug("Restarting opensearch due to reconfiguring node roles")
                    self.charm.restart_opensearch_event.emit()

            return

        # TODO: check if cluster can start independently

        # User config is currently in a default state, which contains multiple insecure default
        # users. Purge the user list before initialising the users the charm requires.
        self.charm.users_manager.purge_initial_default_users()

        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            return

        if not self.charm.state.application.is_admin_user_initialized:
            self.charm.status.set(CharmStatuses.ADMIN_USER_INIT_IN_PROGRESS)

        # Restore purged system users in local `internal_users.yml`
        # with corresponding credentials
        if self.charm.unit.is_leader():
            for user in OPENSEARCH_SYSTEM_USERS:
                self.charm.users_manager.put_or_update_internal_user_leader(user, update=False)

        self.charm.status.clear(CharmStatuses.ADMIN_USER_INIT_IN_PROGRESS)

    def _on_start(self, event: StartEvent) -> None:  # noqa: C901
        """Event handler for start event."""
        if self.charm.cluster_manager.opensearch_client.is_node_up():
            self.cleanup_start_state()
            return

        if self.charm.cluster_manager.needs_start_after_host_reboot:
            # This logic will only be triggered if the service has started (i.e. "started")
            # if we had a "start" hook (i.e. the actual machine has rebooted)
            # and we are a cluster_manager with the service down
            # After these conditions are met, then we can simply restart the service.
            logger.debug(
                "Start hook: snap already installed and service should be up, but it is not. Restarting it..."
            )

            # We had a reboot in this node.
            # We execute the same logic as above:
            self.cleanup_start_state()

            # Now, reissue a restart: we should not have stopped in the first place
            # as "started" flag is still set to True.
            # We do not wait for the 200 return, as maybe more than one unit is coming back
            try:
                self.charm.workload.start_service_only()
                # We're done here, we can return
                return
            except OpenSearchStartError as e:
                logger.warning(f"Machine restart detected but error at service start with: {e}")
                # Defer and retry later
                event.defer()
                return
            except OpenSearchMissingError:
                # This is unlike to happen, unless the snap has been manually removed
                logger.error("Service previously started but now misses the snap.")
                return
        # apply the directives computed and emitted by the peer cluster manager
        if not self.charm.cluster_manager.check_if_can_start():
            logger.debug("cannot start peer cm had a blocking directive")
            event.defer()
            return

        if self.charm.unit.is_leader():
            self.apply_status_from_deployment_desc(
                self.charm.state.application.deployment_desc, show_status_only_once=False
            )
        if (
            not self.charm.state.application.is_admin_user_initialized
            or not self.charm.tls_manager.is_fully_configured()
        ):
            if not self.charm.state.tls_relation:
                status = CharmStatuses.TLS_RELATION_MISSING
            else:
                if not self.charm.state.application.is_admin_user_initialized:
                    status = CharmStatuses.ADMIN_USER_NOT_CONFIGURED
                else:
                    status = CharmStatuses.TLS_NOT_FULLY_CONFIGURED
            self.charm.status.set(status)
            event.defer()
            return

        self.charm.status.clear(CharmStatuses.ADMIN_USER_NOT_CONFIGURED)
        self.charm.status.clear(CharmStatuses.TLS_NOT_FULLY_CONFIGURED)
        self.charm.status.clear(CharmStatuses.TLS_RELATION_MISSING)

        if self.charm.unit.is_leader():
            self.charm.status.clear(CharmStatuses.PEER_CLUSTER_NO_RELATION, app=True)

        # Configure OpenSearch Users
        if not self.charm.unit.is_leader():
            self.charm.users_manager.purge_initial_default_users()
            for user in OPENSEARCH_SYSTEM_USERS:
                self.charm.users_manager.save_user_locally(user)

        # Configure Client Authentication
        self.charm.config_manager.set_client_auth()

        deployment_desc = self.charm.state.application.deployment_desc
        # only start the main orchestrator if a data node is available
        # this allows for "cluster-manager-only" nodes in large deployments
        # workflow documentation:
        # no "data" role in deployment desc -> start gets deferred
        # when "data" node joins -> start cluster-manager via _on_peer_cluster_relation_changed
        # cluster-manager notifies "data" node via refresh of peer cluster relation data
        # "data" node starts and initializes security index
        if (
            deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
            and not deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            and "data" not in deployment_desc.config.roles
            and not self.charm.state.application.is_security_index_initialised
        ):
            self.charm.status.set(CharmStatuses.PEER_CLUSTER_NO_DATA_NODE)
            event.defer()
            return
        # We are requesting start of openSearch
        self.charm.status.set(CharmStatuses.REQUEST_LOCK_ON_START)

        # In large deployments one data node needs to start to initialize the security index
        # this first node ignores the lock
        # if there are multiple data apps in the cluster
        # we synchronize the start of the first data node through peer cluster relation
        # all leader data units request to start as first data node
        #   ->(app databag key: first_data_node on data app)
        # main orchestrator will choose which node to start first
        #   ->(app databag key: first_data_node on main orchestrator app)

        # TODO: Add checks on whether we should ignore lock. Since we are not
        # adding large deployment yet, we always ignore
        if self.charm.lock_manager.should_ignore_lock(deployment_desc):
            logger.debug(
                f"Requesting start as first data node without lock: {self.charm.state.unit_name}"
            )
            # TODO:
            # self.peer_cluster_requirer.set_first_data_node(self.unit_name)
            event.defer()
            return

        logger.info("Emitting the start opensearch event")

        self.charm.start_opensearch_event.emit()

    def _on_start_opensearch(self, event: StartOpenSearch) -> None:  # noqa: C901
        """Start OpenSearch, with a generated or passed conf, if all resources configured."""
        # TODO: Update Peer Cluster relation data

        if (
            self.charm.cluster_manager.is_opensearch_started
            and not self.charm.workload.is_failed()
        ):
            try:
                self._post_start_init(event)
            except (
                OpenSearchHttpError,
                OpenSearchNotFullyReadyError,
            ):
                # check if cluster should have started but is blocked
                logger.debug("OpenSearch already started, but post-start init failed.")
                if (
                    self.charm.state.application.is_data_role_in_cluster_fleet_apps
                    and self.charm.state.application.bootstrapped
                    # and self.opensearch_peer_cm.is_provider(typ="main")
                ):
                    # In large deployments with cluster-manager-only-nodes,
                    # the startup might fail if the cluster was bootstrapped earlier
                    # and the cluster-manager node lost its data
                    logger.warning(
                        "Node is not ready to start, but data node exists and"
                        " the cluster was previously bootstrapped."
                    )
                    self.charm.status.set(CharmStatuses.SERVICE_START_ERROR)

                event.defer()
            except OpenSearchUserMgmtError as e:
                # Either generic start failure or cluster is not read to create the internal users
                logger.warning(e)
                self.charm.lock_manager.release()
                self.charm.status.set(CharmStatuses.SERVICE_START_ERROR)
                event.defer()
            # finally:
            # if self.opensearch_peer_cm.is_provider(typ="main"):
            # self.peer_cluster_provider.refresh_relation_data(event, can_defer=False)
            return

        if self.charm.state.server.started:
            self.charm.state.server.update({"started": None})

        # Check if we can start. This means we will check
        # - profiles requirements
        # - blocking directives
        # - admin user and security index configured/initialised
        # - cluster health
        if not all(
            [
                not self.check_profile_missing_requirements(),
                self.charm.cluster_manager.can_service_start(),
            ]
        ):
            logger.info("Conditions not met to start opensearch. Will retry next event.")
            event.defer()
            return

        if not self.unit_allowed_to_start(event):
            logger.info("The unit is not allowed to wait, the event need to be retried later.")
            event.defer()
            return

        if event.ignore_lock:
            # Only used for force upgrades and starting 1 data node on a large deployment
            # where the main orchestrator has cluster-manager only nodes
            logger.debug("Starting without lock")
        elif not self.charm.lock_manager.acquired:
            logger.debug("Lock to start opensearch not acquired. Will retry next event")
            event.defer()
            return

        if self.charm.workload.is_failed():
            self.charm.lock_manager.release()
            self.charm.status.set(CharmStatuses.SERVICE_START_ERROR)
            event.defer()
            return
        self.charm.status.set(CharmStatuses.WAITING_TO_START)

        try:
            # Retrieve the nodes of the cluster, needed to configure this node
            nodes = self.charm.cluster_manager.get_nodes(False)

            # Set the configuration of the node
            self._set_node_conf(nodes)
        except OpenSearchHttpError as e:
            logger.debug(f"error getting the nodes: {e}")
            self.charm.lock_manager.release()
            event.defer()
            return

        try:
            self.charm.cluster_manager.start(
                wait_until_http_200=(
                    not self.charm.unit.is_leader()
                    or self.charm.state.application.is_security_index_initialised
                )
            )
            self._post_start_init(event)
        except (
            OpenSearchHttpError,
            OpenSearchStartTimeoutError,
            OpenSearchStartError,
            OpenSearchUserMgmtError,
            OpenSearchCmdError,
        ) as e:
            logger.debug("error of type: %s", type(e).__name__)
            self.charm.lock_manager.release()
            logger.warning(e)
            self.charm.status.set(CharmStatuses.SERVICE_START_ERROR)
            event.defer()
        except OpenSearchNotFullyReadyError as e:
            self.charm.lock_manager.release()
            logger.debug("Node started but not fully ready: %s", e)
            event.defer()
        finally:
            # In large deployments with cluster-manager-only-nodes, the startup might fail
            # for the cluster-manager if a joining data node did not yet initialize the
            # security index. We still want to update and broadcast the latest relation data.
            # TODO:
            # if self.opensearch_peer_cm.is_provider(typ="main"):
            #    self.peer_cluster_provider.refresh_relation_data(event, can_defer=False)
            pass

    def _post_start_init(self, event: StartOpenSearch) -> None:
        """Initialisation post OpenSearch start"""
        # initialize the security index if needed (and certs written on disk etc.)
        # this happens only on the first data node to join the cluster
        if (
            self.charm.unit.is_leader()
            and self.charm.cluster_manager.should_initialise_security_index()
        ):
            self.charm.status.set(CharmStatuses.SECURITY_INDEX_INIT_IN_PROGRESS)
            self.charm.cluster_manager.initialise_security_index()
            self.charm.status.clear(CharmStatuses.SECURITY_INDEX_INIT_IN_PROGRESS)

        # Wait for opensearch to be fully ready or throw error
        self.charm.cluster_manager.wait_for_opensearch_up()

        # Wait for opensearch to be online and part of the cluster
        self.charm.cluster_manager.wait_opensearch_part_of_cluster()

        if self.charm.state.server.is_bootstrap_contributor:
            # If the unit is leader we cleanup the application conf as well
            self.charm.cluster_manager.update_bootstrap_state(
                cleanup_application=self.charm.unit.is_leader()
            )
            self.charm.config_manager.cleanup_initial_cluster_managers()

        current_node = self.charm.config_manager.current_node
        self.charm.exclusions_manager.delete_current(
            node=current_node,
            scope=Scope.APP if self.charm.unit.is_leader() else Scope.UNIT,
        )

        self.charm.lock_manager.release()

        # Add a timestamp to always trigger relation changed
        self.charm.state.server.update({"started": str(time.time())})

        # Apply OpenSearch upstream recommended settings
        self.charm.cluster_manager.apply_upstream_fixes()
        # apply cluster health
        self.charm.status.apply_health(wait_for_green_first=True, app=self.charm.unit.is_leader())

        if (
            self.charm.unit.is_leader()
            and self.charm.state.application.deployment_desc.typ
            == DeploymentType.MAIN_ORCHESTRATOR
        ):
            # Creating the monitoring user
            self.charm.users_manager.put_or_update_internal_user_leader(COS_USER, update=False)

        self.charm.unit.open_port("tcp", 9200)

        # clear waiting to start status
        self.charm.status.clear(CharmStatuses.REQUEST_LOCK_ON_START)
        self.charm.status.clear(CharmStatuses.WAITING_TO_START)
        self.charm.status.clear(CharmStatuses.SERVICE_START_ERROR)
        self.charm.status.clear(CharmStatuses.PEER_CLUSTER_NO_DATA_NODE)

        # TODO: Handle event.after_upgrade
        # TODO: Handle refresh relation data of peer cluster

        self.configure_tls_after_start()

    def _on_restart_opensearch(self, event: RestartOpenSearch) -> None:
        """Event handler for restart opensearch event."""
        if not self.charm.lock_manager.acquired:
            logger.debug("Lock to restart opensearch not acquired. Will retry next event")
            event.defer()
            return

        try:
            self.stop_opensearch(restart=True)
            logger.info("Restarting OpenSearch.")
        except OpenSearchStopError as e:
            logger.info(f"Error while Restarting Opensearch: {e}")
            logger.exception(e)
            self.charm.lock_manager.release()
            event.defer()
            self.charm.status.set(CharmStatuses.SERVICE_IS_STOPPING)
            return

        # Ignore the lock if you are the only data node and restarting
        deployment_desc = self.charm.state.application.deployment_desc
        ignore_lock = (
            self.charm.unit.is_leader()
            and (
                "data" in deployment_desc.config.roles
                or deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            )
            and sum(
                app.planned_units
                for app in self.charm.state.application.cluster_fleet_apps.values()
                if "data" in app.roles
            )
            == 1
        )
        logger.debug("Restarting OpenSearch with ignore_lock=%s", ignore_lock)
        self.charm.start_opensearch_event.emit(ignore_lock=ignore_lock)

    def stop_opensearch(self, *, restart: bool = False) -> None:
        """Stop OpenSearch service."""
        self.charm.status.set(CharmStatuses.SERVICE_IS_STOPPING)
        if self.charm.cluster_manager.opensearch_client.is_node_up():
            try:
                nodes = self.charm.cluster_manager.get_nodes(True)
                # do not add exclusions if it's the last unit to stop
                # otherwise cluster manager election will be blocked when starting up again
                # and reusing storage
                # TODO: Configure exclusions
                if len(nodes) > 1:
                    pass
                # 1. Add current node to the voting + alloc exclusions
                # self.opensearch_exclusions.add_current(voting=True, allocation=not restart)
            except OpenSearchHttpError:
                logger.debug("Failed to get online nodes, voting and alloc exclusions not added")

        # block until all primary shards are moved away from the unit that is stopping
        self.charm.health_manager.wait_for_shards_relocation()
        # Stop the workload
        self.charm.cluster_manager.stop_workload()
        self.charm.status.set(CharmStatuses.SERVICE_STOPPED)

    def _on_node_lock_relation_changed(self, _=None) -> None:
        """Event handler for when the node-lock relation changed"""
        self.charm.lock_manager.refresh_lock()

    def is_cluster_healthy_to_start(self) -> bool:
        """Check the cluster health before being able to start."""
        # When a new unit joins, replica shards are automatically added to it. In order to prevent
        # overloading the cluster, units must be started one at a time. So we defer starting
        # opensearch until all shards in other units are in a "started" or "unassigned" state.
        try:
            if (
                self.charm.status.apply_health(
                    wait_for_green_first=True, use_localhost=False, app=False
                )
                == HealthColors.YELLOW_TEMP
            ):
                return False
        except OpenSearchHttpError:
            # this means that the leader unit is not reachable (not started yet),
            # meaning it's a new cluster, so we can safely start the OpenSearch service
            pass

        return True

    def check_profile_missing_requirements(self) -> list[str]:
        """Check all requirements of profile

        Requirements include:
        - System requirements
        - Memory requirements
        - Cluster topology requirements
        """
        try:
            self.charm.profiles_manager.config_profile
        except ValueError:
            logger.error(
                "Invalid profile configuration. Value: %s", self.charm.state.config.get("profile")
            )
            self.charm.status.set(CharmStatuses.INVALID_PROFILE_CONFIG_OPTION)
            return [CharmStatuses.INVALID_PROFILE_CONFIG_OPTION.value.message]

        missing_requirements = self.charm.profiles_manager.get_missing_requirements()

        self.set_profile_status(missing_requirements)

        return missing_requirements

    def set_profile_status(self, missing_requirements: list[str]):
        """Set the charm status based on the missing requirements"""
        if missing_requirements:
            logger.error("Missing profile requirements: %s", missing_requirements)
            self.charm.status.set(
                CharmStatuses.MISSING_PROFILE_REQUIREMENTS,
                dynamic_message=f"Missing requirements: {' - '.join(missing_requirements)}",
            )
        else:
            self.charm.status.clear(
                CharmStatuses.MISSING_PROFILE_REQUIREMENTS,
                dynamic_message="Missing requirements:",
                pattern=Status.CheckPattern.Start,
            )

    def cleanup_start_state(self) -> None:
        """Clean Up Start statuses and state."""
        if self.charm.state.application.is_security_index_initialised:
            self.charm.status.clear(CharmStatuses.WAITING_TO_START)
            self.charm.status.clear(CharmStatuses.PEER_CLUSTER_NO_DATA_NODE)
        if self.charm.state.server.is_bootstrap_contributor:
            self.charm.cluster_manager.update_bootstrap_state(
                cleanup_application=self.charm.unit.is_leader()
            )

    def apply_status_from_deployment_desc(
        self,
        deployment_desc: DeploymentDescription | None = None,
        show_status_only_once: bool = True,
    ) -> None:
        """Resolve and applies corresponding status from the deployment state."""
        if not (
            deployment_desc := deployment_desc or self.charm.state.application.deployment_desc
        ):
            return

        if Directive.SHOW_STATUS not in deployment_desc.pending_directives:
            return

        # remove show_status directive which is applied below
        if show_status_only_once:
            self.charm.cluster_manager.clear_directive(Directive.SHOW_STATUS)

        blocked_status = [
            CharmStatuses.CM_ROLE_REMOVAL_FORBIDDEN,
            CharmStatuses.CM_VO_PROVIDED_INVALID,
            CharmStatuses.DATA_ROLE_REMOVAL_FORBIDDEN,
            CharmStatuses.PEER_CLUSTER_NO_RELATION,
            CharmStatuses.PEER_CLUSTER_WRONG_RELATION,
            CharmStatuses.PEER_CLUSTER_WRONG_ROLES_PROVIDED,
        ]
        if not list(
            filter(
                lambda status: status.value.message == deployment_desc.state.message,
                blocked_status,
            )
        ):
            for status in blocked_status:
                self.charm.status.clear(status, app=True)
            return

        self.charm.app.status = BlockedStatus(deployment_desc.state.message)

    def _set_node_conf(self, nodes: list[Node]) -> None:
        """Set the configuration of the current node / unit."""
        computed_roles = self.charm.state.computed_roles()

        cm_names = self.charm.cluster_manager.get_cluster_managers_names(nodes)
        cm_ips = self.charm.cluster_manager.get_cluster_managers_ips(nodes)
        contribute_to_bootstrap = self.charm.cluster_manager.configure_bootstrap_contributors(
            computed_roles,
            cm_names,
            cm_ips,
        )

        deployment_desc = self.charm.state.application.deployment_desc
        self.charm.config_manager.set_node(
            app=deployment_desc.app,
            cluster_name=deployment_desc.config.cluster_name,
            unit_name=self.charm.state.unit_name,
            roles=computed_roles,
            cm_names=list(set(cm_names)),
            cm_ips=list(set(cm_ips)),
            contribute_to_bootstrap=contribute_to_bootstrap,
            node_temperature=deployment_desc.config.data_temperature,
        )

    def _on_secret_changed(self, event: SecretChangedEvent) -> None:  # noqa: C901
        """Refresh secret and re-run corresponding actions if needed."""
        secret = event.secret
        secret.get_content(refresh=True)

        if not event.secret.label:
            logger.info("Secret %s has no label, ignoring it.", event.secret.id)
            return

        try:
            label_parts = self.charm.state.secrets.breakdown_label(event.secret.label)
        except ValueError:
            logging.info(f"Label {event.secret.label} was meaningless for us, returning")
            return
        # We need to take action on 5 secret types
        # 1. TLS credentials change
        #     - Action: update credentials files
        # 2. 'kibanaserver' user credentials change
        #     - Action: Dashboard relation (secret) needs to be updated
        # 3. System user hash secret update
        #     - Action: Every unit needs to update local internal_users.yml
        #     - Note: Leader is updated already
        # 4. S3 credentials (secret / access keys) in large relations
        #     - Action: write them into the opensearch.yml by running backup module
        # 5. Azure credentials (storage account / secret key)
        #
        # On a separate note: Handling for JWT-config related secrets (e.g. signing-key) happens
        # in the `JwtHandler` class, as it is a secret that is provided from another application
        system_user_hash_keys = [
            self.charm.state.secrets.hash_key(user) for user in OPENSEARCH_SYSTEM_USERS
        ]
        keys_to_process = system_user_hash_keys + [
            CertType.APP_ADMIN.val,
            self.charm.state.secrets.password_key(KIBANA_SERVER_USER),
        ]
        # Variables for better readability
        label_key = label_parts["key"]
        is_leader = self.charm.unit.is_leader()

        # Matching secrets by label
        if (
            label_parts["application_name"] != self.charm.app.name
            or label_parts["scope"] != Scope.APP
            or label_key not in keys_to_process
        ):
            logger.info("Secret %s was not relevant for us.", event.secret.label)
            return

        logger.debug("Secret change for %s", str(label_key))

        if is_leader and label_key == self.charm.state.secrets.password_key(KIBANA_SERVER_USER):
            pass
            # self.charm.opensearch_provider.update_dashboards_password()

        # Non-leader units need to maintain local users in internal_users.yml
        elif not is_leader and label_key in system_user_hash_keys:
            password = event.secret.get_content()[label_key]
            if sys_user := self.charm.state.secrets._user_from_hash_key(label_key):
                self.charm.users_manager.put_internal_user(sys_user, password)

    def unit_allowed_to_start(self, event: StartOpenSearch) -> bool:
        """Check if the unit is allowed to start.

        Basically, we will check if the unit is the only unit in the cluster
        or if it is the first data node. If the cluster is already initialized
        we check cluster health and start.
        """
        # Case of the first "main" cluster to get started.
        deployment_desc = self.charm.state.application.deployment_desc
        if (
            not self.charm.state.application.is_security_index_initialised
            or not self.charm.cluster_manager.alt_hosts
        ):
            return self.charm.unit.is_leader() and (
                deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
                # first data node in a cluster-manager-only deployment
                or (
                    (
                        deployment_desc.start == StartMode.WITH_GENERATED_ROLES
                        or "data" in deployment_desc.config.roles
                    )
                    and event.is_first_data_node
                )
            )
        else:
            return self.is_cluster_healthy_to_start()

    def trigger_peer_rel_changed(
        self,
        only_by_leader: bool = False,
        on_other_units: bool = True,
        on_current_unit: bool = False,
    ) -> None:
        """Force trigger a peer rel changed event."""
        if only_by_leader and not self.charm.unit.is_leader():
            return

        if on_other_units or not on_current_unit:
            if only_by_leader:
                self.charm.state.application.update_ts = time_ns()
            else:
                self.charm.state.server.update_ts = time_ns()

        if on_current_unit:
            self.charm.on[PEER_RELATION].relation_changed.emit(self.charm.state.peer_relation)

    def configure_tls_after_start(self):
        """Configure TLS state and certificates after OpenSearch is started."""
        # update the peer relation data for TLS CA rotation routine
        self.charm.state.reset_ca_rotation_state()
        if self.charm.state.is_tls_full_configured_in_cluster:
            self.charm.status.clear(CharmStatuses.TLS_CA_ROTATION)
            self.charm.status.clear(CharmStatuses.TLS_NOT_FULLY_CONFIGURED)

        # request new certificates after rotating the CA
        if self.charm.state.server.tls_ca_renewing and self.charm.state.server.tls_ca_renewed:
            self.charm.status.set(CharmStatuses.TLS_NOT_FULLY_CONFIGURED)
            self.request_new_unit_certificates()
            if self.charm.unit.is_leader():
                self.request_new_admin_certificate()
            else:
                self.charm.tls_manager.store_admin_tls_secrets_if_applies()

        # If the reload through API failed, we restart the service
        # We remove the old CA and update the chain to only include the new one
        # if all certs are stored and CA rotation is complete in the cluster
        if (
            self.charm.tls_manager.read_stored_ca(self.charm.tls_manager.OLD_CA_ALIAS)
            and self.charm.state.ca_and_certs_rotation_complete_in_cluster()
        ):
            logger.info("post_start_init: Detected CA rotation complete in cluster")
            self.charm.tls_manager.finalize_ca_certs_rotation()

        # TODO: Handle case of peer cluster manager
        # if self.peers_data.get(Scope.UNIT, "cluster_manager_removed", default=False):
        # restore cluster_manager role and restart the service
        # logger.debug("Restoring cluster_manager role and restarting the service")
        # self.peers_data.delete(Scope.UNIT, "cluster_manager_removed")
        # self._restart_opensearch_event.emit()

    def request_new_unit_certificates(self) -> None:
        """Requests a new certificate with the given scope and type from the tls operator."""
        self.charm.state.server.update({"tls_configured": None})
        # TODO: Update peer cluster relation
        # self.charm.tls.update_tls_flag_to_peer_cluster_relation("tls_configured", "remove")

        for cert_type in [CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT]:
            csr = self.charm.state.secrets.get_object(Scope.UNIT, cert_type.val, peek=True)[
                "csr"
            ].encode("utf-8")
            self.charm.tls_events.certs.request_certificate_revocation(csr)

        # doing this sequentially (revoking -> requesting new ones), to avoid triggering
        # the "certificate available" callback with old certificates
        for cert_type in [CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT]:
            secrets = self.charm.state.secrets.get_object(Scope.UNIT, cert_type.val, peek=True)
            key = secrets["key"].encode("utf-8")
            key_password = secrets.get("key-password", None)
            old_csr = secrets["csr"].encode("utf-8")
            csr = self.charm.tls_manager.create_certificate_signing_request(
                scope=Scope.UNIT,
                cert_type=cert_type,
                key=key,
                password=key_password,
                tls_file=False,
            )

            self.charm.tls_events.certs.request_certificate_renewal(
                old_certificate_signing_request=old_csr,
                new_certificate_signing_request=csr,
            )

    def request_new_admin_certificate(self) -> None:
        """Request the generation of a new admin certificate."""
        if not self.charm.unit.is_leader():
            return
        admin_secrets = (
            self.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )

        key = admin_secrets["key"].encode("utf-8")
        key_password = admin_secrets.get("key-password", None)
        csr = self.charm.tls_manager.create_certificate_signing_request(
            scope=Scope.APP,
            cert_type=CertType.APP_ADMIN,
            key=key,
            password=key_password,
            tls_file=False,
        )

        self.charm.tls_events.certs.request_certificate_creation(certificate_signing_request=csr)
