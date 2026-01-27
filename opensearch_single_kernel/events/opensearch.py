#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for General OpenSearch charm events."""

import logging
import time
from datetime import datetime
from typing import TYPE_CHECKING

from ops import (
    BlockedStatus,
    ConfigChangedEvent,
    InstallEvent,
    LeaderElectedEvent,
    Object,
    SecretChangedEvent,
    StartEvent,
    UpdateStatusEvent,
)

from opensearch_single_kernel.common.constants import (
    COS_USER,
    NODE_LOCK_RELATION,
    OPENSEARCH_SYSTEM_USERS,
    CertType,
    DeploymentType,
    Directive,
    HealthColors,
    StartMode,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
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

        # --- OpenSearch Custom events ---
        self.framework.observe(self.charm._start_opensearch_event, self._on_start_opensearch)
        self.framework.observe(self.charm._restart_opensearch_event, self._on_restart_opensearch)

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
            # TODO: Handle TLS functions
            pass

        if self.charm.unit.is_leader():
            self.charm.cluster_manager.reconcile_cluster_config()
            self.apply_status_from_deployment_desc(self.charm.state.application.deployment_desc)

            # TODO: Handle cluster change to main orchestrator
        if not self.charm.state.application.deployment_desc:
            logger.debug("Deployment description not yet computed, deferring event.")
            event.defer()
            return

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
            self.charm._restart_opensearch_event.emit()

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
                    self.charm._restart_opensearch_event.emit()

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

        self.charm._start_opensearch_event.emit()

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

        self.charm.exclusions_manager.delete_current()

        self.charm.lock_manager.release()

        # Add a timestamp to always trigger relation changed
        self.charm.state.server.update({"started": str(time.time())})

        # TODO: OpenSearch fixes

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

        self.charm.tls_events.configure_tls_after_start()

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
        self.charm._start_opensearch_event.emit(ignore_lock=ignore_lock)

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

        # TODO: Address secrets management in a separate PR

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
