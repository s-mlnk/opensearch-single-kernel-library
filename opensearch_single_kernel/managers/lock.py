#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Lock manager.

Ensure that only one node (re)starts, joins the cluster, or leaves the cluster at a time.

The workflow logic goes alongside the following:

1. If there are opensearch online nodes:
   a) the node requesting the lock attempts to create a doc with the name of the node
   b) if it succeeds => the unit gets the lock
   c) if it fails => the unit doesn't get the lock as it is held by another unit
   d) when the unit completes with their locked operation => releases the lock => deletes the doc
2. if there are no online nodes:
   a) we make use of a flag in the relation data
   b) we check on the existence of the flag to know if the lock is held or not
   c) if not there => we set the lock (flag in the peer rel data)
   d) we release the lock by removing that flag from the rel data
"""
import json
import logging
import os

import ops

from opensearch_single_kernel.common.constants import DeploymentType, StartMode
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
from opensearch_single_kernel.core.models import DeploymentDescription, PeerClusterApp
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import format_unit_name
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class PeerLockManager(BaseManager):
    """Fallback lock when all units of OpenSearch are offline."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)

    @property
    def acquired(self) -> bool:
        """Attempt to acquire lock.

        Returns:
            Whether lock was acquired
        """
        if not self._relation:
            return False

        self._relation.data[self.state.server.unit]["lock-requested"] = json.dumps(True)

        if self.state.server.is_app_leader:
            logger.debug("[Node lock] Requested peer lock as leader unit")
            # A separate relation-changed event won't get fired
            self.refresh_lock()

        if self._unit_with_lock != self.state.unit_name:
            logger.debug(
                f"[Node lock] Not acquired. Unit with peer databag lock: {self._unit_with_lock}"
            )
            return False

        if (
            self.state.server.is_app_leader
            and self._relation.data[self.state.application.app][
                "leader-acquired-lock-after-juju-event-id"
            ]
            == os.environ["JUJU_CONTEXT_ID"]
        ):
            # `unit-with-lock` was set in this Juju event
            # If the charm code raises an uncaught exception later in the Juju event,
            # `unit-with-lock` will be reverted to its previous value—which could allow another
            # unit to get the lock.
            # Therefore, we cannot use the lock now. We must wait until the next Juju event,
            # when `unit-with-lock` has been committed (i.e. won't be reverted), to use the
            # lock.
            if self.state.planned_units <= 1:
                # No other unit will get peer relation changed
                # Therefore, no other unit will be able to trigger peer relation changed on this
                # unit. We must use the lock now and accept that `unit-with-lock` could be reverted
                # if the charm code raises an uncaught exception later in the Juju event.
                logger.debug(
                    "[Node lock] Single unit deployment. Not waiting until next Juju event to use peer "
                    "databag lock for leader unit"
                )
            else:
                logger.debug(
                    "[Node lock] Not acquired. Waiting until next Juju event to use peer databag lock "
                    "for leader unit"
                )
                return False

        logger.debug("[Node lock] Acquired via peer databag")
        return True

    def release(self):
        """Release lock for this unit."""
        if not self._relation:
            return

        self._relation.data[self.state.server.unit].pop("lock-requested", None)
        if self.state.server.is_app_leader:
            logger.debug("[Node lock] Released peer lock as leader unit")
            # A separate relation-changed event won't get fired
            self.refresh_lock()

    def _unit_requested_lock(self, unit: ops.Unit):
        """Whether unit requested lock."""
        assert self._relation
        if not (value := self._relation.data.get(unit, {}).get("lock-requested")):
            return False

        value = json.loads(value)
        if not isinstance(value, bool):
            raise ValueError

        return value

    @property
    def _unit_with_lock(self) -> str | None:
        """Get the unit that has lock."""
        if self._relation:
            return self._relation.data[self.state.application.app].get("unit-with-lock")

    @_unit_with_lock.setter
    def _unit_with_lock(self, value: str):
        """Set the unit that has lock."""
        assert self._relation
        assert self._unit_with_lock != value

        if value == self.state.unit_name:
            logger.debug("[Node lock] (leader) granted peer lock to own unit")
            # Prevent leader unit from using lock in the same Juju event that it was granted
            # If the charm code raises an uncaught exception later in the Juju event,
            # `unit-with-lock` will be reverted to its previous value—which could allow another
            # unit to get the lock.
            # Therefore, we cannot use the lock in this Juju event. We must wait until the next
            # Juju event, when `unit-with-lock` has been committed (i.e. won't be reverted), to use
            # the lock.
            # `JUJU_CONTEXT_ID` is unique for each Juju event
            # (https://matrix.to/#/!xdClnUGkurzjxqiQcN:ubuntu.com/$yEGjGlDaIPBtCi8uB3fH6ZaXUjN7GF-Y2s9YwvtPM-o?via=ubuntu.com&via=matrix.org&via=cutefunny.art)

            self._relation.data[self.state.application.app][
                "leader-acquired-lock-after-juju-event-id"
            ] = os.environ["JUJU_CONTEXT_ID"]
        self._relation.data[self.state.application.app]["unit-with-lock"] = value

    @_unit_with_lock.deleter
    def _unit_with_lock(self):
        """Remove the lock."""
        assert self._relation
        self._relation.data[self.state.application.app].pop("unit-with-lock", None)
        self._relation.data[self.state.application.app].pop(
            "leader-acquired-lock-after-juju-event-id", None
        )

    @property
    def _relation(self):
        """Get the lock relation"""
        # Use property instead of `self._relation =` in `__init__()` because of ops Harness unit
        # tests
        return self.state.node_lock_relation

    def refresh_lock(self):
        """Grant & release lock."""
        assert self._relation

        if not (deployment_desc := self.state.application.deployment_desc):
            return

        if not self.state.server.is_app_leader:
            if self._relation.data[self.state.application.app].get(
                "leader-acquired-lock-after-juju-event-id"
            ):
                # Trigger peer relation changed event on leader unit
                # Without this, the leader unit might not receive another event (to use the lock it
                # holds) until the next update status event
                # Use `JUJU_CONTEXT_ID` only to ensure that the value changes
                # (Value should never be read)
                # (If we set the same value that is currently in the databag, a peer relation
                # changed event will not be triggered)
                self._relation.data[self.state.server.unit]["-trigger"] = os.environ[
                    "JUJU_CONTEXT_ID"
                ]
            return

        if self._unit_with_lock and self._unit_requested_lock(
            self.state.get_unit(self._default_unit_name(self._unit_with_lock))
        ):
            # Lock still in use, do not release
            logger.debug("[Node lock] (leader) lock still in use")
            return

        # TODO: adjust which unit gets priority on lock after leader?
        # During initial startup, leader unit must start first
        # Give priority to leader unit

        for unit in (self.state.server.unit, *self._relation.units):
            if self._unit_requested_lock(unit):
                self._unit_with_lock = format_unit_name(unit, app=deployment_desc.app)
                logger.debug(f"[Node lock] (leader) granted peer lock to {unit.name=}")
                break
        else:
            logger.debug("[Node lock] (leader) cleared peer lock")
            del self._unit_with_lock

    @staticmethod
    def _default_unit_name(full_unit_id: str) -> str:
        """Build back the juju formatted unit name."""
        # we first take out the app id suffix
        full_unit_id_split = full_unit_id.split(".")[0].rsplit("-")
        return "{}/{}".format("-".join(full_unit_id_split[:-1]), full_unit_id_split[-1])


class LockManager(PeerLockManager):
    """OpenSearch Lock Manager."""

    OPENSEARCH_INDEX = ".charm_node_lock"

    def __init__(self, state, workload):
        self.name = "lock_manager"
        super().__init__(state, workload)

    def should_ignore_lock(self, deployment_desc: DeploymentDescription) -> bool:
        """Check if we should ignore the lock when starting OpenSearch."""
        return (
            self.state.server.is_app_leader
            # data unit
            and (
                "data" in deployment_desc.config.roles
                or deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            )
            and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR
            and (
                not self.state.application.is_security_index_initialised
                or (
                    # in case all data-nodes are powered down after being previously started
                    # ignore the lock to get a data-node started, as it holds security index
                    self.state.server.started
                    and not self.workload.is_service_started()
                )
            )
            # TODO: Handle large deployment cases
            # and self.peer_cluster_requirer.get_cluster_first_data_node() is None
            # and (
            # deployment_desc.typ != DeploymentType.FAILOVER_ORCHESTRATOR
            # or self._is_failover_and_sole_data_app()
            # )
        )

    def unit_with_lock(self, host: str | None) -> str | None:
        """Unit that has acquired OpenSearch lock."""
        try:
            document_data = self.opensearch_client.request(
                "GET",
                endpoint=f"/{self.OPENSEARCH_INDEX}/_source/0",
                host=host,
                alt_hosts=self.alt_hosts,
                retries=3,
                ignore_retry_on=[404],
            )
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                # No unit has lock or index not available
                return
            raise
        return document_data["unit-name"]

    @property
    def acquired(self) -> bool:  # noqa: C901
        """Attempt to acquire lock.

        Returns:
            Whether lock was acquired
        """
        host = self.state.host_ip if self.opensearch_client.is_node_up() else None
        alt_hosts = self.alt_hosts
        if host or alt_hosts:
            logger.debug("[Node lock] 1+ opensearch nodes online")
            try:
                online_nodes = len(self._nodes(use_localhost=host is not None, hosts=alt_hosts))
            except OpenSearchHttpError:
                logger.exception("Error getting OpenSearch nodes")
                return False
            logger.debug(f"[Node lock] Opensearch {online_nodes=}")
            assert online_nodes > 0
            try:
                unit = self.unit_with_lock(host)
            except OpenSearchHttpError:
                logger.exception("Error checking which unit has OpenSearch lock")
                # if the node lock cannot be acquired, fall back to peer databag lock
                # this avoids hitting deadlock situations in cases where
                # the .charm_node_lock index is not available
                if online_nodes <= 1:
                    return super().acquired
                else:
                    return False
            # If online_nodes == 1, we should acquire the lock via the peer databag.
            # If we acquired the lock via OpenSearch and this unit was stopping, we would be unable
            # to release the OpenSearch lock. For example, when scaling to 0.
            # Then, when 1+ OpenSearch nodes are online, a unit that no longer exists could hold
            # the lock.
            if not unit and online_nodes > 0:
                logger.debug("[Node lock] Attempting to acquire opensearch lock")
                # Acquire opensearch lock
                # Create index if it doesn't exist
                if not self._create_lock_index_if_needed(host, alt_hosts):
                    return False

                # Attempt to create document id 0
                try:
                    response = self.opensearch_client.request(
                        "PUT",
                        endpoint=f"/{self.OPENSEARCH_INDEX}/_create/0?refresh=true&wait_for_active_shards=all",
                        host=host,
                        alt_hosts=self.alt_hosts,
                        retries=0,
                        payload={"unit-name": self.state.unit_name},
                    )
                except OpenSearchHttpError as e:
                    if e.response_code == 409 and "document already exists" in e.response_body.get(
                        "error", {}
                    ).get("reason", ""):
                        # Document already created
                        logger.debug(
                            "[Node lock] Another unit acquired OpenSearch lock while this unit attempted "
                            "to acquire lock"
                        )
                        return False
                    else:
                        logger.exception("Error creating OpenSearch lock document")
                        # in this case, try to acquire peer databag lock as fallback
                        return super().acquired
                else:
                    # Ensure write was successful on all nodes
                    # "It is important to note that this setting [`wait_for_active_shards`] greatly
                    # reduces the chances of the write operation not writing to the requisite
                    # number of shard copies, but it does not completely eliminate the possibility,
                    # because this check occurs before the write operation commences. Once the
                    # write operation is underway, it is still possible for replication to fail on
                    # any number of shard copies but still succeed on the primary. The `_shards`
                    # section of the write operation’s response reveals the number of shard copies
                    # on which replication succeeded/failed."
                    # from
                    # https://www.elastic.co/guide/en/elasticsearch/reference/8.13/docs-index_.html#index-wait-for-active-shards
                    if response["_shards"]["failed"] > 0:
                        logger.error("Failed to write OpenSearch lock document to all nodes.")
                        logger.debug(
                            "[Node lock] Deleting OpenSearch lock after failing to write to all nodes"
                        )
                        # Delete document id 0
                        self.opensearch_client.request(
                            "DELETE",
                            endpoint=f"/{self.OPENSEARCH_INDEX}/_doc/0?refresh=true",
                            host=host,
                            alt_hosts=self.alt_hosts,
                            retries=10,
                        )
                        logger.debug(
                            "[Node lock] Deleted OpenSearch lock after failing to write to all nodes"
                        )
                        return False

                    # This unit has OpenSearch lock
                    unit = self.state.unit_name

            if unit == self.state.unit_name:
                # Lock acquired
                # Release peer databag lock, if any
                logger.debug("[Node lock] Acquired via opensearch")
                super().release()
                logger.debug("[Node lock] Released redundant peer lock (if held)")
                return True

            if unit:
                # Another unit has lock
                logger.debug(f"[Node lock] Not acquired. Unit with opensearch lock: {unit}")
                return False

            assert online_nodes == 1
            logger.debug("[Node lock] No unit has opensearch lock")
        logger.debug("[Node lock] Using peer databag for lock")
        # Request peer databag lock
        # If return value is True:
        # - Lock granted in previous Juju event
        # - OR, unit is leader & lock granted in this Juju event
        return super().acquired

    def release(self):
        """Release lock.

        Limitation: if lock acquired via OpenSearch document and all units offline, OpenSearch
        document lock will not be released
        """
        logger.debug("[Node lock] Releasing lock")

        # fetch current app description
        current_app = self.state.application.deployment_desc.app

        host = self.state.host_ip if self.opensearch_client.is_node_up() else None
        alt_hosts = self.alt_hosts
        if host or alt_hosts:
            logger.debug("[Node lock] Checking which unit has opensearch lock")
            # Check if this unit currently has lock
            # or if there is a stale lock from a unit no longer existing
            # for large deployments the MAIN/FAILOVER orchestrators should broadcast info
            # over non-online units in the relation. This info should be considered here as well.
            unit_with_lock = self.unit_with_lock(host)
            current_app_units = [
                format_unit_name(unit, app=current_app) for unit in self.state.all_units
            ]

            # handle case of large deployments
            other_apps_units = []
            if all_apps := self.state.application.cluster_fleet_apps:
                for app in all_apps.values():
                    p_cluster_app = PeerClusterApp.from_dict(app)
                    if p_cluster_app.app.id == current_app.id:
                        continue

                    units = [
                        format_unit_name(unit, app=p_cluster_app.app)
                        for unit in p_cluster_app.units
                    ]
                    other_apps_units.extend(units)

            if unit_with_lock and (
                unit_with_lock == self.state.unit_name
                or unit_with_lock not in current_app_units + other_apps_units
            ):
                logger.debug("[Node lock] Releasing opensearch lock")
                # Delete document id 0
                try:
                    self.opensearch_client.request(
                        "DELETE",
                        endpoint=f"/{self.OPENSEARCH_INDEX}/_doc/0?refresh=true",
                        host=host,
                        alt_hosts=alt_hosts,
                        retries=3,
                        ignore_retry_on=[404],
                    )
                except OpenSearchHttpError as e:
                    if e.response_code != 404:
                        raise
                logger.debug("[Node lock] Released opensearch lock")
        super().release()
        logger.debug("[Node lock] Released peer lock (if held)")
        logger.debug("[Node lock] Released lock")

    def _create_lock_index_if_needed(self, host: str, alt_hosts: list[str] | None) -> bool:
        """Attempts the creation of the lock index if it doesn't exist."""
        # we do this, to circumvent opensearch raising a 429 error,
        # complaining about spamming the index creation endpoint
        try:
            indices = self.opensearch_client.get_indices(host, alt_hosts)
            if self.OPENSEARCH_INDEX in indices:
                logger.debug(
                    f"{self.OPENSEARCH_INDEX} already created. Skipping creation attempt. List:{indices}"
                )
                if self.state.application.app.planned_units() > 1:
                    self.opensearch_client.request(
                        "GET",
                        endpoint=f"/_cluster/health/{self.OPENSEARCH_INDEX}?wait_for_status=green",
                        resp_status_code=True,
                    )
                return True
        except OpenSearchHttpError:
            pass

        # Create index if it doesn't exist
        try:
            self.opensearch_client.request(
                "PUT",
                endpoint=f"/{self.OPENSEARCH_INDEX}?wait_for_active_shards=all",
                host=host,
                alt_hosts=alt_hosts,
                retries=3,
                ignore_retry_on=[400],
                payload={"settings": {"index": {"auto_expand_replicas": "0-all"}}},
            )
            return True
        except OpenSearchHttpError as e:
            if (
                e.response_code == 400
                and e.response_body.get("error", {}).get("type")
                == "resource_already_exists_exception"
            ):
                # Index already created
                return True
            else:
                logger.exception("Error creating OpenSearch lock index")
                return False
