#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Nodes Exclusions manager."""

import logging

from opensearch_single_kernel.common.constants import Scope
from opensearch_single_kernel.common.exceptions import (
    OpenSearchExclusionsException,
    OpenSearchHttpError,
)
from opensearch_single_kernel.core.models import Node
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import format_unit_name
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class NodesExclusionsManager(BaseManager):
    """OpenSearch Nodes Exclusions Manager."""

    CONFIG_YML = "opensearch.yml"

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "exclusions_manager"

    def _fetch_voting(self) -> set[str]:
        """Fetch the registered voting exclusions."""
        try:
            return self.opensearch_client.fetch_voting_config_exclusions(alt_hosts=self.alt_hosts)
        except (OpenSearchHttpError, KeyError) as e:
            logger.warning(f"Failed to fetch voting exclusions: {e}")
            # no voting exclusion set
            return {}

    def _delete_voting(self, exclusions: set[str], scope: Scope) -> bool:
        """Remove all voting exclusions and then re-adds the subset that should stay.

        The API does not allow to remove a subset of the voting exclusions, at once.
        """
        current_excl = self._fetch_voting()
        logger.debug("Current voting exclusions: %s", current_excl)
        if not current_excl:
            to_stay = None
        else:
            to_stay = current_excl - exclusions
        if current_excl == to_stay:
            # Nothing to do
            logger.debug("No voting exclusions to delete, current set is %s", to_stay)
            return True

        # "wait_for_removal" is VERY important, it removes all voting configs immediately
        # and allows any node to return to the voting config in the future
        try:
            if not self.opensearch_client.remove_exclusions(
                exclusions=exclusions,
                alt_hosts=self.alt_hosts,
            ):
                return False

            if to_stay:
                # Now, we register the units that should stay
                if not self.opensearch_client.add_voting_exclusions(
                    exclusions=to_stay,
                    alt_hosts=self.alt_hosts,
                ):
                    return False

            # Finally, we clean up the VOTING_TO_DELETE
            if scope == Scope.APP:
                self.state.application.delete_voting_exclusions = (
                    self.state.application.delete_voting_exclusions - exclusions
                )
            else:
                self.state.server.delete_voting_exclusions = (
                    self.state.server.delete_voting_exclusions - exclusions
                )

            return True
        except OpenSearchHttpError as e:
            logger.error(f"Failed to delete voting exclusions {exclusions}: {e}")
            return False

    def _delete_allocations(self, node: Node, allocs: list[str] | None = None) -> bool:
        """This removes the allocation exclusions if needed."""
        try:
            existing = self.opensearch_client.fetch_allocations(alt_hosts=self.alt_hosts)
            to_remove = set(allocs if allocs is not None else [node.name])
            res = self.opensearch_client.add_allocations(
                node, allocations=existing - to_remove, override=True, alt_hosts=self.alt_hosts
            )
            return res
        except OpenSearchHttpError:
            return False

    def add_current(
        self,
        node: Node,
        scope: Scope,
        voting: bool = True,
        allocation: bool = True,
        raise_error: bool = False,
    ) -> None:
        """Add voting and alloc exclusions."""
        if voting and (node.is_cm_eligible() or node.is_voting_only()):
            if not self._add_voting(scope, node):
                logger.error(f"Failed to add voting exclusion: {node.name}.")
                if raise_error:
                    raise OpenSearchExclusionsException("Failed to add voting exclusion.")

        if allocation and node.is_data():
            if not self.opensearch_client.add_allocations(node=node, alt_hosts=self.alt_hosts):
                logger.error(f"Failed to add shard allocation exclusion: {node.name}.")
                if raise_error:
                    raise OpenSearchExclusionsException("Failed to add allocation exclusion.")

    def delete_current(
        self,
        node: Node,
        scope: Scope,
        voting: bool = True,
        allocation: bool = True,
        raise_error: bool = False,
    ) -> None:
        """Delete voting and alloc exclusions."""
        if voting and (node.is_cm_eligible() or node.is_voting_only()):
            if not self._delete_voting({node.name}, scope):
                logger.error(f"Failed to delete voting exclusion: {node.name}.")
                if raise_error:
                    raise OpenSearchExclusionsException("Failed to delete voting exclusion.")

        if allocation and node.is_data():
            if not self._delete_allocations(node):
                logger.error(f"Failed to delete shard allocation exclusion: {node.name}.")
                # Load the content of the list, avoiding '' entries
                if scope == Scope.APP:
                    state = self.state.application
                else:
                    state = self.state.server
                current_allocations = state.allocation_exclusions_to_delete
                current_allocations.add(node.name)
                state.allocation_exclusions_to_delete = current_allocations

                if raise_error:
                    raise OpenSearchExclusionsException("Failed to delete allocation exclusion.")

    def _units_to_cleanup(self, removable: list[str]) -> set[str] | None:
        """Deletes all units that have left the cluster via Juju.

        This method ensures we keep a small list of voting exclusions at all times.
        """
        if not (deployment_desc := self.state.application.deployment_desc) or not removable:
            return set()

        # if self._charm.opensearch_peer_cm.is_provider(typ="main") and (
        #    apps_in_fleet := self.state.application.cluster_fleet_apps
        # ):
        #    apps_in_fleet = [PeerClusterApp.from_dict(app) for app in apps_in_fleet.values()]
        #    units = {
        #        format_unit_name(u, p_cluster_app.app)
        #        for p_cluster_app in apps_in_fleet
        #        for u in p_cluster_app.units
        #    }
        # else:

        units = {format_unit_name(u, deployment_desc.app) for u in self.state.all_units}

        # Now, we need to remove the units that were marked for deletion and are not in the
        # cluster anymore.
        to_remove = []
        for node in removable:
            if node not in units:
                # Unit still exists
                to_remove.append(node)
        return set(to_remove)

    def cleanup(self, scope: Scope, node: Node) -> None:
        """Delete all exclusions that failed to be deleted."""
        state = self.state.application if scope == Scope.APP else self.state.server
        units_to_cleanup = self._units_to_cleanup(list(state.delete_voting_exclusions))
        self._delete_voting(units_to_cleanup, scope)
        allocations_to_cleanup = list(state.allocation_exclusions_to_delete)
        if allocations_to_cleanup and self._delete_allocations(node, allocations_to_cleanup):
            state.update({"allocation-exclusions-to-delete": None})

    def add_to_cleanup_list(self, unit_name: str, scope: Scope) -> None:
        """Add Voting and alloc exclusions for a target unit.

        This method is just a clean-up-later routine. We (re)add the unit to the exclusions and,
        hence, the leader of this app will be aware of this unit's removal and log it into its
        app-level peer data.
        """
        state = self.state.application if scope == Scope.APP else self.state.server
        for lst in [state.allocation_exclusions_to_delete, state.delete_voting_exclusions]:
            # Load the content of the list, avoiding '' entries
            lst = lst.union({unit_name})

    def _add_voting(self, scope: Scope, node: Node, exclusions: set[str] | None = None) -> bool:
        """Include the current node in the CMs voting exclusions list of nodes."""
        try:
            to_add = exclusions or {node.name}
            result = self.opensearch_client.add_voting_exclusions(
                exclusions=to_add,
                alt_hosts=self.alt_hosts,
            )
            if scope == Scope.APP:
                self.state.application.delete_voting_exclusions = to_add.union(
                    self.state.application.delete_voting_exclusions
                )
            else:
                self.state.server.delete_voting_exclusions = to_add.union(
                    self.state.server.delete_voting_exclusions
                )

            # The voting excl. API returns a status only
            return result
        except OpenSearchHttpError:
            return False
