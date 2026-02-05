#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for Charm."""
import logging
import re
from typing import TYPE_CHECKING

from ops.model import ActiveStatus

from opensearch_single_kernel.common.constants import HealthColors
from opensearch_single_kernel.common.statuses import (
    CharmStatuses,
)
from opensearch_single_kernel.utils.enum import BaseStrEnum
from opensearch_single_kernel.utils.helpers import trigger_peer_rel_changed

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class Status:
    """Class for managing the various status changes in a charm."""

    class CheckPattern(BaseStrEnum):
        """Enum for types of status comparison."""

        Equal = "equal"
        Start = "start"
        End = "end"
        Contain = "contain"
        Interpolated = "interpolated"

    def __init__(self, charm: "OpenSearchBaseCharm"):
        self.charm = charm

    def apply_health(
        self,
        wait_for_green_first: bool = False,
        use_localhost: bool = True,
        app: bool = True,
        unit: bool = True,
    ):
        """Fetch cluster health and set it on the app status."""
        status = self.charm.health_manager.get(
            wait_for_green_first=wait_for_green_first, use_localhost=use_localhost
        )
        logger.info(f"Current health of cluster: {status}")

        if unit:
            self._apply_health_for_unit(status)
        if app:
            self._apply_health_for_app(status)

        return status

    def _apply_health_for_app(self, status: str) -> None:
        """Cluster wide / app status."""
        if not self.charm.unit.is_leader():
            trigger_peer_rel_changed(self.charm, on_other_units=True)
            return

        if status == HealthColors.GREEN:
            # health green: cluster healthy
            self.charm.status.clear(CharmStatuses.CLUSTER_HEALTH_RED, app=True)
            self.charm.status.clear(CharmStatuses.CLUSTER_HEALTH_YELLOW, app=True)
            self.charm.status.clear(CharmStatuses.WAITING_FOR_BUSY_SHARDS, app=True)
        elif status == HealthColors.RED:
            # health RED: some primary shards are unassigned
            self.charm.status.set(CharmStatuses.CLUSTER_HEALTH_RED, app=True)
        elif status == HealthColors.YELLOW_TEMP:
            # health is yellow but temporarily (shards are relocating or initializing)
            self.charm.status.set(CharmStatuses.WAITING_FOR_BUSY_SHARDS, app=True)
        elif status == HealthColors.YELLOW:
            # health is yellow permanently (some replica shards are unassigned)
            self.charm.status.set(CharmStatuses.CLUSTER_HEALTH_YELLOW, app=True)

    def _apply_health_for_unit(self, status: str, host: str | None = None):
        """Apply the health status on the current unit."""
        if status != HealthColors.YELLOW_TEMP:
            self.charm.status.clear(
                CharmStatuses.WAITING_FOR_SPECIFIC_BUSY_SHARDS,
                pattern=Status.CheckPattern.Interpolated,
            )
            return

        busy_shards = self.charm.health_manager.opensearch_client.get_busy_shards_by_unit(
            host=host, alt_hosts=self.charm.health_manager.alt_hosts
        )
        if not busy_shards:
            self.charm.status.clear(
                CharmStatuses.WAITING_FOR_SPECIFIC_BUSY_SHARDS,
                pattern=Status.CheckPattern.Interpolated,
            )
            return

        message = sorted([f"{key}/{','.join(val)}" for key, val in busy_shards.items()])
        self.charm.status.set(
            CharmStatuses.WAITING_FOR_SPECIFIC_BUSY_SHARDS,
            dynamic_params={"shards": " - ".join(message)},
        )

    def clear(
        self,
        status: CharmStatuses,
        pattern: CheckPattern = CheckPattern.Equal,
        app: bool = False,
    ):
        """Resets the unit status if it was previously blocked/maintenance with message."""
        status_message = status.value.message
        context = self.charm.app if app else self.charm.unit

        condition: bool
        if pattern == Status.CheckPattern.Equal:
            condition = context.status.message == status_message
        elif pattern == Status.CheckPattern.Start:
            condition = context.status.message.startswith(status_message)
        elif pattern == Status.CheckPattern.End:
            condition = context.status.message.endswith(status_message)
        elif pattern == Status.CheckPattern.Interpolated:
            regex_pattern = re.sub(r"\{.*?\}", r"(?s:.*?)", status_message)
            condition = re.fullmatch(regex_pattern, context.status.message) is not None
        else:
            condition = status_message in context.status.message

        if condition:
            # if (
            # not app
            # TODO: Make sure to revisit this once we take upgrade as a refactoring subject
            # and self.charm._upgrade
            # and (status := self.charm._upgrade.get_unit_juju_status())
            # ):
            # context.status = status
            # else:
            context.status = ActiveStatus()

    def set(
        self,
        charm_status: CharmStatuses,
        app: bool = False,
        dynamic_params: dict[str, str] | None = None,
    ):
        """Set status on unit or app IF not already set.

        This is seemingly useless, but it is unfortunately needed to avoid updating unnecessarily
        the "last active since" field on the model, which prevents it from stabilizing on small
        machines on integration tests (colliding with "idle period").
        """
        status = charm_status.value
        context = self.charm.app if app else self.charm.unit
        # TODO: Make sure to uncomment and handle this once we take upgrade for refactor
        # Upgrade app status takes priority over other app statuses
        # if app and self.charm._upgrade and (upgrade_status := self.charm._upgrade.app_status):
        # context.status = upgrade_status
        # return
        if dynamic_params:
            # We need to update the default message
            status_message = charm_status.value.message.format(**dynamic_params)
            status_class = status.__class__
            status = status_class(status_message)

        if context.status == status:
            return

        context.status = status
