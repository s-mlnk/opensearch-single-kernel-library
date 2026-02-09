#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Base Charm."""

from abc import ABC, abstractmethod

import ops
from ops import EventSource

from opensearch_single_kernel.common.constants import Substrates
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.events.custom_events import (
    RestartOpenSearch,
    StartOpenSearch,
)
from opensearch_single_kernel.events.opensearch import OpenSearchEventsHandler
from opensearch_single_kernel.events.tls import TLSEventsHandler
from opensearch_single_kernel.managers.cluster import ClusterManager
from opensearch_single_kernel.managers.config import ConfigManager
from opensearch_single_kernel.managers.exclusions import NodesExclusionsManager
from opensearch_single_kernel.managers.health import HealthManager
from opensearch_single_kernel.managers.lock import LockManager
from opensearch_single_kernel.managers.profiles import ProfilesManager
from opensearch_single_kernel.managers.tls import TlsManager
from opensearch_single_kernel.managers.users import UsersManager
from opensearch_single_kernel.utils.status import Status
from opensearch_single_kernel.workload.base import BaseWorkload


class OpenSearchBaseCharm(ops.CharmBase, ABC):
    """Base OpenSearch Charm, this will include base structure for both machine and k8s charms."""

    restart_opensearch_event = EventSource(RestartOpenSearch)
    start_opensearch_event = EventSource(StartOpenSearch)

    def __init__(self, *args):
        super().__init__(*args)

        # Status
        self.status = Status(self)

        # State
        self.state = ClusterState(self, self.substrate)

        # Managers
        self.tls_manager = TlsManager(self.state, self.workload)
        self.users_manager = UsersManager(self.state, self.workload)
        self.cluster_manager = ClusterManager(self.state, self.workload)
        self.exclusions_manager = NodesExclusionsManager(self.state, self.workload)
        self.lock_manager = LockManager(self.state, self.workload)
        self.profiles_manager = ProfilesManager(self.state, self.workload)
        self.health_manager = HealthManager(self.state, self.workload)
        self.config_manager = ConfigManager(self.state, self.workload)

        # Event Handlers
        self.opensearch_events = OpenSearchEventsHandler(self)
        self.tls_events = TLSEventsHandler(self)

    @property
    @abstractmethod
    def workload(self) -> BaseWorkload:
        """Access current workload."""
        pass

    @property
    @abstractmethod
    def substrate(self) -> Substrates:
        """Access current substrate."""
        pass
