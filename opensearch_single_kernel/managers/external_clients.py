#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch External Clients Manager."""

from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.workload.base import BaseWorkload


class ExternalClientsManager(BaseManager):
    """OpenSearch External Clients Manager.

    Handles logic of interacting with external clients that are related
    through the opensearch-client interface.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "external_clients_manager"
        self.yaml_setter = YamlConfigSetter(self.workload)
