#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for General OpenSearch action events."""

from typing import TYPE_CHECKING

from ops import (
    ActionEvent,
    Object,
)

from opensearch_single_kernel.common.constants import (
    OPENSEARCH_USERS,
    CertType,
    DeploymentType,
    Scope,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchError,
)
from opensearch_single_kernel.utils.helpers import generate_password

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


class ActionsEventsHandler(Object):
    """Class implementing OpenSearch Charm actions handling."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, key="actions_events")
        self.charm = charm

        # --- events ---
        self.framework.observe(self.charm.on.set_password_action, self._on_set_password_action)
        self.framework.observe(self.charm.on.get_password_action, self._on_get_password_action)

    def _on_set_password_action(self, event: ActionEvent):
        """Set new admin password from user input or generate if not passed."""
        if not self.charm.state.application.deployment_desc:
            event.fail("The action can only be run once the deployment is complete.")
            return
        if self.charm.state.application.deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            event.fail("The action can only be run on the main orchestrator cluster.")
            return
        if not self.charm.unit.is_leader():
            event.fail("The action can only be run on leader unit.")
            return
        # TODO: block on upgrade
        # if self.upgrade_in_progress:
        # event.fail("Setting password not supported while upgrade in-progress")
        # return

        user_name = event.params.get("username")
        if user_name not in OPENSEARCH_USERS:
            event.fail(f"Only the {OPENSEARCH_USERS} usernames are allowed for this action.")
            return

        password = event.params.get("password") or generate_password()
        try:
            self.charm.users_manager.put_or_update_internal_user_leader(user_name, password)
            label = self.charm.state.secrets.password_key(user_name)
            event.set_results({label: password})
            # We know we are already running for MAIN_ORCH. and its leader unit
            # TODO: Update relation of peer cluster provider
            # self.peer_cluster_provider.refresh_relation_data(event)
        except OpenSearchError as e:
            event.fail(f"Failed changing the password: {e}")
        except RuntimeError as e:
            # From:
            # https://github.com/canonical/operator/blob/ \
            #     eb52cef1fba4df2f999f88902fb39555fb6de52f/ops/charm.py
            if str(e) == "cannot defer action events":
                event.fail("Cluster is not ready to update this password. Try again later.")
            else:
                event.fail(f"Failed with unknown error: {e}")

    def _on_get_password_action(self, event: ActionEvent):
        """Return the password and cert chain for the admin user of the cluster."""
        if not self.charm.state.application.deployment_desc:
            event.fail("The action can only be run once the deployment is complete.")
            return

        user_name = event.params.get("username")
        if user_name not in OPENSEARCH_USERS:
            event.fail(f"Only the {OPENSEARCH_USERS} username is allowed for this action.")
            return

        if not self.charm.state.application.is_admin_user_initialized:
            event.fail(f"{user_name} user not configured yet.")
            return

        if not self.charm.tls_manager.is_fully_configured():
            event.fail("TLS certificates not configured yet.")
            return

        password = self.charm.state.secrets.get(
            Scope.APP, self.charm.state.secrets.password_key(user_name)
        )
        cert = self.charm.state.secrets.get_object(
            Scope.APP, CertType.APP_ADMIN.val, peek=True
        )  # replace later with new user certs

        event.set_results(
            {
                "username": user_name,
                "password": password,
                "ca-chain": cert["chain"],
            }
        )
