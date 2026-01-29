#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for TLS events."""

import logging
from typing import TYPE_CHECKING

from ops import (
    ActionEvent,
    ConfigChangedEvent,
    Object,
    RelationBrokenEvent,
    RelationCreatedEvent,
)

from opensearch_single_kernel.common.constants import (
    OPENSEARCH_USERS,
    TLS_RELATION,
    CertType,
    DeploymentType,
    Scope,
    StoreType,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchError,
    OpenSearchFileOperationError,
    OpenSearchHttpError,
)
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
    TLSCertificatesRequiresV3,
)
from opensearch_single_kernel.utils.helpers import generate_password

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class TLSEventsHandler(Object):
    """Class implementing OpenSearch TLS events handling."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, key="tls_events")
        self.charm = charm

        # Requirer
        self.certs = TLSCertificatesRequiresV3(charm, TLS_RELATION, expiry_notification_time=23)

        # Events
        self.framework.observe(
            self.charm.on[TLS_RELATION].relation_created, self._on_tls_relation_created
        )
        self.framework.observe(
            self.charm.on[TLS_RELATION].relation_broken, self._on_tls_relation_broken
        )

        self.framework.observe(self.certs.on.certificate_available, self._on_certificate_available)
        self.framework.observe(self.certs.on.certificate_expiring, self._on_certificate_expiring)
        self.framework.observe(
            self.certs.on.certificate_invalidated, self._on_certificate_invalidated
        )

        # Actions
        self.framework.observe(self.charm.on.set_tls_private_key_action, self._on_set_private_key)
        self.framework.observe(self.charm.on.set_password_action, self._on_set_password_action)
        self.framework.observe(self.charm.on.get_password_action, self._on_get_password_action)

    def _on_set_private_key(self, event: ActionEvent):
        """Set the TLS private key, which will be used for requesting the certificate."""
        if not self.charm.state.application.deployment_desc:
            event.fail("The action can only be run once the deployment is complete.")
            return
        # TODO: Check if the charm is in upgrade

        if not self.charm.state.tls_relation:
            event.fail("TLS relation not available.")
            return

        cert_type = CertType(event.params["category"])  # type
        scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT
        if scope == Scope.APP and not (
            self.charm.unit.is_leader()
            and self.charm.state.application.deployment_desc.typ
            == DeploymentType.MAIN_ORCHESTRATOR
        ):
            event.fail(
                "Only the juju leader unit of the main orchestrator can set private key for the admin certificates."
            )
            return

        try:
            secrets = {
                "key": event.params.get("key", None),
                "key-password": event.params.get("password", None),
            }
            csr = self.charm.tls_manager.create_certificate_signing_request(
                scope, cert_type, secrets=secrets
            )
            self.certs.request_certificate_creation(certificate_signing_request=csr)

        except ValueError as e:
            event.fail(str(e))

    def _on_tls_relation_created(self, event: RelationCreatedEvent) -> None:
        """Request certificate when TLS relation created."""
        # TODO: Defer when upgrade is in progress
        if not (deployment_desc := self.charm.state.application.deployment_desc):
            event.defer()
            return

        admin_cert = (
            self.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )

        if self.charm.unit.is_leader() and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            # create passwords for both ca trust_store/admin key_store
            self.charm.tls_manager.create_store_pwd_if_not_exists(
                Scope.APP, CertType.APP_ADMIN, StoreType.TRUSTSTORE
            )
            self.charm.tls_manager.create_store_pwd_if_not_exists(
                Scope.APP, CertType.APP_ADMIN, StoreType.KEYSTORE
            )
            csr = self.charm.tls_manager.create_certificate_signing_request(
                Scope.APP, CertType.APP_ADMIN
            )

            self.certs.request_certificate_creation(certificate_signing_request=csr)
        elif not admin_cert.get("truststore-password"):
            logger.debug("Truststore-password from main-orchestrator not available yet.")
            event.defer()
            return

        # create passwords for both unit-http/transport key_stores
        self.charm.tls_manager.create_store_pwd_if_not_exists(
            Scope.UNIT, CertType.UNIT_TRANSPORT, StoreType.KEYSTORE
        )
        self.charm.tls_manager.create_store_pwd_if_not_exists(
            Scope.UNIT, CertType.UNIT_HTTP, StoreType.KEYSTORE
        )

        unit_transport_csr = self.charm.tls_manager.create_certificate_signing_request(
            Scope.UNIT, CertType.UNIT_TRANSPORT
        )
        unit_http_csr = self.charm.tls_manager.create_certificate_signing_request(
            Scope.UNIT, CertType.UNIT_HTTP
        )
        self.certs.request_certificate_creation(certificate_signing_request=unit_transport_csr)
        self.certs.request_certificate_creation(certificate_signing_request=unit_http_csr)

    def _on_tls_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Notify the charm that the relation is broken."""
        # TODO: If upgrade log a warning
        if self.charm.tls_manager.all_tls_resources_stored():
            return

        # Otherwise, we block.
        self.charm.status.set(CharmStatuses.TLS_RELATION_BROKEN)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:  # noqa: C901
        """Enable TLS when TLS certificate available.

        CertificateAvailableEvents fire whenever a new certificate is created by the TLS charm.
        """
        try:
            scope, cert_type, secrets = self.charm.tls_manager.find_secret(
                event.certificate_signing_request, "csr"
            )
            logger.debug(f"{scope.val}.{cert_type.val} TLS certificate available.")
        except TypeError:
            logger.debug("Unknown certificate available.")
            return

        # variables for better readability
        is_leader_unit = self.charm.unit.is_leader()

        deployment_desc = self.charm.state.application.deployment_desc
        is_main_orchestrator = deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR

        # seems like the admin certificate is also broadcast to non leader units on refresh request
        if not is_leader_unit and scope == Scope.APP:
            return

        old_cert = secrets.get("cert", None)
        ca_chain = "\n".join(event.chain[::-1])

        self.charm.tls_manager.update_certificate_secret_if_needed(
            scope=scope,
            cert_type=cert_type,
            ca_chain=ca_chain,
            certificate=event.certificate,
            ca=event.ca,
        )

        current_stored_ca = self.charm.tls_manager.read_stored_ca()
        if current_stored_ca != event.ca:
            if not self.charm.tls_manager.store_new_ca(
                self.charm.state.secrets.get_object(scope, cert_type.val, peek=True),
                create_store_pwd=is_leader_unit and is_main_orchestrator,
            ):
                logger.debug("Could not store new CA certificate.")
                event.defer()
                return
            # replacing the current CA initiates a rolling restart and certificate renewal
            # the workflow is the following:
            # get new CA -> set tls_ca_renewing -> restart -> post_start_init -> set tls_ca_renewed
            # -> request new certs -> get new certs -> on_tls_conf_set
            # -> delete both tls_ca_renewing and tls_ca_renewed
            if current_stored_ca:
                self.charm.state.server.tls_ca_renewing = True
                # TODO: Handle this when large deployments are introduced
                # self.update_tls_flag_to_peer_cluster_relation(
                # flag="tls_ca_renewing", operation="add"
                # )
                self.on_tls_ca_rotation()
                return

        # store the certificates and keys in a key store
        self.charm.tls_manager.store_new_tls_resources(
            cert_type,
            self.charm.state.secrets.get_object(scope, cert_type.val, peek=True),
        )

        # apply the chain.pem file for API requests, only if the CA cert has not been updated
        admin_secrets = (
            self.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )
        if admin_secrets.get("chain") and not self.charm.tls_manager.read_stored_ca(
            alias=self.charm.tls_manager.OLD_CA_ALIAS
        ):
            try:
                self.charm.tls_manager.update_request_ca_bundle()
            except OpenSearchFileOperationError as e:
                logger.debug(f"Error while updating request CA bundle: {e}")
                event.defer()
                return

        # store the admin certificates in non-leader units
        # if admin cert not available we need to defer, otherwise it will never be stored
        if not self.charm.unit.is_leader():
            if admin_secrets.get("cert"):
                self.charm.tls_manager.store_new_tls_resources(CertType.APP_ADMIN, admin_secrets)
            else:
                logger.info("Admin certificate not available yet. Waiting for next events.")
                event.defer()
                return

        # TODO: Handle opensearch-client relation in a separate PR.
        # for relation in self.charm.opensearch_provider.relations:
        #    try:
        # self.charm.opensearch_provider.update_certs(relation.id, ca_chain)
        # except KeyError:
        # As we are setting the ca_chain, it should not be likely to happen a KeyError at
        # update_certs. This logic is left for a very corner case.
        # logger.error("Error updating certificates in the relation: ca_chain not set.")
        # event.defer()
        # return

        # TODO: Handle large deployment case
        # broadcast secret updates for certs and CA to related sub-clusters
        # if self.charm.unit.is_leader() and self.charm.opensearch_peer_cm.is_provider(typ="main"):
        # self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)

        renewal = self.charm.tls_manager.read_stored_ca(
            alias=self.charm.tls_manager.OLD_CA_ALIAS
        ) is not None or (old_cert is not None and old_cert != event.certificate)

        try:
            self.on_tls_conf_set(event, scope, cert_type, renewal)
        except (OpenSearchError, OpenSearchFileOperationError) as e:
            logger.exception(e)
            event.defer()

    def on_tls_ca_rotation(self) -> None:
        """Called when adding new CA to the trust store."""
        self.charm.status.set(CharmStatuses.TLS_CA_ROTATION)
        logger.debug("Restarting opensearch due to CA rotation")
        self.charm.restart_opensearch_event.emit()

    def _on_certificate_expiring(
        self, event: CertificateExpiringEvent | CertificateInvalidatedEvent
    ) -> None:
        """Request the new certificate when old certificate is expiring."""
        self.charm.state.server.update({"tls_configured": ""})
        # TODO: Update peer cluster relation
        try:
            scope, cert_type, secrets = self.charm.tls_manager.find_secret(
                event.certificate, "cert"
            )
            logger.debug(f"{scope.val}.{cert_type.val} TLS certificate expiring.")
        except TypeError:
            logger.debug("Unknown certificate expiring.")
            return

        old_csr = secrets["csr"].encode("utf-8")

        new_csr = self.charm.tls_manager.create_certificate_signing_request(
            scope=scope, cert_type=cert_type, secrets=secrets, tls_file=False
        )
        self.certs.request_certificate_renewal(
            old_certificate_signing_request=old_csr,
            new_certificate_signing_request=new_csr,
        )

    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent) -> None:
        """Handle a cert that was revoked or has expired"""
        logger.debug(f"Received certificate invalidation. Reason: {event.reason}")
        self._on_certificate_expiring(event)

    def on_unit_ip_changed(self, event: ConfigChangedEvent) -> None:
        """Triggered when the unit IP is changed."""
        self.charm.status.set(CharmStatuses.TLS_NEW_CERTS_REQUESTED)
        self.charm.tls_manager.delete_stored_tls_resources()
        self.request_new_unit_certificates()

    def on_tls_conf_set(
        self,
        event: CertificateAvailableEvent,
        scope: Scope,
        cert_type: CertType,
        renewal: bool,
    ):
        """Called after certificate ready and stored on the corresponding scope databag.

        - Store the cert on the file system, on all nodes for APP certificates
        - Update the corresponding yaml conf files
        - Run the security admin script
        """
        if scope == Scope.UNIT:
            admin_secrets = (
                self.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
                or {}
            )

            self.charm.config_manager.update_opensearch_config()
            # write the admin cert conf on all units, in case there is a leader loss + cert renewal
            if not admin_secrets.get("subject"):
                return

        self.charm.tls_manager.store_admin_tls_secrets_if_applies()

        # In case of renewal of the unit transport layer cert - restart opensearch
        if renewal and self.charm.state.application.is_admin_user_initialized:
            if self.charm.tls_manager.is_fully_configured():
                try:
                    self.charm.tls_manager.reload_tls_certificates()
                except OpenSearchHttpError:
                    logger.error("Could not reload TLS certificates via API, will restart.")
                    self.charm.restart_opensearch_event.emit()
                else:
                    self.charm.status.clear(CharmStatuses.TLS_NOT_FULLY_CONFIGURED)
                    self.charm.state.reset_ca_rotation_state()
                    # if all certs are stored and CA rotation is complete in the cluster
                    # we delete the old ca and update the chain to only include the new one
                    if (
                        self.charm.tls_manager.read_stored_ca(self.charm.tls_manager.OLD_CA_ALIAS)
                        and self.charm.state.ca_and_certs_rotation_complete_in_cluster()
                    ):
                        logger.info("on_tls_conf_set: Detected CA rotation complete in cluster")
                        self.charm.tls_manager.finalize_ca_certs_rotation()
            else:
                logger.debug("TLS not fully configured yet, deferring event.")
                event.defer()
                return

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
            # if str(e) == "cannot defer action events":
            #    event.fail("Cluster is not ready to update this password. Try again later.")
            # else:
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
