#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for TLS events."""
import logging
from typing import TYPE_CHECKING

from ops import (
    ActionEvent,
    Object,
    RelationBrokenEvent,
    RelationCreatedEvent,
)

from opensearch_single_kernel.common.constants import (
    TLS_RELATION,
    CertType,
    DeploymentType,
    Scope,
    StoreType,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
)
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
    TLSCertificatesRequiresV3,
)

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
        self.framework.observe(self.charm.on.set_tls_private_key_action, self._on_set_private_key)
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

    def _on_set_private_key(self, event: ActionEvent):
        """Set the TLS private key, which will be used for requesting the certificate."""
        if not self.charm.state.application.deployment_desc:
            event.fail("The action can only be run once the deployment is complete.")
            return
        # TODO: Check if the charm is in upgrade

        cert_type = CertType(event.params["category"])  # type
        scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT
        if scope == Scope.APP and not (
            self.charm.unit.is_leader()
            and self.charm.state.application.deployment_desc.typ
            == DeploymentType.MAIN_ORCHESTRATOR
        ):
            event.log(
                "Only the juju leader unit of the main orchestrator can set private key for the admin certificates."
            )
            return

        try:
            csr = self.charm.tls_manager.create_certificate_signing_request(
                scope, cert_type, event.params.get("key", None), event.params.get("password", None)
            )
            if self.charm.model.get_relation(TLS_RELATION):
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

            if self.charm.state.tls_relation:
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
        if self.charm.state.tls_relation:
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

        # seems like the admin certificate is also broadcast to non leader units on refresh request
        if not self.charm.unit.is_leader() and scope == Scope.APP:
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
            if not (deployment_desc := self.charm.state.application.deployment_desc):
                logger.debug("Could not store new CA certificate.")
                event.defer()
                return
            if not self.charm.tls_manager.store_new_ca(
                self.charm.state.secrets.get_object(scope, cert_type.val, peek=True),
                create_store_pwd=self.charm.unit.is_leader()
                and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR,
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
            cert_type, self.charm.state.secrets.get_object(scope, cert_type.val, peek=True)
        )

        # apply the chain.pem file for API requests, only if the CA cert has not been updated
        admin_secrets = (
            self.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )
        if admin_secrets.get("chain") and not self.charm.tls_manager.read_stored_ca(
            alias=self.charm.tls_manager.OLD_CA_ALIAS
        ):
            self.charm.tls_manager.update_request_ca_bundle()

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
        except OpenSearchError as e:
            logger.exception(e)
            event.defer()

    def on_tls_ca_rotation(self) -> None:
        """Called when adding new CA to the trust store."""
        self.charm.status.set(CharmStatuses.TLS_CA_ROTATION)
        logger.debug("Restarting opensearch due to CA rotation")
        self.charm._restart_opensearch_event.emit()

    def _on_certificate_expiring(
        self, event: CertificateExpiringEvent | CertificateInvalidatedEvent
    ) -> None:
        """Request the new certificate when old certificate is expiring."""
        self.charm.state.server.update({"tls_configured": None})
        # TODO: Update peer cluster relation
        try:
            scope, cert_type, secrets = self.charm.tls_manager.find_secret(
                event.certificate, "cert"
            )
            logger.debug(f"{scope.val}.{cert_type.val} TLS certificate expiring.")
        except TypeError:
            logger.debug("Unknown certificate expiring.")
            return

        key = secrets["key"]
        key_password = secrets.get("key-password", None)
        old_csr = secrets["csr"].encode("utf-8")

        new_csr = self.charm.tls_manager.create_certificate_signing_request(
            scope=scope, cert_type=cert_type, key=key, password=key_password
        )
        self.certs.request_certificate_renewal(
            old_certificate_signing_request=old_csr, new_certificate_signing_request=new_csr
        )

    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent) -> None:
        """Handle a cert that was revoked or has expired"""
        logger.debug(f"Received certificate invalidation. Reason: {event.reason}")
        self._on_certificate_expiring(event)

    def on_tls_conf_set(
        self, event: CertificateAvailableEvent, scope: Scope, cert_type: CertType, renewal: bool
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
            if not (truststore_pwd := admin_secrets.get("truststore-password")):
                event.defer()
                return

            keystore_pwd = self.charm.state.secrets.get_object(scope, cert_type.val, peek=True)[
                "keystore-password"
            ]

            # node http or transport cert
            self.charm.config_manager.set_node_tls_conf(
                cert_type,
                truststore_pwd=truststore_pwd,
                keystore_pwd=keystore_pwd,
            )

            # write the admin cert conf on all units, in case there is a leader loss + cert renewal
            if not admin_secrets.get("subject"):
                return
            self.charm.config_manager.set_admin_tls_conf(admin_secrets)

        self.charm.tls_manager.store_admin_tls_secrets_if_applies()

        # In case of renewal of the unit transport layer cert - restart opensearch
        if renewal and self.charm.state.application.is_admin_user_initialized:
            if self.charm.tls_manager.is_fully_configured():
                try:
                    self.charm.tls_manager.reload_tls_certificates()
                except OpenSearchHttpError:
                    logger.error("Could not reload TLS certificates via API, will restart.")
                    self.charm._restart_opensearch_event.emit()
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
            self.certs.request_certificate_revocation(csr)

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

            self.certs.request_certificate_renewal(
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

        self.certs.request_certificate_creation(certificate_signing_request=csr)
