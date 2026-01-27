#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch TLS manager."""

import logging
import socket
from datetime import datetime
from typing import Any

from charmlibs.pathops import PathProtocol

from opensearch_single_kernel.common.constants import CertType, Scope, StoreType
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates import (
    generate_csr,
    generate_private_key,
)
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import (
    cert_expiration_remaining_hours,
    generate_password,
    is_alias_missing_error,
    parse_tls_file,
    split_ca_chain,
)
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class TlsManager(BaseManager):
    """OpenSearch TLS Manager.

    This manager provides functionalities to deal with certificates creation,
    signing request, managing the keystore, and updating secrets related to tls. It
    can be used by different events handlers not only tls events handler.
    """

    CA_ALIAS = "ca"
    OLD_CA_ALIAS = f"old-{CA_ALIAS}"
    KEYTOOL = "opensearch.keytool"
    OLD_CA_PREFIX = "old-"
    CERTS_EXPIRATION_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "tls_manager"

    def all_tls_resources_stored(self, only_unit_resources: bool = False) -> bool:  # noqa: C901
        """Check if all TLS resources are stored on disk."""
        cert_types = [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]
        if not only_unit_resources:
            cert_types.append(CertType.APP_ADMIN)

        # compare issuer of the cert with the issuer of the CA
        # if they don't match, certs are not up-to-date and need to be renewed after CA rotation
        if not (current_ca := self.read_stored_ca()):
            return False

        ca_issuer = self.get_cert_issuer(cert=current_ca)

        for cert_type in cert_types:
            cert_type_path = self.workload.paths.certs / f"{cert_type}.p12"
            if not cert_type_path.exists():
                return False

            scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT
            secret = self.state.secrets.get_object(scope, cert_type.val, peek=True)

            cert_issuer = self.get_cert_issuer_from_path(
                store_pwd=secret.get("keystore-password"),
                store_path=self.workload.paths.certs / f"{cert_type}.p12",
            )
            if not cert_issuer:
                return False

            if cert_issuer != ca_issuer:
                return False

        return True

    def all_certificates_available(self) -> bool:
        """Method that checks if all certs available and issued from same CA."""
        secrets = self.state.secrets

        admin_secrets = secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        if not admin_secrets or not admin_secrets.get("cert"):
            return False

        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            unit_secrets = secrets.get_object(Scope.UNIT, cert_type.val, peek=True)
            if not unit_secrets or not unit_secrets.get("cert"):
                return False

        return True

    def is_fully_configured(self) -> bool:
        """Check if all TLS secrets and resources exist and are stored."""
        return self.all_certificates_available() and self.all_tls_resources_stored()

    def create_store_pwd_if_not_exists(
        self, scope: Scope, cert_type: CertType, store_type: StoreType
    ):
        """Create passwords for the key stores if not already created.

        Args:
            scope (Scope): The secret scope which can be UNIT / APP.
            cert_type (CertType): The secret certificate type (unit-http, unit-transport).
            store_type (StoreType): The type of store which can be "truststore" or "keystore".
        """
        store_pwd = None

        secrets = self.state.secrets.get_object(scope, cert_type.val, peek=True)
        if secrets:
            store_pwd = secrets.get(f"{store_type.val}-password")

        if not store_pwd:
            # and not (
            # TODO: handle this once large deployment is implemented
            # self.charm.opensearch_peer_cm.is_consumer(of="main")
            # and cert_type == CertType.APP_ADMIN
            # ):

            self.state.secrets.put_object(
                scope,
                cert_type.val,
                {f"{store_type.val}-password": generate_password()},
                merge=True,
            )

    def _get_subject(self, cert_type: CertType) -> str:
        """Get subject of the certificate."""
        if cert_type == CertType.APP_ADMIN:
            cn = "admin"
        else:
            cn = self.state.host_ip

        return cn

    def _get_sans(self, cert_type: CertType) -> dict[str, list[str]]:
        """Create a list of OID/IP/DNS names for an OpenSearch unit.

        Returns:
            A list representing the hostnames of the OpenSearch unit.
            or None if admin cert_type, because that cert is not tied to a specific host.
        """
        sans = {"sans_oid": ["1.2.3.4.5.5"]}  # required for node discovery
        if cert_type == CertType.APP_ADMIN:
            return sans

        dns = {self.state.unit_name, socket.gethostname(), socket.getfqdn()}
        logger.info(f"This is the current DNS {dns}")
        ips = {self.state.host_ip}

        host_public_ip = self.workload.get_host_public_ip()
        if cert_type == CertType.UNIT_HTTP and host_public_ip:
            ips.add(host_public_ip)

        for ip in ips.copy():
            try:
                name, aliases, addresses = socket.gethostbyaddr(ip)
                logger.info(
                    f"This is the actual return of gethostbyaddr {name, aliases, addresses}"
                )
                ips.update(addresses)

                dns.add(name)
                dns.update(aliases)
            except (socket.herror, socket.gaierror):
                continue

        sans["sans_ip"] = [ip for ip in ips if ip.strip()]
        sans["sans_dns"] = [entry for entry in dns if entry.strip()]

        return sans

    def create_certificate_signing_request(
        self,
        scope: Scope,
        cert_type: CertType,
        key: str | None = None,
        password: str | None = None,
        tls_file: bool = True,
    ) -> bytes:
        """Create CSR and save certificate key and password in secrets."""
        if key is None:
            key = generate_private_key()
        else:
            if tls_file:
                key = parse_tls_file(key)

        if password is not None:
            password = password.encode("utf-8")

        subject = self._get_subject(cert_type)
        organization = self.state.application.deployment_desc.config.cluster_name
        csr = generate_csr(
            add_unique_id_to_subject_name=False,
            private_key=key,
            private_key_password=password,
            subject=subject,
            organization=organization,
            **self._get_sans(cert_type),
        )

        self.state.secrets.put_object(
            scope=scope,
            key=cert_type.val,
            value={
                "key": key.decode("utf-8"),
                "key-password": password,
                "csr": csr.decode("utf-8"),
                "subject": f"/O={organization}/CN={subject}",
            },
            merge=True,
        )
        return csr

    def update_certificate_secret_if_needed(
        self, scope: Scope, cert_type: CertType, ca_chain: str, certificate: str, ca: str
    ):
        """Update the certificate secrets if needed"""
        current_secret_obj = self.state.secrets.get_object(scope, cert_type.val, peek=True) or {}
        secret = {
            "chain": current_secret_obj.get("chain"),
            "cert": current_secret_obj.get("cert"),
            "ca-cert": current_secret_obj.get("ca-cert"),
        }

        if secret != {"chain": ca_chain, "cert": certificate, "ca-cert": ca}:
            # Juju is not able to check if secrets' content changed between revisions
            # this IF is intended to reduce a storm of secret-removed/-changed events
            # for the same content
            self.state.secrets.put_object(
                scope,
                cert_type.val,
                {
                    "chain": ca_chain,
                    "cert": certificate,
                    "ca-cert": ca,
                },
                merge=True,
            )

    def find_secret(
        self, event_data: str, secret_name: str
    ) -> tuple[Scope, CertType, dict[str, str]] | None:
        """Find secret across all scopes (app, unit) and across all cert types.

        Returns:
            scope: scope type of the secret.
            cert type: certificate type of the secret (APP_ADMIN, UNIT_HTTP etc.)
            secret: dictionary of the data stored in this secret
        """

        def is_secret_found(secrets: dict[str, str] | None) -> bool:
            return (
                secrets is not None
                and secrets.get(secret_name, "").rstrip() == event_data.rstrip()
            )

        app_secrets = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        if is_secret_found(app_secrets):
            return Scope.APP, CertType.APP_ADMIN, app_secrets

        u_transport_secrets = self.state.secrets.get_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val, peek=True
        )
        if is_secret_found(u_transport_secrets):
            return Scope.UNIT, CertType.UNIT_TRANSPORT, u_transport_secrets

        u_http_secrets = self.state.secrets.get_object(
            Scope.UNIT, CertType.UNIT_HTTP.val, peek=True
        )
        if is_secret_found(u_http_secrets):
            return Scope.UNIT, CertType.UNIT_HTTP, u_http_secrets

        return None

    def read_ca(self, alias: str, store_pwd: str, store_path: PathProtocol) -> str | None:
        """Load stored CA cert."""
        return (self.list_cas(store_pwd, store_path) or {}).get(alias)

    def list_cas(
        self, store_pwd: str, store_path: PathProtocol
    ) -> dict[str, str] | None:  # noqa: C901
        """List the CAs currently stored in a trust store.

        Args:
            store_pwd: Password for the trust store.
            store_path: Path to the trust store.

        Returns:
            A mapping from base alias to full concatenated PEM chain.
            If an alias is partitioned as <alias>-0, <alias>-1, ... in the store,
            they are reassembled and returned under the base <alias> key.
        """
        if not store_path.exists():
            return None

        cmd = f"openssl pkcs12 -in {store_path}"
        args = f"-passin pass:{store_pwd}"
        try:
            stored_certs = self.workload.run_cmd(cmd, args, use_errors_replace=True).out
        except OpenSearchCmdError as e:
            logger.error("Error reading the current truststore: %s", e)
            return None

        # split by -----END CERTIFICATE-----
        cert_blocks = split_ca_chain(stored_certs)

        start_cert_marker = "-----BEGIN CERTIFICATE-----"
        chains: dict[str, list[tuple[int, str]]] = {}

        for block in cert_blocks:
            # find the friendlyName: line produced by openssl pkcs12
            alias_line = next(
                (line for line in block.split("\n") if line.strip().startswith("friendlyName:")),
                None,
            )
            alias = alias_line.split("friendlyName:", 1)[-1].strip()
            pem = f"{start_cert_marker}{block.split(start_cert_marker, 1)[1]}".strip()

            # parse optional trailing -<int> index
            base = alias
            idx = 0
            parts = alias.rsplit("-", 1)
            if len(parts) == 2 and parts[1].isdigit():
                # Only treat as index if suffix is purely digits
                idx = int(parts[1])
                base = parts[0]

            chains.setdefault(base, []).append((idx, pem))

        # reassemble chains in index order
        out: dict[str, str] = {}
        for base, items in chains.items():
            items.sort(key=lambda t: t[0])
            out[base] = "\n".join(p for _, p in items if p)

        return out

    def read_stored_ca(self, alias: str = CA_ALIAS) -> str | None:
        """Load stored CA cert."""
        secrets = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        ca_trust_store = self.workload.paths.certs / f"{self.CA_ALIAS}.p12"
        logger.debug(f"Reading stored ca from {ca_trust_store}")
        if not (ca_trust_store.exists() and secrets):
            return None

        return self.read_ca(
            alias=alias,
            store_pwd=secrets.get("truststore-password"),
            store_path=ca_trust_store,
        )

    def store_ca(
        self,
        alias: str,
        store_pwd: str,
        store_path: PathProtocol,
        ca: str,
        keep_previous: bool = True,
    ) -> bool:
        """Add new CA cert(s) to a PKCS12 trust store (generic).

        Args:
            alias: Alias to use for the CA certs.
            store_pwd: Password for the trust store.
            store_path: Path to the trust store.
            ca: CA cert(s) to store.
            keep_previous: Whether to keep the previous CA certs in the trust store.

        Returns:
            bool: True if the operation succeeded, False otherwise.
        """
        logger.info("Storing CA cert(s) with alias: %s into truststore.", alias)
        return self._store_ca_chain(
            alias=alias,
            store_pwd=store_pwd,
            store_path=store_path,
            ca=ca,
            keep_previous=keep_previous,
            add_read_perm=True,
        )

    def _store_ca_chain(  # noqa: C901
        self,
        *,
        alias: str,
        store_pwd: str,
        store_path: PathProtocol,
        ca: str,
        keep_previous: bool,
        snap_user_with_write_permission: bool = False,
        add_read_perm: bool = False,
    ) -> bool:
        """Common implementation to store a CA chain into a PKCS12 keystore."""
        tmpdir = store_path.parent
        starter_mode = "0664"
        snap_user = "snap_daemon:root"
        final_mode = "0640"
        # import root first, then intermediates
        certs = list(reversed(split_ca_chain(ca)))
        if snap_user_with_write_permission and store_path.exists():
            try:
                self.workload.run_cmd(f"sudo chmod {starter_mode} {store_path}")
            except OpenSearchCmdError:
                pass

        for i, pem in enumerate(certs):
            internal_alias = f"{alias}-{i}"
            old_internal_alias = f"old-{alias}-{i}"

            # rename existing alias to old-<alias>-<i> if requested
            if keep_previous:
                try:
                    self.workload.run_cmd(
                        f"{self.KEYTOOL} -changealias "
                        f"-alias {internal_alias} -destalias {old_internal_alias} "
                        f"-keystore {store_path} -storetype PKCS12",
                        f"-storepass {store_pwd}",
                    )
                except OpenSearchCmdError as e:
                    msg = (e.out or "") + (e.err or "")
                    if ("does not exist" not in msg) and (
                        "Keystore file does not exist" not in msg
                    ):
                        return False

            # import the cert
            try:
                with self.workload.temp_file(
                    dir=tmpdir.parent,
                    mode="w",
                    encoding="utf-8",
                    errors="replace",
                    delete=True,
                ) as tmp:
                    tmp.write(pem)
                    tmp.flush()
                    tmp_path = tmp.name

                    try:
                        self.workload.run_cmd(
                            f"{self.KEYTOOL} -importcert -noprompt "
                            f"-alias {internal_alias} -keystore {store_path} -file {tmp_path} -storetype PKCS12",
                            f"-storepass {store_pwd}",
                        )
                    except OpenSearchCmdError as e:
                        logger.error(
                            "Failed to import cert for alias %s into %s: %s",
                            internal_alias,
                            store_path,
                            (e.out or "") + (e.err or ""),
                        )
                        return False
            except OSError as e:
                # tmp file creation issues
                logger.error("Failed to create temporary file for CA import: %s", e)
                return False

        # post-actions
        try:
            command = ""
            if snap_user_with_write_permission:
                command = (
                    f"sudo chown {snap_user} {store_path}; sudo chmod {final_mode} {store_path};"
                )
            if add_read_perm:
                command += f"sudo chmod +r {store_path}"
            self.workload.run_cmd(command)
        except OpenSearchCmdError:
            pass

        return True

    def add_ca_to_request_bundle(self, ca_cert: str) -> None:
        """Add the CA cert to the request bundle for the requests module."""
        bundle_path = self.workload.paths.certs / "chain.pem"
        if not bundle_path.exists():
            return

        bundle_content = bundle_path.read_text()
        if ca_cert not in bundle_content:
            bundle_path.write_text(f"{bundle_content}\n{ca_cert}")

    def store_new_tls_resources(self, cert_type: CertType, secrets: dict[str, Any]):
        """Add key and cert to keystore."""
        if not self.state.ca_rotation_complete_in_cluster:
            return

        # if the TLS certificate is available before the keystore-password, create it anyway
        if cert_type == CertType.APP_ADMIN:
            self.create_store_pwd_if_not_exists(Scope.APP, cert_type, StoreType.KEYSTORE)
        else:
            self.create_store_pwd_if_not_exists(Scope.UNIT, cert_type, StoreType.KEYSTORE)

        if not secrets.get("key"):
            logger.error("TLS key not found, quitting.")
            return
        logger.debug(f"Storing {cert_type.val} TLS resources on disk.")
        self.store_key_pair(
            name=cert_type.val,
            store_pwd=secrets.get("keystore-password"),
            store_path=self.workload.paths.certs / f"{cert_type}.p12",
            cert=secrets.get("cert"),
            key=secrets.get("key"),
            key_pwd=secrets.get("key-password"),
        )

    def store_key_pair(
        self,
        name: str,
        store_pwd: str,
        store_path: PathProtocol,
        cert: str,
        key: str,
        key_pwd: str | None,
    ) -> None:
        """Store cert in keystore."""
        store_path.unlink(missing_ok=True)

        with (
            self.workload.temp_file(mode="w+t", suffix=".pem", dir=store_path.parent) as tmp_key,
            self.workload.temp_file(mode="w+t", suffix=".cert", dir=store_path.parent) as tmp_cert,
        ):
            # Write key
            tmp_key.write(key)
            tmp_key.flush()
            tmp_key.seek(0)
            # Write Cert
            tmp_cert.write(cert)
            tmp_cert.flush()
            tmp_cert.seek(0)

            cmd = f"openssl pkcs12 -export -in {tmp_cert.name} -inkey {tmp_key.name} -out {store_path} -name {name}"
            args = f"-passout pass:{store_pwd}"
            if key_pwd:
                args = f"{args} -passin pass:{key_pwd}"

            try:
                self.workload.run_cmd(cmd, args)
                self.workload.run_cmd(f"sudo chmod +r {store_path}")
            except OpenSearchCmdError as e:
                logger.error("Error storing the TLS certificates for %s: %s", name, e)
        logger.info("TLS certificate for %s stored.", name)

    def update_request_ca_bundle(self) -> None:
        """Create a new chain.pem file for requests module"""
        logger.debug("Updating requests TLS CA bundle")
        admin_secret = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)

        # we store the pem format to make it easier for the python requests lib
        self.workload.write_file(
            f"{self.workload.paths.certs}/chain.pem",
            admin_secret["chain"],
        )

    def store_admin_tls_secrets_if_applies(self) -> None:
        """Store admin TLS resources if available and mark unit as configured if correct."""
        # In the case of the first units before TLS is initialized,
        # or non-main orchestrator units having not received the secrets from the main yet
        if not (
            current_secrets := self.state.secrets.get_object(
                Scope.APP, CertType.APP_ADMIN.val, peek=True
            )
        ):
            return

        # in the case the cluster was bootstrapped with multiple units at the same time
        # and the certificates have not been generated yet
        if not current_secrets.get("cert") or not current_secrets.get("chain"):
            return

        # Store the "Admin" certificate, key and CA on the disk of the new unit
        self.store_new_tls_resources(CertType.APP_ADMIN, current_secrets)

        # Mark this unit as tls configured
        if self.is_fully_configured():
            self.state.server.tls_configured = True
            # TODO: Update peer cluster relation
            # self.update_tls_flag_to_peer_cluster_relation("tls_configured", "add")

    def get_cert_issuer(self, cert: str) -> str | None:
        """Retrieve the certificate issuer from a string certificate."""
        # to make sure the content is processed correctly by openssl, temporary store it in a file
        with self.workload.temp_file(mode="w+t", dir=self.workload.root / "/tmp") as tmp_ca_file:
            tmp_ca_file.write(cert)
            tmp_ca_file.flush()
            tmp_ca_file.seek(0)

            try:
                return self.workload.run_cmd(
                    f"openssl x509 -in {tmp_ca_file.name} -noout -issuer"
                ).out
            except OpenSearchCmdError as e:
                logger.error("Error reading the current truststore: %s", e)
                return None

    def get_cert_issuer_from_path(self, store_pwd: str, store_path: PathProtocol) -> str | None:
        """Retrieve the certificate issuer from a string certificate."""
        try:
            return self.workload.run_cmd(
                f"openssl pkcs12 -in {store_path}",
                f"""-nodes \
                -passin pass:{store_pwd} \
                | openssl x509 -noout -issuer
                """,
                use_errors_replace=True,
            ).out
        except OpenSearchCmdError as e:
            logger.error("Error reading the current certificate: %s", e)
            return None

    def reload_tls_certificates(self):
        """Reload transport and HTTP layer communication certificates via REST APIs."""
        # using the SSL API requires authentication with app-admin cert and key
        admin_secret = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        with (
            self.workload.temp_file(mode="w+t", dir=self.workload.paths.conf) as tmp_cert,
            self.workload.temp_file(mode="w+t", dir=self.workload.paths.conf) as tmp_key,
        ):
            tmp_cert.write(admin_secret["cert"])
            tmp_cert.flush()
            tmp_cert.seek(0)

            tmp_key.write(admin_secret["key"])
            tmp_key.flush()
            tmp_key.seek(0)

            self.opensearch_client.reload_tls_certificates(
                cert_files=(tmp_cert.name, tmp_key.name)
            )

    def finalize_ca_certs_rotation(self) -> None:
        """Handle the completion of CA rotation."""
        logger.info("CA rotation completed. Deleting old CA and updating request bundle.")
        self.remove_old_ca()
        self.update_request_ca_bundle()

    def get_unit_certificates(self) -> dict[CertType, str]:
        """Retrieve the list of certificates for this unit."""
        certs = {}

        transport_secrets = self.state.secrets.get_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val, peek=True
        )
        if transport_secrets and transport_secrets.get("cert"):
            certs[CertType.UNIT_TRANSPORT] = transport_secrets["cert"]

        http_secrets = self.state.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP.val, peek=True)
        if http_secrets and http_secrets.get("cert"):
            certs[CertType.UNIT_HTTP] = http_secrets["cert"]

        if self.state.server.is_app_leader:
            admin_secrets = self.state.secrets.get_object(
                Scope.APP, CertType.APP_ADMIN.val, peek=True
            )
            if admin_secrets and admin_secrets.get("cert"):
                certs[CertType.APP_ADMIN] = admin_secrets["cert"]

        return certs

    def check_certs_expiration(self) -> dict[CertType, str] | None:
        """Checks the certificates' expiration. and return those expiring soon."""
        last_cert_check = datetime.strptime(
            self.state.server.certs_exp_checked_at, self.CERTS_EXPIRATION_DATE_FORMAT
        )

        # See if the last check was made less than 6h ago, if yes - leave
        if (datetime.now() - last_cert_check).seconds < 6 * 3600:
            return None

        certs = self.get_unit_certificates()

        # keep certificates that are expiring in less than 24h
        for cert_type in list(certs.keys()):
            hours = cert_expiration_remaining_hours(certs[cert_type])
            if hours > 24 * 7:
                del certs[cert_type]

        return certs

    def remove_old_ca(self) -> None:
        """Remove old CA cert from trust store."""
        secrets = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        trust_store_pwd = secrets.get("truststore-password")
        trust_store_path = self.workload.paths.certs / f"{self.CA_ALIAS}.p12"

        old_ca = self.read_stored_ca(alias=self.OLD_CA_ALIAS)
        self.remove_ca(
            alias=self.OLD_CA_ALIAS,
            store_pwd=trust_store_pwd,
            store_path=trust_store_path,
        )
        # remove it from the request bundle
        self._remove_ca_from_request_bundle(old_ca)

    def remove_ca(self, alias: str, store_pwd: str, store_path: PathProtocol) -> None:
        """Remove old CA cert from the truststore.

        Args:
            alias: Alias to use for the CA certs.
            store_pwd: Password for the trust store.
            store_path: Path to the trust store.
        """
        if not store_path.exists():
            logger.debug("Truststore %s does not exist, nothing to remove.", store_path)
            return

        list_cmd = f"{self.KEYTOOL} -list -keystore {store_path} -alias {alias} -storetype PKCS12"
        list_args = f"-storepass {store_pwd}"
        try:
            self.workload.run_cmd(list_cmd, list_args)
        except OpenSearchCmdError as e:
            if is_alias_missing_error(e, alias):
                logger.debug(
                    "Alias %s not found in %s when listing before delete, ignoring.",
                    alias,
                    store_path,
                )
                return
            # Anything else is a real error
            raise

        del_cmd = f"{self.KEYTOOL} -delete -keystore {store_path} -alias {alias} -storetype PKCS12"
        del_args = f"-storepass {store_pwd}"
        try:
            self.workload.run_cmd(del_cmd, del_args)
        except OpenSearchCmdError as e:
            if is_alias_missing_error(e, alias):
                logger.debug(
                    "Alias %s already gone from %s when deleting, ignoring.",
                    alias,
                    store_path,
                )
                return
            raise

        logger.info("Removed %s from truststore.", alias)

    def _remove_ca_from_request_bundle(self, ca_cert: str) -> None:
        """Remove the CA cert from the request bundle for the requests module."""
        bundle_path = self.workload.paths.certs / "chain.pem"
        if not bundle_path.exists():
            return

        bundle_content = bundle_path.read_text()
        bundle_path.write_text(bundle_content.replace(ca_cert, ""))

    def store_new_ca(self, secrets: dict[str, Any], create_store_pwd: bool) -> bool:  # noqa: C901
        """Add new CA cert to trust store."""
        if create_store_pwd:
            self.create_store_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN, StoreType.KEYSTORE)

        admin_secrets = (
            self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )

        if not ((secrets or {}).get("ca-cert") and admin_secrets.get("truststore-password")):
            logger.error("CA cert  or truststore-password not found, quitting.")
            return False

        if not self.store_ca(
            alias=self.CA_ALIAS,
            store_pwd=admin_secrets.get("truststore-password"),
            store_path=self.workload.paths.certs / f"{self.CA_ALIAS}.p12",
            ca=secrets.get("ca-cert"),
            keep_previous=True,
        ):
            return False

        self.add_ca_to_request_bundle(secrets.get("chain"))

        return True
