#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Charm literals."""


from opensearch_single_kernel.utils.enum import BaseStrEnum


class Substrates(BaseStrEnum):
    """Possible substrates."""

    K8S = "k8s"
    VM = "vm"


class Scope(BaseStrEnum):
    """Peer relations scope."""

    APP = "app"
    UNIT = "unit"


class HealthColors(BaseStrEnum):
    """Colors the clusters or a unit may have depending on their health."""

    GREEN = "green"
    YELLOW = "yellow"
    YELLOW_TEMP = "yellow-temp"
    RED = "red"
    UNKNOWN = "unknown"
    IGNORE = "ignore"


class Directive(BaseStrEnum):
    """Directive indicating what the pending actions for the current deployments are."""

    NONE = "none"
    SHOW_STATUS = "show-status"
    WAIT_FOR_PEER_CLUSTER_RELATION = "wait-for-peer-cluster-relation"
    INHERIT_CLUSTER_NAME = "inherit-name"
    VALIDATE_CLUSTER_NAME = "validate-cluster-name"
    RECONFIGURE = "reconfigure-cluster"


class StartMode(BaseStrEnum):
    """Mode of start of units in this deployment."""

    WITH_PROVIDED_ROLES = "start-with-provided-roles"
    WITH_GENERATED_ROLES = "start-with-generated-roles"


class PerformanceType(BaseStrEnum):
    """Performance types available."""

    PRODUCTION = "production"
    TESTING = "testing"


class DeploymentType(BaseStrEnum):
    """Nature of a sub cluster deployment."""

    MAIN_ORCHESTRATOR = "main-orchestrator"
    FAILOVER_ORCHESTRATOR = "failover-orchestrator"
    OTHER = "other"


class State(BaseStrEnum):
    """State of a deployment, directly mapping to the juju statuses."""

    ACTIVE = "active"
    BLOCKED_WAITING_FOR_RELATION = "blocked-waiting-for-peer-cluster-relation"
    BLOCKED_WRONG_RELATED_CLUSTER = "blocked-wrong-related-cluster"
    BLOCKED_CANNOT_START_WITH_ROLES = "blocked-cannot-start-with-current-set-roles"
    BLOCKED_CANNOT_APPLY_NEW_ROLES = "blocked-cannot-apply-new-roles"


# TLS
class CertType(BaseStrEnum):
    """Certificate types."""

    APP_ADMIN = "app-admin"  # admin / management of cluster
    # APP_CLIENT_HTTP = "app-client-http"  # external http clients (rest layer)
    UNIT_TRANSPORT = "unit-transport"  # internal node to node communication (transport layer)
    UNIT_HTTP = "unit-http"  # http for nodes (rest layer) - units act as servers


class StoreType(BaseStrEnum):
    """Type of certificates and keys store."""

    KEYSTORE = "keystore"
    TRUSTSTORE = "truststore"


class TlsFileExt(BaseStrEnum):
    """Extensions of TLS generated files."""

    CA = ".ca"
    CERT = ".cert"
    CHAIN = ".chain"
    CSR = ".csr"
    KEY = ".key"
    KEYPASS = ".key-password"


class OpenSearchPaths(BaseStrEnum):
    """Base Paths for OpenSearch Snap."""

    HOME = "usr/share/opensearch"
    CONF = "etc/opensearch"
    DATA = "var/lib/opensearch"
    LOGS = "var/log/opensearch"
    JDK = "usr/lib/jvm/java-21-openjdk-amd64"
    TMP = "usr/share/tmp"
    BIN = "usr/share/opensearch/bin"


# Profiles
_1GB_IN_KB = 1024 * 1024  # 1GB in KB
MAX_HEAP_SIZE_IN_KB = 31 * _1GB_IN_KB  # 31GB in KB
PERFORMANCE_PROFILE = "profile"
# Opensearch Snap revision
OPENSEARCH_SNAP_REVISION = "98"  # Keep in sync with `workload_version` file

# OpenSearch Users and roles
OPENSEARCH_SYSTEM_USERS = {"admin", "kibanaserver"}
OPENSEARCH_USERS = OPENSEARCH_SYSTEM_USERS | {"monitor"}
KIBANA_SERVER_USER = "kibanaserver"
ADMIN_USER = "admin"
COS_USER = "monitor"
COS_ROLE = "readall_and_monitor"

GENERATED_ROLES = ["data", "ingest", "ml", "cluster_manager"]


# OpenSearch default port
OPENSEARCH_HTTP_PORT = 9200

# OpenSearch storage name
OPENSEARCH_STORAGE_NAME = "opensearch-data"


# Relations
PEER_RELATION = "opensearch-peers"
TLS_RELATION = "certificates"
NODE_LOCK_RELATION = "node-lock-fallback"
PEER_CLUSTER_ORCHESTRATOR_RELATION = "peer-cluster-orchestrator"
PEER_CLUSTER_RELATION = "peer-cluster"


# Paths
BASE_SNAP_DIR = "/var/snap/opensearch"
SNAP_DATA = "current"
SNAP_COMMON = "common"
SNAP = "/snap/opensearch/current"


# Secrets
PW_POSTFIX = "password"
HASH_POSTFIX = f"{PW_POSTFIX}-hash"
ADMIN_PW = f"admin-{PW_POSTFIX}"
ADMIN_PW_HASH = f"{ADMIN_PW}-hash"
S3_CREDENTIALS = "s3-creds"
S3_PEER_SECRET_KEYS = [
    "secret-key",
    "access-key",
    "s3-secret-key",
    "s3-access-key",
    S3_CREDENTIALS,
]
AZURE_CREDENTIALS = "azure-creds"
AZURE_PEER_SECRET_KEYS = [
    "azure-storage-account",
    "azure-secret-key",
    "secret-key",
    "storage-account",
    AZURE_CREDENTIALS,
]
GCS_CREDENTIALS = "gcs-creds"


# Messages
PEER_CLUSTER_NO_RELATION = "Cannot start. Waiting for peer cluster relation..."
PEER_CLUSTER_WRONG_RELATION = "Cluster name doesn't match with related cluster. Remove relation."
CLUSTER_MANAGER_VOTING_ROLES_PROVIDED_INVALID = (
    "cluster_manager and voting_only roles cannot be both set on the same nodes."
)
CLUSTER_MANAGER_ROLE_REMOVAL_FORBIDDEN = (
    "Removal of cluster_manager role from deployment not allowed."
)
DATA_ROLE_REMOVAL_FORBIDDEN = (
    "Removal of data role from current deployment not allowed - the data cannot be reallocated."
)
