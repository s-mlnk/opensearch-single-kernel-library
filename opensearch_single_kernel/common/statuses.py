# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Statuses for the OpenSearch Charm.

This module defines various status enums that represent the state of the charm.
"""
from enum import Enum

from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus


class CharmStatuses(Enum):
    """Collection of possible statuses for the charm."""

    ACTIVE_IDLE = ActiveStatus("")
    INSTALL_IN_PROGRESS = MaintenanceStatus("Installing OpenSearch...")
    INSTALL_ERROR = BlockedStatus("Could not install OpenSearch.")

    # TLS Status
    TLS_RELATION_MISSING = BlockedStatus("Missing TLS relation with this cluster.")
    TLS_NOT_FULLY_CONFIGURED = MaintenanceStatus("Waiting for TLS to be fully configured...")
    TLS_CA_ROTATION = MaintenanceStatus("Applying new CA certificate...")
    TLS_RELATION_BROKEN = BlockedStatus(
        "Relation broken with the TLS Operator while TLS not fully configured. Stopping OpenSearch."
    )
    TLS_CERTS_EXPIRATION_ERROR = BlockedStatus(
        "The certificates: {certificates} need to be refreshed."
    )
    TLS_NEW_CERTS_REQUESTED = MaintenanceStatus("Requesting new TLS certificates...")

    # Profiles
    INVALID_PROFILE_CONFIG_OPTION = BlockedStatus(
        "Invalid profile configuration option. Only `production` and `testing` values are allowed."
    )

    # Configuration Status
    ADMIN_USER_INIT_IN_PROGRESS = MaintenanceStatus("Configuring admin user...")
    ADMIN_USER_NOT_CONFIGURED = MaintenanceStatus(
        "Waiting for the admin user to be fully configured..."
    )
    MISSING_PROFILE_REQUIREMENTS = BlockedStatus("Missing requirements: {requirements}")

    # Health Status
    CLUSTER_HEALTH_RED = BlockedStatus(
        "1 or more 'primary' shards are not assigned, please scale your application up."
    )
    CLUSTER_HEALTH_UNKNOWN = BlockedStatus(
        "No unit online, cannot determine if it's safe to scale-down."
    )
    CLUSTER_HEALTH_YELLOW = BlockedStatus(
        "1 or more 'replica' shards are not assigned, please scale your application up."
    )
    WAITING_FOR_BUSY_SHARDS = MaintenanceStatus("Some shards are still initializing / relocating.")
    WAITING_FOR_SPECIFIC_BUSY_SHARDS = WaitingStatus(
        "The shards {shards} need to complete building"
    )

    # Lock Status
    REQUEST_LOCK_ON_START = WaitingStatus("Requesting lock on operation: start")

    # Security Index
    SECURITY_INDEX_INIT_IN_PROGRESS = MaintenanceStatus("Initializing the security index...")

    # Start
    SERVICE_START_ERROR = BlockedStatus(
        "An error occurred during the start of the OpenSearch service."
    )
    WAITING_TO_START = WaitingStatus("Waiting for OpenSearch to start...")

    # Stop
    SERVICE_IS_STOPPING = WaitingStatus("The OpenSearch service is stopping.")
    SERVICE_STOPPED = WaitingStatus("The OpenSearch service stopped.")

    # Peer Cluster
    PEER_CLUSTER_NO_DATA_NODE = BlockedStatus(
        "Cannot run cluster with current roles. Waiting for data node..."
    )
    PEER_CLUSTER_NO_RELATION = BlockedStatus("Cannot start. Waiting for peer cluster relation...")
    PEER_CLUSTER_WRONG_RELATION = BlockedStatus(
        "Cluster name don't match with related cluster. Remove relation."
    )
    PEER_CLUSTER_WRONG_ROLES_PROVIDED = BlockedStatus(
        "Cannot start cluster with current set of roles."
    )
    CM_ROLE_REMOVAL_FORBIDDEN = BlockedStatus(
        "Removal of cluster_manager role from deployment not allowed."
    )
    CM_VO_PROVIDED_INVALID = BlockedStatus(
        "cluster_manager and voting_only roles cannot be both set on the same nodes."
    )
    DATA_ROLE_REMOVAL_FORBIDDEN = BlockedStatus(
        "Removal of data role from current deployment not allowed - the data cannot be reallocated."
    )
