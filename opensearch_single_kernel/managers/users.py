#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Configuration manager."""
import logging
from typing import Any

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    COS_ROLE,
    COS_USER,
    KIBANA_SERVER_USER,
    OPENSEARCH_SYSTEM_USERS,
    OPENSEARCH_USERS,
    Scope,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.helpers import generate_hashed_password
from opensearch_single_kernel.workload.base import BaseWorkload

USER_ENDPOINT = "/_plugins/_security/api/internalusers"
ROLE_ENDPOINT = "/_plugins/_security/api/roles"
ROLESMAPPING_ENDPOINT = "/_plugins/_security/api/rolesmapping"

logger = logging.getLogger(__name__)


class UsersManager(BaseManager):
    """OpenSearch Users Manager.

    This manager handles everything related to configuring users in OpenSearch.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "users_manager"
        self.yaml_setter = YamlConfigSetter(self.workload.paths.conf)

    def put_or_update_internal_user_leader(
        self,
        user: str,
        pwd: str | None = None,
        update: bool = True,
    ) -> None:
        """Create system user or update it with a new password."""
        # Leader is to set new password and hash, others populate existing hash locally
        secret = self.state.secrets.get(Scope.APP, self.state.secrets.password_key(user))
        if secret and not update:
            self._put_or_update_internal_user_unit(user)
            return

        hashed_pwd, pwd = generate_hashed_password(pwd)

        # Updating security index
        # We need to do this for all credential changes
        if secret and update:
            self.update_user_password(user, hashed_pwd)

        # In case it's a new user, OR it's a system user (that has an entry in internal_users.yml)
        # we either need to initialize or update (local) credentials as well
        if not secret or user in OPENSEARCH_SYSTEM_USERS:
            self.put_internal_user(user, hashed_pwd)

        # Secrets need to be maintained
        # For System Users we also save the hash key
        # so all units can fetch it for local users (internal_users.yml) updates.
        self.state.secrets.put(Scope.APP, self.state.secrets.password_key(user), pwd)

        if user in OPENSEARCH_SYSTEM_USERS:
            self.state.secrets.put(Scope.APP, self.state.secrets.hash_key(user), hashed_pwd)

        if user == ADMIN_USER:
            self.state.application.update({"admin_user_initialized": "True"})

    def _put_or_update_internal_user_unit(self, user: str) -> None:
        """Create system user or update it with a new password."""
        # Leader is to set new password and hash, others populate existing hash locally
        hashed_pwd = self.state.secrets.get(Scope.APP, self.state.secrets.hash_key(user))

        # System users have to be saved locally in internal_users.yml
        if user in OPENSEARCH_SYSTEM_USERS:
            self.put_internal_user(user, hashed_pwd)

    def purge_initial_default_users(self):
        """Removes all users from internal_users yaml config.

        This is to be used when starting up the charm, to remove unnecessary default users.
        """
        try:
            internal_users = self.yaml_setter.load("opensearch-security/internal_users.yml").keys()
        except FileNotFoundError:
            # internal_users.yml hasn't been initialised yet, so skip purging for now.
            return

        for user in internal_users:
            if user != "_meta":
                self.yaml_setter.delete("opensearch-security/internal_users.yml", user)

    def save_user_locally(self, user: str):
        """Save the user in internal_users.yaml"""
        user_hash = self.state.secrets.hash_key(user)
        hashed_pwd = self.state.secrets.get(Scope.APP, user_hash)
        # System users have to be saved locally in internal_users.yml
        self.put_internal_user(user, hashed_pwd)

    def get_roles(self) -> dict[str, Any]:
        """Gets list of roles.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        try:
            return self.opensearch_client.request("GET", f"{ROLE_ENDPOINT}/")
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

    def create_role(
        self,
        role_name: str,
        permissions: dict[str, str] | None = None,
        action_groups: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Creates a role with the given permissions.

        This method assumes the dicts provided are valid opensearch config. If not, raises
        OpenSearchUserMgmtError.

        Args:
            role_name: name of the role
            permissions: A valid dict of existing opensearch permissions.
            action_groups: A valid dict of existing opensearch action groups.

        Raises:
            OpenSearchUserMgmtError: If the role creation request fails.

        Returns:
            HTTP response to opensearch API request.
        """
        try:
            resp = self.opensearch_client.request(
                "PUT",
                f"{ROLE_ENDPOINT}/{role_name}",
                payload={**(permissions or {}), **(action_groups or {})},
            )
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            logger.error(f"Couldn't create role: {resp}")
            raise OpenSearchUserMgmtError(f"creating role {role_name} failed")

        return resp

    def remove_role(self, role_name: str) -> dict[str, Any]:
        """Remove the given role from opensearch distribution.

        Args:
            role_name: name of the role to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if role_name is empty

        Returns:
            HTTP response to opensearch API request.
        """
        if not role_name:
            raise OpenSearchUserMgmtError(
                "role name empty - sending a DELETE request to endpoint root isn't permitted"
            )

        try:
            resp = self.opensearch_client.request("DELETE", f"{ROLE_ENDPOINT}/{role_name}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                return {
                    "status": "OK",
                    "response": "role does not exist, and therefore has not been removed",
                }
            else:
                raise OpenSearchUserMgmtError(e)

        logger.debug(resp)
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing role {role_name} failed")

        return resp

    def get_users(self) -> dict[str, Any]:
        """Gets list of users.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        try:
            return self.opensearch_client.request("GET", f"{USER_ENDPOINT}/")
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

    def create_user(
        self, user_name: str, roles: list[str] | None, hashed_pwd: str
    ) -> dict[str, Any]:
        """Create or update user and assign the requested roles to the user.

        Args:
            user_name: name of the user to be created.
            roles: list of roles to be applied to the user. These must already exist.
            hashed_pwd: the hashed password for the user.

        Raises:
            OpenSearchUserMgmtError: If the request fails.

        Returns:
            HTTP response to opensearch API request.
        """
        payload = {"hash": hashed_pwd}
        if roles:
            payload["opendistro_security_roles"] = roles

        try:
            resp = self.opensearch_client.request(
                "PUT",
                f"{USER_ENDPOINT}/{user_name}",
                payload=payload,
            )
        except OpenSearchHttpError as e:
            logger.error(f"Couldn't create user {str(e)}")
            raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            raise OpenSearchUserMgmtError(f"creating user {user_name} failed")

        return resp

    def remove_user(self, user_name: str) -> dict[str, Any]:
        """Remove the given user from opensearch distribution.

        Args:
            user_name: name of the user to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if user_name is empty

        Returns:
            HTTP response to opensearch API request.
        """
        if not user_name:
            raise OpenSearchUserMgmtError(
                "user name empty - sending a DELETE request to endpoint root isn't permitted"
            )

        try:
            resp = self.opensearch_client.request("DELETE", f"{USER_ENDPOINT}/{user_name}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                return {
                    "status": "OK",
                    "response": "user does not exist, and therefore has not been removed",
                }
            else:
                raise OpenSearchUserMgmtError(e)

        logger.debug(resp)
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing user {user_name} failed")
        return resp

    def patch_user(self, user_name: str, patches: list[dict[str, Any]]) -> dict[str, Any]:
        """Applies patches to user.

        Args:
            user_name: name of the user to be created.
            patches: a list of patches to be applied to the user in question.

        Raises:
            OpenSearchUserMgmtError: If the request fails.

        Returns:
            HTTP response to opensearch API request.
        """
        try:
            resp = self.opensearch_client.request(
                "PATCH",
                f"{USER_ENDPOINT}/{user_name}",
                payload=patches,
            )
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"patching user {user_name} failed")

        return resp

    def create_role_mapping(self, role: str, mapped_users: list[str]) -> None:
        """Creates or replaces role mapping for selected role with all of its users mapped to it.

        Args:
            role: name of the role for users being mapped to.
            mapped_users: all the users, that should be mapped to the specified role.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        try:
            resp = self.opensearch_client.request(
                "PUT",
                f"{ROLESMAPPING_ENDPOINT}/{role}",
                payload={"users": mapped_users, "backend_roles": [role]},
            )
        except OpenSearchHttpError as e:
            logger.error(f"Couldn't create role mapping {str(e)}")
            raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            raise OpenSearchUserMgmtError(f"creating role mapping {role} failed")

    def remove_role_mapping(self, role: str) -> None:
        """Remove the given role mapping if it exists.

        Args:
            role: name of the role mapping to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if role is empty
        """
        if not role:
            raise OpenSearchUserMgmtError(
                "role name empty - sending a DELETE request to endpoint root isn't permitted"
            )

        try:
            resp = self.opensearch_client.request("DELETE", f"{ROLESMAPPING_ENDPOINT}/{role}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                resp = {
                    "status": "OK",
                    "response": "role mapping does not exist, and therefore has not been removed",
                }
            else:
                raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing role mapping {role} failed")

    def update_user_password(self, username: str, hashed_pwd: str):
        """Change user hashed password."""
        resp = self.opensearch_client.request(
            "PATCH",
            f"/_plugins/_security/api/internalusers/{username}",
            [{"op": "replace", "path": "/hash", "value": hashed_pwd}],
        )
        if resp.get("status") != "OK":
            raise OpenSearchError(f"{resp}")

    def put_internal_user(self, user: str, hashed_pwd: str):
        """User creation for specific system users."""
        if user not in OPENSEARCH_USERS:
            raise OpenSearchError(f"User {user} is not an internal user.")
        logger.debug(f"Creating internal user {user}, with {hashed_pwd}")

        if user == ADMIN_USER:
            # reserved: False, prevents this resource from being update-protected from:
            # updates made on the dashboard or the rest api.
            # we grant the admin user all opensearch access + security_rest_api_access
            logger.debug("putting admin to internal_users.yml")
            self.yaml_setter.put(
                "opensearch-security/internal_users.yml",
                "admin",
                {
                    "hash": hashed_pwd,
                    "reserved": False,
                    "backend_roles": [ADMIN_USER],
                    "opendistro_security_roles": [
                        "security_rest_api_access",
                        "all_access",
                    ],
                    "description": "Admin user",
                },
            )
        elif user == KIBANA_SERVER_USER:
            self.yaml_setter.put(
                "opensearch-security/internal_users.yml",
                f"{KIBANA_SERVER_USER}",
                {
                    "hash": hashed_pwd,
                    "reserved": False,
                    "description": "Kibanaserver user",
                },
            )
        elif user == COS_USER:
            roles = [COS_ROLE]
            self.create_user(COS_USER, roles, hashed_pwd)
            self.patch_user(
                COS_USER,
                [{"op": "replace", "path": "/opendistro_security_roles", "value": roles}],
            )
