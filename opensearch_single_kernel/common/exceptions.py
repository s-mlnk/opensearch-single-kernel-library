#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm-specific exceptions."""


import json
from typing import Optional


class OpenSearchError(Exception):
    """Base exception class for OpenSearch errors."""


class OpenSearchInstallError(OpenSearchError):
    """Exception thrown when OpenSearch fails to be installed."""


class OpenSearchMissingError(OpenSearchError):
    """Exception thrown when an action is attempted on OpenSearch when it's not installed."""


class OpenSearchStartError(OpenSearchError):
    """Exception thrown when OpenSearch fails to start."""


class OpenSearchStartTimeoutError(OpenSearchStartError):
    """Exception thrown when OpenSearch takes too long to start."""


class OpenSearchSecretError(OpenSearchError):
    """Parent exception for secrets related issues within OpenSearch."""


class OpenSearchSecretInsertionError(OpenSearchSecretError):
    """Exception thrown when a secret couldn't be updated / added."""


class OpenSearchHttpError(OpenSearchError):
    """Exception thrown when an OpenSearch REST call fails."""

    def __init__(self, response_text: Optional[str] = None, response_code: Optional[int] = None):
        self.response_text = response_text
        try:
            self.response_body = json.loads(response_text)
        except (json.JSONDecodeError, TypeError):
            self.response_body = {}
        self.response_code = response_code
        if self.response_body:
            message = f"HTTP error {self.response_code=}\n{self.response_body=}"
        else:
            message = f"HTTP error {self.response_code=}\n{self.response_text=}"
        super().__init__(message)


class OpenSearchHAError(OpenSearchError):
    """Exception thrown when the HA of the OpenSearch charm is violated."""


class OpenSearchNotFullyReadyError(OpenSearchError):
    """Exception thrown when a node is started but not full ready to take on requests."""


class OpenSearchUserMgmtError(OpenSearchError):
    """Base exception class for OpenSearch user management errors."""


class OpenSearchCmdError(OpenSearchError):
    """Exception thrown when an OpenSearch bin command fails."""

    def __init__(self, cmd: str, out: Optional[str] = None, err: Optional[str] = None):
        self.cmd = cmd
        self.out = out
        self.err = err
        super().__init__(f"Command failed: {cmd}\nstdout={out}\nstderr={err}")


class OpenSearchStopError(OpenSearchError):
    """Exception thrown when OpenSearch fails to stop."""


class OpenSearchProvidedRolesException(OpenSearchError):
    """Exception class for events when the user provided node roles will violate quorum."""


class OpenSearchExclusionsException(OpenSearchError):
    """Exception class for all Voting/Allocation exclusions related exceptions."""


class OpenSearchFileOperationError(OpenSearchError):
    """Exception thrown when file operations related to OpenSearch fail."""
