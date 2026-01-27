#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base interface for common workload operations."""
import logging
import socket
from abc import ABC, abstractmethod
from contextlib import contextmanager
from types import SimpleNamespace
from typing import List, Optional

from charmlibs.pathops import PathProtocol

from opensearch_single_kernel.common.constants import (
    BASE_SNAP_DIR,
    SNAP,
    SNAP_COMMON,
    SNAP_DATA,
    OpenSearchPaths,
)

logger = logging.getLogger(__name__)


class Paths:
    """This class represents the group of Paths that need to be exposed.

    Args:
            home: Home path of Opensearch, equivalent to the env variable ${OPENSEARCH_HOME}
            conf: Path to the config folder of opensearch
            data: Path to the data folder of opensearch
            logs: Path to the logs folder of opensearch
            jdk: Path of the jdk that comes bundled with the opensearch distro
            tmp: JNA temporary directory
            bin: Path to the bin/ folder
    """

    def __init__(self, root: PathProtocol):
        super().__init__()
        self.root = root

    @property
    def base_snap_dir(self) -> PathProtocol:
        """Return path to the Base snap directory."""
        return self.root / BASE_SNAP_DIR

    @property
    def snap_data(self) -> PathProtocol:
        """Return path to the snap data directory."""
        return self.base_snap_dir / SNAP_DATA

    @property
    def snap_common(self) -> PathProtocol:
        """Return path to the snap common directory."""
        return self.base_snap_dir / SNAP_COMMON

    @property
    def snap(self) -> PathProtocol:
        """Return path to the snap directory."""
        return self.root / SNAP

    @property
    def home(self) -> PathProtocol:
        """Return path to the home snap directory."""
        return self.snap_data / OpenSearchPaths.HOME.val

    @property
    def conf(self) -> PathProtocol:
        """Return path to the conf snap directory."""
        return self.snap_data / OpenSearchPaths.CONF.val

    @property
    def data(self) -> PathProtocol:
        """Return path to the data snap directory."""
        return self.snap_common / OpenSearchPaths.DATA.val

    @property
    def logs(self) -> PathProtocol:
        """Return path to the logs snap directory."""
        return self.snap_common / OpenSearchPaths.LOGS.val

    @property
    def jdk(self) -> PathProtocol:
        """Return path to the jdk directory."""
        return self.snap / OpenSearchPaths.JDK.val

    @property
    def tmp(self) -> PathProtocol:
        """Return path to the tmp directory."""
        return self.snap_common / OpenSearchPaths.TMP.val

    @property
    def bin(self) -> PathProtocol:
        """Return path to the bin directory."""
        return self.snap / OpenSearchPaths.BIN.val

    @property
    def plugins(self) -> PathProtocol:
        """Returns Plugins Path"""
        return self.home / "plugins"

    @property
    def certs(self) -> PathProtocol:
        """Returns Certificates Path"""
        return self.conf / "certificates"

    @property
    def certs_relative(self) -> str:
        """Returns Certificates relative Path"""
        return "certificates"

    @property
    def seed_hosts(self) -> PathProtocol:
        """Returns Seed hosts"""
        return self.conf / "unicast_hosts.txt"


# --- Base Workload
class BaseWorkload(ABC):
    """Base interface for common workload operations."""

    @property
    @abstractmethod
    def root(self) -> PathProtocol:
        """Return the root path."""
        pass

    @abstractmethod
    def install(self) -> None:
        """Install the workload."""
        pass

    @property
    @abstractmethod
    def paths(self) -> Paths:
        """Return the Workload's paths"""
        pass

    def write_file(self, path_str: str, data: str, override: bool = True):
        """Persists data into file. Useful for files generated on the fly, such as certs etc."""
        if not override and self.exists(path_str):
            return
        path = self.root / path_str

        parent_dir_path = path.parent
        if parent_dir_path:
            parent_dir_path.mkdir(parents=True, exist_ok=True)

        path.write_text(data)

    @contextmanager
    def temp_file(
        self,
        mode: str = "w+b",
        encoding=None,
        dir: PathProtocol | None = None,
        delete=True,
        *,
        errors=None,
        suffix=None,
    ):
        """Context manager for creating temporary files."""
        pass

    def exists(self, path_str: str) -> bool:
        """Return whether the path exists in filesystem."""
        path = self.root / path_str
        return path.exists()

    @abstractmethod
    def remove_file(self, file_path: str):
        """Remove file from the filesystem."""
        pass

    @abstractmethod
    def is_service_started(self, paused: Optional[bool] = False) -> bool:
        """Check if the snap service and JVM process are running.

        Set paused=True if the process was intentionally paused.
        """
        pass

    @abstractmethod
    def get_host_public_ip(self) -> Optional[str]:
        """Fetches the Public IP address of the current unit."""
        pass

    @abstractmethod
    def start_service_only(self):
        """Start the actual service only (snap / pebble)."""
        pass

    def is_reachable(self, host: str, port: int) -> bool:
        """Attempting a socket connection to a host/port."""
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except OSError as e:
            logger.debug(f"Connection to {host}:{port} fails with: {e}")
            return False

    @abstractmethod
    def run_script(self, script_name: str, args: str = None):
        """Run script provided by Opensearch in another directory, relative to OPENSEARCH_HOME."""
        pass

    @abstractmethod
    def run_cmd(
        self, command: str, args: str = None, use_errors_replace: bool = False, stdin: str = None
    ) -> SimpleNamespace:
        """Run Command in CLI"""
        pass

    @abstractmethod
    def meminfo(self) -> dict[str, float]:
        """Read the /proc/meminfo file and return the values."""
        pass

    @abstractmethod
    def is_failed(self) -> bool:
        """Check if snap service failed."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop the opensearch service."""
        pass

    @abstractmethod
    def start_service(self):
        """Start the opensearch service."""
        pass

    @abstractmethod
    def _apply_system_requirement(self, system_requirement: str, value: int) -> bool:
        """Apply a system requirement."""
        pass

    @abstractmethod
    def _get_kernel_property_value(self, prop: str) -> int:
        """Get the value of a kernel parameter."""
        pass

    def check_missing_system_requirements(self) -> List[str]:
        """Checks the system requirements."""
        missing_requirements = []

        prop, val = "vm.max_map_count", 262144
        if self._get_kernel_property_value(prop) < val and not self._apply_system_requirement(
            prop, val
        ):
            missing_requirements.append(f"{prop} should be at least {val}")

        prop, val = "vm.swappiness", 0
        if self._get_kernel_property_value(prop) > val and not self._apply_system_requirement(
            prop, 0
        ):
            missing_requirements.append(f"{prop} should be at most {val}")

        prop, val = "net.ipv4.tcp_retries2", 5
        if self._get_kernel_property_value(prop) > val and not self._apply_system_requirement(
            prop, val
        ):
            missing_requirements.append(f"{prop} should be at most {val}")

        if missing_requirements:
            logger.error("Missing system requirements: %s", missing_requirements)
        return missing_requirements
