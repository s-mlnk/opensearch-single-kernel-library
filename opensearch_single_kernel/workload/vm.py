#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Machine VM Workload."""
import logging
import os
import subprocess
import tempfile
from contextlib import contextmanager
from types import SimpleNamespace

from charmlibs import pathops
from charmlibs.pathops import PathProtocol
from overrides import override
from tenacity import Retrying, retry, stop_after_attempt, wait_exponential, wait_fixed

from opensearch_single_kernel.common.constants import OPENSEARCH_SNAP_REVISION
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchInstallError,
    OpenSearchMissingError,
    OpenSearchStartError,
    OpenSearchStopError,
)
from opensearch_single_kernel.lib.charms.operator_libs_linux.v1.systemd import (
    service_failed,
    service_running,
)
from opensearch_single_kernel.lib.charms.operator_libs_linux.v2 import snap
from opensearch_single_kernel.lib.charms.operator_libs_linux.v2.snap import SnapError
from opensearch_single_kernel.utils.helpers import mask_sensitive_information
from opensearch_single_kernel.workload.base import BaseWorkload, Paths

logger = logging.getLogger(__name__)


class VMWorkload(BaseWorkload):
    """OpenSearch Machine VM Workload."""

    SERVICE_NAME = "daemon"

    def __init__(self):
        super().__init__()
        for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(5)):
            with attempt:
                cache = snap.SnapCache()
                self.opensearch_snap = cache["opensearch"]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    @override
    def install(self) -> None:
        """Install the workload."""
        try:
            cache = snap.SnapCache()
            self.opensearch_snap = cache["opensearch"]
            # Make sure that we have the exact revision
            self.opensearch_snap.ensure(snap.SnapState.Latest, revision=OPENSEARCH_SNAP_REVISION)
            self.opensearch_snap.connect("process-control")
            if not self.opensearch_snap.held:
                # hold the snap in charm determined revision
                self.opensearch_snap.hold()
        except snap.SnapError as e:
            logger.error(f"Failed to install/upgrade opensearch. \n{e}")
            raise OpenSearchInstallError()

    @contextmanager
    def temp_file(
        self,
        mode="w+b",
        data: str | None = None,
        encoding: str | None = None,
        dir: PathProtocol | None = None,
        delete: bool = True,
        *,
        errors: str | None = None,
        suffix: str | None = None,
    ):
        """Create a temporary file and return the file, clean it once context is closed."""
        f = tempfile.NamedTemporaryFile(
            mode=mode, encoding=encoding, dir=dir, delete=False, errors=errors, suffix=suffix
        )
        file_path: PathProtocol = self.root / f.name
        try:
            if data:
                self.write_text(data, file_path)
            yield file_path
        finally:
            if not f.closed:
                f.close()
            if delete:
                try:
                    file_path.unlink()
                except OSError as e:
                    raise e

    @override
    def run_script(self, script_name: str, args: str = None):
        """Run script provided by Opensearch in another directory, relative to OPENSEARCH_HOME.

        Args:
            script_name (str): The name of script file to execute.
            args (str): Arguments passed to the script.
        """
        script_path = f"{self.paths.home}/{script_name}"
        if not os.access(script_path, os.X_OK):
            self.run_cmd(f"chmod a+x {script_path}")

        self.run_cmd(f"snap run --shell opensearch.daemon -- {script_path}", args)

    @override
    def get_host_public_ip(self) -> str | None:
        """Fetches the Public IP address of the current unit."""
        cmd = "unit-get public-address"
        output = self.run_cmd(cmd)
        if output.returncode != 0:
            return None

        return output.out.strip()

    def is_started(self) -> bool:
        """Check if OpenSearch is started."""
        reachable = self.is_reachable(self.host, self.port)
        if not reachable:
            logger.debug("Cannot connect to the OpenSearch server...")

        return reachable

    @override
    def is_service_started(self, paused: bool | None = False) -> bool:
        """Check if the snap service and JVM process are running.

        Set paused=True if the process was intentionally paused.
        """
        if not self.opensearch_snap.present:
            return False

        if not service_running("snap.opensearch.daemon.service"):
            return False

        # Now, we must dig deeper into the actual status of systemd and the JVM process.
        # First, we want to make sure the process is not stopped, dead or zombie.
        try:
            pid = self.run_cmd("lsof", args="-ti:9200").out.rstrip()
            if not pid or not os.path.exists(f"/proc/{pid}/stat"):
                return False
            with open(f"/proc/{pid}/stat") as f:
                stat = f.read()
        except (subprocess.CalledProcessError, OpenSearchCmdError):
            return False

        # From: https://github.com/torvalds/linux/blob/ \
        #     8d8d276ba2fb5f9ac4984f5c10ae60858090babc/fs/proc/array.c#L126-L140
        # Possible states to consider:
        # "R (running)",		/* 0x00 */
        # "S (sleeping)",		/* 0x01 */
        # "D (disk sleep)",	/* 0x02 */
        # "T (stopped)",		/* 0x04 */
        # "t (tracing stop)",	/* 0x08 */
        # "X (dead)",		/* 0x10 */
        # "Z (zombie)",		/* 0x20 */
        # "P (parked)",		/* 0x40 */
        # "I (idle)",		/* 0x80 */
        # "Parked" state is ignored as it applies to threads.
        if stat[2] == "T" and paused:
            return True

        # We do not check reachability of the service
        # If that is needed, then use the `is_started` method.
        return stat[2] not in ["Z", "T", "X"]

    @override
    def start_service_only(self):
        """Start the actual service only (snap / pebble)."""
        if not self.opensearch_snap.present:
            raise OpenSearchMissingError()

        try:
            self.opensearch_snap.start([self.SERVICE_NAME])
        except snap.SnapError as e:
            logger.error(f"Failed to start the opensearch.{self.SERVICE_NAME} service. \n{e}")
            raise OpenSearchStartError()

    @override
    def is_failed(self) -> bool:
        """Check if snap service failed."""
        if not self.opensearch_snap.present:
            raise OpenSearchMissingError()

        return service_failed("snap.opensearch.daemon.service")

    @override
    def start_service(self):
        """Start the snap exposed "daemon" service."""
        if not self.opensearch_snap.present:
            raise OpenSearchMissingError()

        if self.opensearch_snap.services[self.SERVICE_NAME]["active"]:
            logger.info(f"The opensearch.{self.SERVICE_NAME} service is already started.")
            return

        try:
            self.opensearch_snap.start([self.SERVICE_NAME])
        except snap.SnapError as e:
            logger.error(f"Failed to start the opensearch.{self.SERVICE_NAME} service. \n{e}")
            raise OpenSearchStartError()

    @override
    def meminfo(self) -> dict[str, float]:
        """Read the /proc/meminfo file and return the values.

        According to the kernel source code, the values are always in kB:
            https://github.com/torvalds/linux/blob/
                2a130b7e1fcdd83633c4aa70998c314d7c38b476/fs/proc/meminfo.c#L31
        Returns:
            meminfo: The memory info values.
        """
        with open("/proc/meminfo") as f:
            meminfo = f.read().split("\n")
            meminfo = [line.split() for line in meminfo if line.strip()]

        return {line[0][:-1]: float(line[1]) for line in meminfo}

    @override
    def _apply_system_requirement(self, system_requirement: str, value: int) -> bool:
        """Apply a system requirement.

        Args:
            system_requirement (str): Kernel parameter to update.
            value (int): Value of the kernel parameter.

        Returns:
            applied (bool): Whether the kernel value is applied successfully.
        """
        try:
            self.run_cmd(f"sysctl -w {system_requirement}={value}")
            return int(self.run_cmd(f"sysctl -n {system_requirement}").out.rstrip()) == value
        except OpenSearchCmdError:
            return False

    @override
    def _get_kernel_property_value(self, prop: str) -> int:
        """Get the value of a kernel parameter.

        Args:
            prop (str): Kernel property name.

        Returns:
            value (int): Kernel property value.
        """
        return int(self.run_cmd(f"sysctl -n {prop}").out.rstrip())

    @override
    def run_cmd(
        self,
        command: str,
        args: str | None = None,
        use_errors_replace: bool = False,
        stdin: str | None = None,
    ) -> SimpleNamespace:
        """Run command.

        Args:
            command: can contain arguments
            args: command line arguments
            stdin: string input to be passed on the standard input of the subprocess
            use_errors_replace: replace errors with empty string

        Returns the stdout
        """
        command_with_args = command
        if args is not None:
            command_with_args = f"{command} {args}"

        # only log the command and no arguments to avoid logging sensitive information
        command = mask_sensitive_information(command_with_args)
        logger.debug(f"Executing command: {command}")

        run_kwargs = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True,
            encoding="utf-8",
            timeout=25,
            env=os.environ,
        )

        # OpenSSL's "pkcs12 -in" output may contain non-UTF-8 bytes in Bag Attributes
        # (e.g., friendlyName: debian:netlock_arany_=class_gold=_fQtanúsítvány.pem). When Python
        # decodes stdout/stderr as UTF-8, this can raise UnicodeDecodeError.
        #
        # We enable errors="replace" only when explicitly requested (e.g., in list_cas or
        # certificate-issuer parsing), because those commands only need ASCII PEM blocks
        # and not the exact attribute encoding. All other commands (keytool, chmod, x509)
        # should fail if their output is not valid UTF-8.
        if use_errors_replace:
            run_kwargs["errors"] = "replace"
        if stdin:
            run_kwargs["input"] = stdin
        try:
            output = subprocess.run(command_with_args, **run_kwargs)

            logger.debug(f"{command}:\n{output.stdout}")

            if output.returncode != 0:
                logger.debug(f"{command}:\n Stderr: {output.stderr}\n Stdout: {output.stdout}")
                raise OpenSearchCmdError(cmd=command, out=output.stdout, err=output.stderr)
            return SimpleNamespace(
                cmd=command, out=output.stdout, err=output.stderr, returncode=output.returncode
            )
        except (TimeoutError, subprocess.TimeoutExpired):
            raise OpenSearchCmdError(cmd=command)

    @override
    def stop(self) -> None:
        """Stop the opensearch service."""
        if not self.opensearch_snap.present:
            raise OpenSearchMissingError()

        try:
            self.opensearch_snap.stop([self.SERVICE_NAME])
        except SnapError as e:
            logger.error(f"Failed to stop the opensearch.{self.SERVICE_NAME} service. \n{e}")
            raise OpenSearchStopError()

    @property
    @override
    def paths(self) -> Paths:
        """Return Workload's paths"""
        return Paths(self.root)

    @property
    @override
    def root(self) -> PathProtocol:
        """Return the root path."""
        return pathops.LocalPath("/")
