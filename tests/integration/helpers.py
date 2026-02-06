#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import random
import shlex
import socket
import subprocess
import tempfile
from datetime import datetime, timedelta
from hashlib import md5
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

import requests
import yaml
from opensearchpy import OpenSearch
from pytest_operator.plugin import OpsTest
from tenacity import (
    RetryError,
    Retrying,
    retry,
    stop_after_attempt,
    stop_after_delay,
    wait_fixed,
    wait_random,
)

from .conftest import APP_NAME
from .models import Status, Unit

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)s", datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)


def get_raw_application(ops_test: OpsTest, app: str) -> Dict[str, Any]:
    """Get raw application details."""
    return json.loads(
        subprocess.check_output(
            f"juju status --model {ops_test.model.info.name} {app} --format=json".split()
        )
    )["applications"][app]


def now() -> str:
    """Print date."""
    return datetime.now().strftime("%H:%M:%S")


def _dump_juju_logs(model: str, unit: Optional[str] = None, lines: int = 500) -> None:
    """Dump juju logs on the console."""
    target_file = f"/tmp/{uuid4().hex}.txt"

    cmd = "juju debug-log"
    if unit:
        pos = unit.rfind("-")
        if pos != -1:
            unit = f"{unit[:pos]}/{unit[pos + 1 :]}"  # noqa
        cmd = f"{cmd} --include={unit}"

    cmd = f"{cmd} --model={model} --limit {lines} > {target_file}; cat {target_file}"
    logger.error(f"Dumping juju logs for {unit if unit else 'all'}:")
    logger.error(subprocess.check_output(cmd, shell=True).decode("utf-8"))
    logger.error("\n\n")


def _progress_line(units: List[Unit]) -> str:
    """Log progress line."""
    log = ""
    for u in units:
        if not log:
            log = (
                f"\n\tapp: {u.short_name.split('-')[0]} {u.app_status.value} -- "
                f"message: {u.app_status.message}\n"
            )

        log = (
            f"{log}\t\t{u.name}{'*' if u.is_leader else ' '} -- ({u.ip}) -- [{u.agent_status.value} "
            f"(since: {u.agent_status.since.strftime('%H:%M:%S')})] "
            f"{u.workload_status.value}: {u.workload_status.message or ''}\n"
        )

    return log


async def get_unit_hostname(ops_test: OpsTest, unit_id: int, app: str) -> str:
    """Get the hostname of a specific unit."""
    _, hostname, _ = await ops_test.juju("ssh", f"{app}/{unit_id}", "hostname")
    return hostname.strip()


async def _get_unit(
    ops_test: OpsTest,
    app: str,
    raw_app: dict[str, Any],
    unit_name: str,
    raw_unit: dict[str, Any],
    subordinate: bool = False,
) -> Unit:
    """Create a Unit object from raw unit data."""
    unit_id = int(unit_name.split("/")[-1])

    app_id = f"{ops_test.model.uuid}/{app}"
    app_short_id = md5(app_id.encode()).hexdigest()[:3]
    machine_id = -1 if subordinate else int(raw_unit["machine"])

    return Unit(
        id=unit_id,
        short_name=unit_name.replace("/", "-"),
        name=f"{unit_name.replace('/', '-')}.{app_short_id}",
        ip=raw_unit["public-address"],
        hostname=await get_unit_hostname(ops_test, unit_id, app),
        is_leader=raw_unit.get("leader", False),
        machine_id=machine_id,
        workload_status=Status(
            value=raw_unit["workload-status"]["current"],
            since=raw_unit["workload-status"]["since"],
            message=raw_unit["workload-status"].get("message"),
        ),
        agent_status=Status(
            value=raw_unit["juju-status"]["current"],
            since=raw_unit["juju-status"]["since"],
        ),
        app_status=Status(
            value=raw_app["application-status"]["current"],
            since=raw_app["application-status"]["since"],
            message=raw_app["application-status"].get("message"),
        ),
    )


async def get_application_units(ops_test: OpsTest, app: str) -> List[Unit]:
    """Get fully detailed units of an application."""
    # Juju incorrectly reports the IP addresses after the network is restored this is reported as a
    # bug here: https://github.com/juju/python-libjuju/issues/738. Once this bug is resolved use of
    # `get_unit_ip` should be replaced with `.public_address`
    raw_app = get_raw_application(ops_test, app)
    units = []
    for u_name, raw_unit in raw_app["units"].items():
        if not raw_unit.get("public-address"):
            # unit not ready yet...
            continue
        units.append(_get_unit(ops_test, app, raw_app, u_name, raw_unit))

    return await asyncio.gather(*units) if units else []


async def get_application_subordinate_units(
    ops_test: OpsTest, principal_app: str, app: str
) -> List[Unit]:
    """Get fully detailed units of an application."""
    # Juju incorrectly reports the IP addresses after the network is restored this is reported as a
    # bug here: https://github.com/juju/python-libjuju/issues/738. Once this bug is resolved use of
    # `get_unit_ip` should be replaced with `.public_address`
    raw_app = get_raw_application(ops_test, app)
    units = []
    for principal_unit in get_raw_application(ops_test, principal_app)["units"].values():
        u_name, raw_unit = None, None
        for u_name, raw_unit in principal_unit["subordinates"].items():
            if u_name.startswith(f"{app}/"):
                break
        else:
            raise ValueError(f"Subordinate unit for {app} not found in {principal_app}")

        if not raw_unit.get("public-address"):
            # unit not ready yet...
            continue

        units.append(_get_unit(ops_test, app, raw_app, u_name, raw_unit, subordinate=True))
    return await asyncio.gather(*units) if units else []


def _is_every_condition_on_app_met(
    ops_test: OpsTest,
    app: str,
    units: Optional[List[Unit]],
    apps_statuses: Optional[List[str]],
    apps_full_statuses: Optional[Dict[str, Dict[str, List[str]]]],
) -> bool:
    """Evaluate if all the conditions of an application are met."""
    if units:
        app_status = units[0].app_status
    else:
        app_status = get_raw_application(ops_test, app)["application-status"]
        app_status = Status(
            value=app_status["current"],
            since=app_status["since"],
            message=app_status.get("message"),
        )

    if apps_statuses:
        if app_status.value not in apps_statuses:
            return False
    else:
        any_match = False
        for status_val, messages in apps_full_statuses[app].items():
            any_match = any_match or (
                app_status.value == status_val and app_status.message in (messages or ["", None])
            )
        if not any_match:
            return False

    return True


def _is_every_condition_on_units_met(
    model: str,
    app: str,
    units: List[Unit],
    units_statuses: Optional[List[str]],
    units_full_statuses: Optional[Dict[str, Dict[str, Dict[str, List[str]]]]],
    idle_period: int,
) -> bool:
    """Evaluate if all the conditions of a unit are met."""
    for unit in units:
        if unit.agent_status.value != "idle":
            return False

        if unit.workload_status.value == "error":
            logger.error(f"Error in: {unit.name}")
            _dump_juju_logs(model, unit.name)

        if units_statuses:
            if unit.workload_status.value not in units_statuses:
                return False
        else:
            any_match = False
            for status_val, messages in units_full_statuses[app]["units"].items():
                any_match = any_match or (
                    unit.workload_status.value == status_val
                    and unit.workload_status.message in (messages or ["", None])
                )
            if not any_match:
                return False

        if unit.agent_status.since + timedelta(seconds=idle_period) > datetime.now():
            return False

    return True


async def _is_every_condition_met(
    ops_test: OpsTest,
    apps: List[str],
    wait_for_exact_units: Dict[str, int],
    apps_statuses: Optional[List[str]] = None,
    apps_full_statuses: Optional[Dict[str, Dict[str, List[str]]]] = None,
    units_statuses: Optional[List[str]] = None,
    units_full_statuses: Optional[Dict[str, Dict[str, Dict[str, List[str]]]]] = None,
    idle_period: int = 30,
) -> bool:
    """Evaluate if all the deployment status conditions are met."""
    for app in apps:
        app_dict = get_raw_application(ops_test, app)
        expected_units = wait_for_exact_units[app]
        if "subordinate-to" in app_dict:
            logger.debug(f"Subordinate app: {app}")
            # In this case, we must search for the principal app
            units = await get_application_subordinate_units(
                ops_test, app_dict["subordinate-to"][0], app
            )
        else:
            logger.debug(f"This is a principal app: {app}")
            units = await get_application_units(ops_test, app)

        if -1 < expected_units != len(units):
            logger.info(f"{app} -- expected units: {expected_units} -- current: {len(units)}")
            return False

        if (apps_statuses or apps_full_statuses) and not _is_every_condition_on_app_met(
            ops_test=ops_test,
            app=app,
            units=(units if expected_units > -1 else None),
            apps_statuses=apps_statuses,
            apps_full_statuses=apps_full_statuses,
        ):
            logger.info(f"\tApp: {app} - conditions unmet.")
            logger.info(_progress_line(units))
            return False

        if (
            expected_units > -1
            and (units_statuses or units_full_statuses)
            and not _is_every_condition_on_units_met(
                model=ops_test.model.info.name,
                app=app,
                units=units,
                units_statuses=units_statuses,
                units_full_statuses=units_full_statuses,
                idle_period=idle_period,
            )
        ):
            logger.info(f"\tApp: {app} - Units - conditions unmet.")
            logger.info(_progress_line(units))
            return False

    return True


async def wait_until(  # noqa: C901
    ops_test: OpsTest,
    apps: List[str],
    apps_statuses: Optional[List[str]] = None,
    apps_full_statuses: Optional[Dict[str, Dict[str, List[str]]]] = None,
    units_statuses: Optional[List[str]] = None,
    units_full_statuses: Optional[Dict[str, Dict[str, Dict[str, List[str]]]]] = None,
    wait_for_exact_units: Optional[Union[int, Dict[str, int]]] = -1,
    idle_period: int = 30,
    timeout: int = 1200,
) -> None:
    """Block and wait until a set of statuses and timeouts are met.

    Args:
        ops_test: The ops test framework instance
        apps: A list of applications whose statuses to test against
        apps_statuses: List of acceptable application statuses to wait for, for all apps.
            ["blocked", "active", ...]
        apps_full_statuses: List of acceptable unit statuses to wait for, for all apps with more
            granularity: {"app1": {"blocked": ["msg1", "msg2"], "active": []}, "app2": ...}
        units_statuses: List of acceptable statuses to wait for, for all units of all apps.
            ["blocked", "active", ...]
        units_full_statuses: List of acceptable statuses to wait for, for all apps with more
            granularity: {"app1": "units": {"blocked": ["msg1", "msg2"], "active": []}}, "app2"...}
        wait_for_exact_units: The desired number of units to wait for, can be >= to -1
            if set as int, this value is expected for all apps but if more granularity is needed to
            be set, pass a dictionary such as: {"app1": 2, "app2": 1, ...}, if set to -1, the check
            only happens at the application level.
        idle_period: Seconds to wait for the agents of each application unit to be idle.
        timeout: Time to wait before giving up on waiting.
    """
    if not apps:
        raise ValueError("apps must be specified.")
    if not (apps_statuses or apps_full_statuses or units_statuses or units_full_statuses):
        apps_statuses = ["active"]
        units_statuses = ["active"]
    if isinstance(wait_for_exact_units, int):
        wait_for_exact_units = {app: wait_for_exact_units for app in apps}
    elif not wait_for_exact_units:
        wait_for_exact_units = {app: -1 for app in apps}
    else:
        for app in apps:
            if app not in wait_for_exact_units:
                wait_for_exact_units[app] = 1
    try:
        logger.info("\n\n\n")
        logger.info(
            subprocess.check_output(
                f"juju status --model {ops_test.model.info.name}", shell=True
            ).decode("utf-8")
        )
        for attempt in Retrying(stop=stop_after_delay(timeout), wait=wait_fixed(10)):
            with attempt:
                logger.info(f"\n\n\n{now()} -- Waiting for model...")
                if await _is_every_condition_met(
                    ops_test=ops_test,
                    apps=apps,
                    wait_for_exact_units=wait_for_exact_units,
                    apps_statuses=apps_statuses,
                    apps_full_statuses=apps_full_statuses,
                    units_statuses=units_statuses,
                    units_full_statuses=units_full_statuses,
                    idle_period=idle_period,
                ):
                    logger.info(f"{now()} -- Waiting for model: complete.\n\n\n")
                    return
                raise Exception
    except RetryError:
        logger.error("wait_until -- Timed out!\n\n\n")
        logger.info(
            subprocess.check_output(
                f"juju status --model {ops_test.model.info.name}", shell=True
            ).decode("utf-8")
        )
        _dump_juju_logs(model=ops_test.model.info.name, lines=3000)
        raise


async def get_application_unit_ids_ips(ops_test: OpsTest, app: str = APP_NAME) -> Dict[int, str]:
    """List the units of an application by id and corresponding IP.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        Dictionary unit_id / unit_ip, of the application
    """
    result = {}
    for unit in await get_application_units(ops_test, app):
        result[unit.id] = unit.ip

    return result


async def get_application_unit_ids_hostnames(
    ops_test: OpsTest, app: str = APP_NAME
) -> Dict[int, str]:
    """List the units of an application by id and corresponding host name."""
    result = {}
    for unit in ops_test.model.applications[app].units:
        unit_id = int(unit.name.split("/")[1])
        result[unit_id] = await get_unit_hostname(ops_test, unit_id, app)

    return result


def get_application_unit_ids(ops_test: OpsTest, app: str = APP_NAME) -> List[int]:
    """List the unit IDs of an application.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        list of current unit ids of the application
    """
    return [int(unit.name.split("/")[1]) for unit in ops_test.model.applications[app].units]


def get_file_contents(ops_test: OpsTest, unit: str, filename: str) -> str:
    output = subprocess.check_output(
        ["bash", "-c", f"JUJU_MODEL={ops_test.model.name} juju ssh {unit} sudo cat {filename}"]
    )
    return output


def get_conf_as_dict(ops_test: OpsTest, unit: str, filename: str) -> dict[str, str]:
    """Convert a yml config file to a dict."""
    config = get_file_contents(ops_test, unit, filename)
    return yaml.safe_load(str(config.decode("utf-8")).replace("ll", ""))


async def get_leader_unit_id(ops_test: OpsTest, app: str = APP_NAME) -> int:
    """Helper function that retrieves the leader unit ID."""
    leader_unit = None
    for unit in ops_test.model.applications[app].units:
        if await unit.is_leader_from_status():
            leader_unit = unit
            break

    return int(leader_unit.name.split("/")[1])


async def get_leader_unit_ip(ops_test: OpsTest, app: str = APP_NAME) -> str:
    """Helper function that retrieves the leader unit."""
    for unit in await get_application_units(ops_test, app):
        if unit.is_leader:
            return unit.ip


@retry(wait=wait_fixed(wait=15), stop=stop_after_attempt(15))
async def run_action(
    ops_test: OpsTest,
    unit_id: Optional[int],
    action_name: str,
    params: Optional[Dict[str, any]] = None,
    app: str = APP_NAME,
) -> SimpleNamespace:
    """Run a charm action.

    Returns:
        A SimpleNamespace with "status, response (results)"
    """
    if unit_id is None:
        online_units = []
        for unit in await get_application_units(ops_test, app):
            if unit.workload_status.value != "active":
                continue

            ping = subprocess.call(
                f"nc -zv {unit.ip} 22".split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if ping == 0:
                online_units.append(unit)

        unit_id = random.choice(online_units).id

    unit_name = [
        unit.name
        for unit in ops_test.model.applications[app].units
        if unit.name.endswith(f"/{unit_id}")
    ][0]

    action = await ops_test.model.units.get(unit_name).run_action(action_name, **(params or {}))
    action = await action.wait()

    return SimpleNamespace(status=action.status or "completed", response=action.results)


async def get_secrets(
    ops_test: OpsTest, unit_id: Optional[int] = None, username: str = "admin", app: str = APP_NAME
) -> Dict[str, str]:
    """Use the charm action to retrieve the admin password and chain.

    Returns:
        Dict with the admin and cert chain stored on the peer relation databag.
    """
    # can retrieve from any unit running unit, so we pick the first
    return (
        await run_action(ops_test, unit_id, "get-password", {"username": username}, app=app)
    ).response


async def http_request(
    ops_test: OpsTest,
    method: str,
    endpoint: str,
    payload: Optional[Union[str, Dict[str, any]]] = None,
    resp_status_code: bool = False,
    verify=True,
    user: Optional[str] = "admin",
    user_password: Optional[str] = None,
    app: str = APP_NAME,
    json_resp: bool = True,
    extra_headers: Optional[Dict[str, any]] = None,
):
    """Makes an HTTP request.

    Args:
        ops_test: The ops test framework instance.
        method: the HTTP method (GET, POST, HEAD etc.)
        endpoint: the url to be called.
        payload: the body of the request if any.
        resp_status_code: whether to only return the http response code.
        verify: whether verify certificate chain or not
        user_password: use alternative password than the admin one in the secrets.
        app: the name of the current application.
        json_resp: return a json response or simply log

    Returns:
        A json object.
    """
    admin_secrets = await get_secrets(ops_test, app=app)

    # fetch the cluster info from the endpoint of this unit
    with requests.Session() as session, tempfile.NamedTemporaryFile(mode="w+") as chain:
        chain.write(admin_secrets["ca-chain"])
        chain.seek(0)

        logger.info(f"Calling: {method} -- {endpoint}")

        request_kwargs = {
            "method": method,
            "url": endpoint,
            "timeout": (17, 17),
        }
        headers = {}
        if json_resp:
            headers.update(
                {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }
            )
        if extra_headers:
            headers.update(extra_headers)

        if headers:
            request_kwargs["headers"] = headers

        if isinstance(payload, str):
            request_kwargs["data"] = payload
        elif isinstance(payload, dict):
            request_kwargs["data"] = json.dumps(payload)

        session.auth = (user, user_password or admin_secrets["password"])

        request_kwargs["verify"] = chain.name if verify else False
        resp = session.request(**request_kwargs)

        if resp.status_code == 503:
            logger.debug("\n\n\n\n -- Error 503 -- \n")
            await debug_failed_unit(ops_test, app, endpoint)

        if resp_status_code:
            return resp.status_code

        if json_resp:
            return resp.json()

        logger.info(f"\n{resp.text}")
        return resp


async def debug_failed_unit(ops_test: OpsTest, app: str, endpoint: str) -> None:
    """Print the logs of a unit failing with a certain set of statuses."""
    unit_ip = endpoint[8:].split(":")[0]

    ids_ips = await get_application_unit_ids_ips(ops_test, app=app)
    unit_id = [u_id for u_id, u_ip in ids_ips.items() if u_ip == unit_ip][0]

    root = "/var/snap/opensearch"
    files_to_debug = [
        f"{root}/common/logs/{app}-{ops_test.model_name}.log",
        f"{root}/current/config/opensearch.yml",
        f"{root}/current/config/unicast_hosts.txt",
    ]
    for f in files_to_debug:
        logger.debug(f"{f}:\n")

        get_logs_cmd = f"run --unit {app}/{unit_id} -- sudo cat {f}"
        _, out, err = await ops_test.juju(*get_logs_cmd.split())
        logger.debug(f"out:\n{out}\n---\nerr:\n{err}")

        logger.debug("\n\n------------------\n\n")


def opensearch_client(
    hosts: List[str], user_name: str, password: str, cert_path: str
) -> OpenSearch:
    """Build an opensearch client."""
    return OpenSearch(
        hosts=[{"host": ip, "port": 9200} for ip in hosts],
        http_auth=(user_name, password),
        http_compress=True,
        sniff_on_start=True,  # sniff before doing anything
        sniff_on_connection_fail=True,  # refresh nodes after a node fails to respond
        sniffer_timeout=60.0,  # and also every 60 seconds
        # sniff_timeout=5.0,  # and also every 60 seconds
        use_ssl=True,  # turn on ssl
        verify_certs=True,  # make sure we verify SSL certificates
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        ca_certs=cert_path,  # cert path on disk
    )


async def get_application_unit_ips(ops_test: OpsTest, app: str = APP_NAME) -> List[str]:
    """List the unit IPs of an application.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        list of current unit IPs of the application
    """
    return [unit.ip for unit in await get_application_units(ops_test, app)]


async def get_secret_by_label(ops_test, label: str) -> Dict[str, str]:
    secrets_raw = await ops_test.juju("list-secrets")
    secret_ids = [
        secret_line.split()[0] for secret_line in secrets_raw[1].split("\n")[1:] if secret_line
    ]

    for secret_id in secret_ids:
        secret_data_raw = await ops_test.juju(
            "show-secret", "--format", "json", "--reveal", secret_id
        )
        secret_data = json.loads(secret_data_raw[1])

        if label == secret_data[secret_id].get("label"):
            return secret_data[secret_id]["content"]["Data"]


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def check_cluster_formation_successful(
    ops_test: OpsTest, unit_ip: str, unit_names: List[str]
) -> bool:
    """Returns whether the cluster formation was successful and all nodes successfully joined.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the unit of the OpenSearch unit.
        unit_names: The list of unit names in the cluster.

    Returns:
        Whether The cluster formation is successful.
    """
    response = await http_request(ops_test, "GET", f"https://{unit_ip}:9200/_nodes")
    if "_nodes" not in response or "nodes" not in response:
        return False

    successful_nodes = response["_nodes"]["successful"]
    if successful_nodes < len(unit_names):
        return False

    registered_nodes = [node_desc["name"] for node_desc in response["nodes"].values()]
    return set(unit_names) == set(registered_nodes)


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def cluster_health(
    ops_test: OpsTest, unit_ip: str, wait_for_green_first: bool = False
) -> Dict[str, any]:
    """Fetch the cluster health."""
    if wait_for_green_first:
        try:
            return await http_request(
                ops_test,
                "GET",
                f"https://{unit_ip}:9200/_cluster/health?wait_for_status=green&timeout=1m",
            )
        except requests.HTTPError:
            # it timed out, settle with current status, fetched next without the 1min wait
            pass

    return await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cluster/health",
    )


async def get_application_unit_ips_names(ops_test: OpsTest, app: str = APP_NAME) -> Dict[str, str]:
    """List the units of an application by name and corresponding IPs.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        Dictionary unit_name / unit_ip, of the application
    """
    result = {}
    for unit in await get_application_units(ops_test, app):
        result[unit.name] = unit.ip

    return result


def get_application_unit_names(ops_test: OpsTest, app: str = APP_NAME) -> List[str]:
    """List the unit names of an application.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        list of current unit names of the application
    """
    app_id = f"{ops_test.model.uuid}/{app}"
    app_short_id = md5(app_id.encode()).hexdigest()[:3]
    return [
        f"{unit.name.replace('/', '-')}.{app_short_id}"
        for unit in ops_test.model.applications[app].units
    ]


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
async def cluster_voting_config_exclusions(
    ops_test: OpsTest, unit_ip: str
) -> List[Dict[str, str]]:
    """Fetch the cluster allocation of shards."""
    result = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cluster/state/metadata/voting_config_exclusions",
    )
    return (
        result.get("metadata", {})
        .get("cluster_coordination", {})
        .get("voting_config_exclusions", {})
    )


async def execute_update_status_manually(ops_test: OpsTest, app: str):
    """Execute the update-status hook manually."""
    leader_id = await get_leader_unit_id(ops_test, app)

    cmd = '"export JUJU_DISPATCH_PATH=hooks/update-status; ./dispatch"'
    exec_cmd = f"juju exec -u opensearch/{leader_id} -m {ops_test.model.name} -- {cmd}"
    try:
        # The "normal" subprocess.run with "export ...; ..." cmd was failing
        # Noticed that, for this case, canonical/jhack uses shlex instead to split.
        # Adding it fixed the issue.
        subprocess.run(shlex.split(exec_cmd))
    except Exception as e:
        logger.error(
            f"Failed to apply state: process exited with {e.returncode}; "
            f"stdout = {e.stdout}; "
            f"stderr = {e.stderr}.",
        )


@retry(wait=wait_fixed(wait=30), stop=stop_after_attempt(15))
async def set_watermark(
    ops_test: OpsTest,
    app: str,
) -> None:
    """Set watermark on the application."""
    unit_ip = await get_leader_unit_ip(ops_test, app=app)
    await http_request(
        ops_test,
        "PUT",
        f"https://{unit_ip}:9200/_cluster/settings",
        {
            "persistent": {
                "cluster.routing.allocation.disk.threshold_enabled": "false",
            }
        },
        app=app,
    )


def is_reachable(host: str, port: int) -> bool:
    """Attempting a socket connection to a host/port."""
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((host, port))
        return True
    except Exception as e:
        logger.debug(f"Connection to {host}:{port} fails with: {e}")
        return False
    finally:
        s.close()


async def is_up(ops_test: OpsTest, unit_ip: str, retries: int = 25) -> bool:
    """Return if node up."""
    try:
        for attempt in Retrying(stop=stop_after_attempt(retries), wait=wait_fixed(wait=15)):
            with attempt:
                await http_request(ops_test, "GET", f"https://{unit_ip}:9200/")
                return True
    except RetryError:
        return False


async def get_reachable_unit_ips(ops_test: OpsTest, app: str = APP_NAME) -> List[str]:
    """Helper function to retrieve the IP addresses of all online units."""
    result = []
    for ip in await get_application_unit_ips(ops_test, app):
        if not is_reachable(ip, 9200):
            continue

        if await is_up(ops_test, ip, retries=1):
            result.append(ip)

    return result


def juju_version_major() -> int:
    """Fetch the juju version."""
    version = subprocess.run(["juju", "--version"], check=True, stdout=subprocess.PIPE).stdout
    return int(version.strip().decode("utf-8").split(".")[0])


async def get_controller_hostname(ops_test: OpsTest) -> str:
    """Return controller machine hostname."""
    _, raw_controller, _ = await ops_test.juju("show-controller")

    controller = yaml.safe_load(raw_controller.strip())

    return [
        machine.get("instance-id")
        for machine in controller[ops_test.controller_name]["controller-machines"].values()
    ][0]


async def app_name(ops_test: OpsTest) -> str | None:
    """Returns the name of the cluster running OpenSearch.

    This is important since not all deployments of the OpenSearch charm have the
    application name "opensearch".
    Note: if multiple clusters are running OpenSearch this will return the one first found.
    """
    apps = json.loads(
        subprocess.check_output(
            f"juju status --model {ops_test.model.info.name} --format=json".split()
        )
    )["applications"]

    logger.info(f"Apps inside app_name: {apps}")

    opensearch_apps = {
        name: desc for name, desc in apps.items() if desc["charm-name"] == "opensearch"
    }
    for name, desc in opensearch_apps.items():
        if name == "opensearch-main":
            return name

    return list(opensearch_apps.keys())[0] if opensearch_apps else None
