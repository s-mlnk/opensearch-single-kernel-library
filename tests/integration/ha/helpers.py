#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import subprocess

from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from opensearch_single_kernel.core.models import App, Node
from tests.integration.conftest import APP_NAME
from tests.integration.helpers import (
    get_application_unit_ids_ips,
    get_leader_unit_ip,
    http_request,
)
from tests.integration.models import Shard

from .continuous_writes import ContinuousWrites

logger = logging.getLogger(__name__)


def nodes_count_by_role(nodes: list[Node]) -> dict[str, int]:
    """Count number of nodes by role."""
    result = {}
    for node in nodes:
        for role in node.roles:
            if role not in result:
                result[role] = 0
            result[role] += 1

    return result


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


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
async def get_elected_cm_unit_id(ops_test: OpsTest, unit_ip: str) -> int:
    """Returns the unit id of the current elected cm node."""
    # get current elected cm node
    resp = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cluster/state/cluster_manager_node",
    )
    cm_node_id = resp.get("cluster_manager_node")
    if not cm_node_id:
        return -1

    # get all nodes
    resp = await http_request(ops_test, "GET", f"https://{unit_ip}:9200/_nodes")
    node_name = resp["nodes"][cm_node_id]["name"]

    return int(node_name.split(".")[0].split("-")[-1])


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
async def cluster_allocation(ops_test: OpsTest, unit_ip: str) -> list[dict[str, str]]:
    """Fetch the cluster allocation of shards."""
    return await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cat/allocation",
    )


async def get_number_of_shards_by_node(ops_test: OpsTest, unit_ip: str) -> dict[int, int]:
    """Get the number of shards allocated per node."""
    init_cluster_alloc = await cluster_allocation(ops_test, unit_ip)

    result = {}
    for alloc in init_cluster_alloc:
        key = -1
        if alloc["node"] != "UNASSIGNED":
            key = int(alloc["node"].split(".")[0].split("-")[-1])
        result[key] = int(alloc["shards"])

    return result


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
async def all_nodes(ops_test: OpsTest, unit_ip: str, app: str = APP_NAME) -> list[Node]:
    """Fetch all cluster nodes."""
    response = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_nodes",
        app=app,
    )
    nodes = response.get("nodes", {})

    result = []
    for node_id, node in nodes.items():
        result.append(
            Node(
                name=node["name"],
                roles=node["roles"],
                ip=node["ip"],
                app=App(id=node["attributes"]["app_id"]),
                unit_id=int(node["name"].split(".")[0].split("-")[-1]),
                temperature=node.get("attributes", {}).get("temp"),
            )
        )
    return result


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
async def get_shards_by_state(ops_test: OpsTest, unit_ip: str) -> dict[str, list[str]]:
    """Returns all shard statuses for all indexes in the cluster.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the OpenSearch unit.

    Returns:
        Whether all indexes have been successfully replicated and shards started.
    """
    response = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cat/shards",
    )

    logger.info(f"Shards:\n{response}")

    indexes_by_status = {}
    for shard in response:
        indexes_by_status.setdefault(shard["state"], []).append(
            f"{shard['node']}/{shard['index']}"
        )

    return indexes_by_status


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
async def get_shards_by_index(ops_test: OpsTest, unit_ip: str, index_name: str) -> list[Shard]:
    """Returns the list of shards and their location in cluster for an index.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the OpenSearch unit.
        index_name: the name of the index.

    Returns:
        List of shards.
    """
    response = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/{index_name}/_search_shards",
    )

    nodes = response["nodes"]

    result = []
    for shards_collection in response["shards"]:
        for shard in shards_collection:
            node_name_split = nodes[shard["node"]]["name"].split(".")[0].split("-")
            result.append(
                Shard(
                    index=index_name,
                    num=shard["shard"],
                    is_prim=shard["primary"],
                    node_id=shard["node"],
                    unit_id=int(node_name_split[-1]),
                    app="-".join(node_name_split[:-1]),
                )
            )

    return result


async def assert_continuous_writes_increasing(
    c_writes: ContinuousWrites,
) -> None:
    """Asserts that the continuous writes are increasing."""
    writes_count = await c_writes.count()
    await asyncio.sleep(20)
    more_writes = await c_writes.count()
    assert more_writes > writes_count, "Writes not continuing to DB"


async def assert_continuous_writes_consistency(
    ops_test: OpsTest, c_writes: ContinuousWrites, apps: list[str]
) -> None:
    """Continuous writes checks."""
    result = await c_writes.stop()
    logger.info(f"Continuous writes result: {result}")
    assert result.max_stored_id == result.count - 1
    assert result.max_stored_id == result.last_expected_id

    unit_ip = await get_leader_unit_ip(ops_test, apps[0])

    # fetch unit ips by unit id by application
    apps_units_ips = {app: await get_application_unit_ids_ips(ops_test, app) for app in apps}

    # investigate the data in each shard, primaries and their respective replicas
    shards = await get_shards_by_index(ops_test, unit_ip, ContinuousWrites.INDEX_NAME)
    shards_by_id = {}
    for shard in shards:
        shards_by_id.setdefault(shard.num, []).append(shard)

    # count data on each shard. For the **balanced** continuous writes index, we have 2
    # primary shards and replica shards of each on all the nodes. In other words: prim1 and
    # its replicas will have a different "num" than prim2 and its replicas.
    count_from_shards = 0
    for shard_num, shards_list in shards_by_id.items():
        count_by_shard = [
            await c_writes.count(
                unit_ip=apps_units_ips[shard.app][shard.unit_id],
                preference=f"_shards:{shard_num}|_only_local",
            )
            for shard in shards_list
        ]
        # all shards with the same id must have the same count
        assert len(set(count_by_shard)) == 1
        count_from_shards += count_by_shard[0]

    assert result.count == count_from_shards
