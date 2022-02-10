# Based on: https://github.com/GoogleCloudPlatform/python-docs-samples/blob/main/workflows/cloud-client/main.py
# Changes from example:
#   * Adapted for async execution.
#   * Refactored monolithic function into smaller functions.
#   * Support for arbitrary JSON-serializable key:value pairs
#   * Logging with loguru instead of print

from loguru import logger

import json
import os
import time
from typing import Any

from google.cloud.workflows_v1beta import WorkflowsAsyncClient
from google.cloud.workflows.executions_v1beta import ExecutionsAsyncClient
from google.cloud.workflows.executions_v1beta.types import Execution


async def run_workflow(name: str, **kwargs) -> Any:  # TODO: fix return type
    # Create Async API Clients
    execution_client = ExecutionsAsyncClient()
    workflows_client = WorkflowsAsyncClient()

    # Construct the fully qualified workflow path.
    project, location = await get_project_location()
    parent = workflows_client.workflow_path(project, location, name)

    # Execute workflow
    response = await _execute_workflow(
        execution_client,
        parent,
        **kwargs,
    )
    logger.debug(f"Created execution: {response.name}")

    # Wait for execution to finish, then print results.
    execution_finished = False
    backoff_delay = 1  # Start wait with delay of 1 second

    logger.debug("Polling every second for result...")
    while not execution_finished:
        execution = await execution_client.get_execution(
            request={"name": response.name}
        )
        execution_finished = execution.state != Execution.State.ACTIVE

        # If we haven't seen the result yet, wait a second.
        if not execution_finished:
            logger.debug("- Waiting for results...")
            time.sleep(backoff_delay)
            backoff_delay *= 2  # Double the delay to provide exponential backoff.
        else:
            logger.debug(f"Execution finished with state: {execution.state.name}")
            logger.debug(execution.result)
            return execution.result


async def get_project_location() -> tuple[str, str]:
    if not (project := os.getenv("GOOGLE_CLOUD_PROJECT", "bachelor-339614")):
        raise Exception("GOOGLE_CLOUD_PROJECT env var is required.")
    if not (location := os.getenv("WORKFLOW_REGION", "europe-west4")):
        raise Exception("WORKFLOW_REGION env var is required.")
    return project, location


async def get_execution_args(kwargs: dict) -> Execution | None:
    """Serializes dict of arguments to JSON that will be passed to the workflow execution."""
    execution = None
    if kwargs:
        j = json.dumps(kwargs)  # TODO: handle exceptions (or do it top level?)
        execution = Execution(argument=j)
    return execution


async def _execute_workflow(
    client: ExecutionsAsyncClient, parent: str, **kwargs
) -> Execution:
    """Creates a callable object that starts the execution of a workflow"""
    # Add keyword arguments to request body (if any)
    execution = await get_execution_args(kwargs)
    return await client.create_execution(
        parent=parent,
        execution=execution,
    )
