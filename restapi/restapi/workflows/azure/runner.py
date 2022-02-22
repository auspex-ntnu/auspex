from re import S
from typing import Any

from pydantic import BaseSettings, Field
from ..base import WorkflowRunner
from azure.mgmt.logic.aio import LogicManagementClient


class AzureRunner(WorkflowRunner):
    async def start_scan(self) -> dict:  # ???
        return {}

    async def start_pdf(self) -> dict:
        return {}


class LogicAppSettings(BaseSettings):
    credential: str = Field(..., env="AZURE_CLIENT_CREDENTIAL")
    subscription_id: str = Field(..., env="AZURE_SUBSCRIPTION_ID")
    base_url: str = Field(..., env="AZURE_LOGICAPP_BASE_URL")
    polling_interval: str = Field(..., env="AZURE_LOGICAPP_POLLING_INTERVAL")
    resource_group_name: str = Field(..., env="AZURE_RESOURCE_GROUP_NAME")
    workflow_name: str = Field(..., env="AZURE_WORKFLOW_NAME")


settings = LogicAppSettings()


def _get_client() -> LogicManagementClient:
    return LogicManagementClient(
        settings.credential,
        settings.subscription_id,
        settings.base_url,
    )


async def run_workflow(name: str, *args) -> Any:
    client = _get_client()
    workflow = await client.workflows.enable(
        settings.resource_group_name,
        settings.workflow_name,
    )
    # RETURN VALUE????
