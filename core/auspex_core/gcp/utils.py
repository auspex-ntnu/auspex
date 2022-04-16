import httpx


def get_project_id_http() -> str:
    """Get metadata for a container running on Cloud Run.

    Example:
        >>> get_project_id_http()
        'ntnu-student-project'
    """
    res = httpx.get(
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        headers={"Metadata-Flavor": "Google"},
    )
    return res.text
