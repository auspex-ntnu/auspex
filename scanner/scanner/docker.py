import docker
from functools import cache


@cache
def get_docker_client() -> docker.DockerClient:
    return docker.from_env()


def pull_docker_image(image_name: str) -> None:
    client = get_docker_client()
    client.images.pull(image_name)
