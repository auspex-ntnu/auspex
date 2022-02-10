import docker
from functools import cache
from loguru import logger


@cache
def get_docker_client() -> docker.DockerClient:
    return docker.from_env()


def pull_docker_image(image: str) -> None:
    client = get_docker_client()
    logger.info(f"Docker: Pulling {image}")
    client.images.pull(image)
