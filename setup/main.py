from typing import Protocol
from loguru import logger
from setup import firestore, storage


class Initable(Protocol):
    def init(self) -> None:
        """Runs the initialization logic for the given GCP service."""
        ...


services: dict[str, Initable] = {
    "firestore": firestore,
    "storage": storage,
}


def main():
    for service_name, service in services.items():
        try:
            service.init()
        except Exception as e:
            logger.error(f"Failed to initialize {service_name}")
            logger.exception(e)
            raise e


if __name__ == "__main__":
    main()
