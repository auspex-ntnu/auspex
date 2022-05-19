# TODO: move to auspex_core/exceptions


class DockerRegistryException(Exception):
    pass


class ImageNotFound(DockerRegistryException):
    """Raised when an image cannot be found in a repository."""


class RegistryError(DockerRegistryException):
    """Raised when the call to a registry fails."""


class TagsError(DockerRegistryException):
    """Raised when a /tags/list response can't be parsed."""


class ImageNameNotSet(DockerRegistryException):
    """Trying to interact with an ImageInfo whose .image attribute hasn't been intialized"""


class InvalidImageTimeMode(DockerRegistryException):
    """Raised when an invalid ImageTimeMode is encountered."""
