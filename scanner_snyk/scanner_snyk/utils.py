import time

from sanitize_filename import sanitize


def get_scan_filename(image_name: str, backend: str) -> str:
    filename = f"{backend}_{image_name}_{time.time()}.json"
    filename = filename.replace(":", "_")  # replace before sanitization
    return sanitize(filename)
