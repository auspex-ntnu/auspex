import json

from scanner.backends.snyk.model import SnykContainerScan

with open("phpscan.json", "r") as f:
    j = json.load(f)

s = SnykContainerScan.parse_obj(j)
print(s)
