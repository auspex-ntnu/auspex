from scanner.backends.snyk.model import SnykContainerScan
import json


with open("phpscan.json", "r") as f:
    j = json.load(f)

s = SnykContainerScan.parse_obj(j)
print(s)
