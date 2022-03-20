#!/bin/bash

cd reporter
poetry run pytest
cd ../scanner
poetry run pytest
cd ../restapi
poetry run pytest