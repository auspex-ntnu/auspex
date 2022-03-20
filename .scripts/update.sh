#!/bin/bash

(cd core && poetry update && poetry install)
(cd reporter && poetry update && poetry install)
(cd scanner && poetry update && poetry install)
(cd restapi && poetry update && poetry install)