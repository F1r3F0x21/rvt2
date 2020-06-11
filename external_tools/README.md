# External tools

Some external tools to the rvt

## ElasticSearch

Elastic is used by the `indexer` plugin, to allow advanced searches and
dashboards. You need an ElasticSearch server somewhere in your network. For a
local install, you can use either a downloaded ElasticSearch server, or a
docker image, as you find fit.

- `run_elastic_docker.sh`: Runs a server using docker.
- `fun_elastic.sh`: Runs the server in a directory `elastisearch-7.X.X`

## Tika

Tika is a document parser by the Apache Foundation. Tika is uses by the
`indexer` module. You need a Tika server in your network. For a local install,
run the script and modules will be downloaded automatically.

- `run.sh`: Run Tika as a server. This script downloads libraries and
  dependeincies if they are not found in the current directory
