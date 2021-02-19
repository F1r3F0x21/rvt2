#!/bin/bash
# Sometimes, indices are automatically set to read-only. This happens, for instance, if the disk use is
# above a threshold of typically 95%. Fix the problem and then run this command
# Use: rw_incides.sh [https://localhost:9200]

if [ -z "$1" ]; then
    ESSERVER=http://localhost:9200
else
    ESSERVER=$2
fi

curl -X PUT "$ESSERVER/_all/_settings" -H 'Content-Type: application/json' -d'{ "index.blocks.read_only_allow_delete" : false } }'
