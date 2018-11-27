#!/bin/sh
set -e

client=$(find /root/onos -type f -name client | grep "^/root/onos/apache-karaf-[0-9.]*/bin/client" | head -1)

if [ ! -x "$client" ]; then
  echo "ONOS Client executable not found"
  exit 1
fi

"$client" -- "$@"
