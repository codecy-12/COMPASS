#!/bin/sh
set -eu

MODE="${COMPASS_MODE:-runtime}"
TRACE_DIR="${COMPASS_TRACE_DIR:-/traces}"
mkdir -p "${TRACE_DIR}" /opt/httpd/cgi-bin

case "${MODE}" in
  runtime)
    exec strace -ff -tt -yy -s 65535 -o "${TRACE_DIR}/runtime.strace" /opt/httpd/bin/httpd -X -f /opt/httpd/conf/httpd.conf
    ;;
  offline)
    exec uftrace record -a -o "${TRACE_DIR}/uftrace.data" -- /opt/httpd/bin/httpd -X -f /opt/httpd/conf/httpd.conf
    ;;
  plain)
    exec /opt/httpd/bin/httpd -X -f /opt/httpd/conf/httpd.conf
    ;;
  *)
    echo "unknown COMPASS_MODE: ${MODE}" >&2
    exit 1
    ;;
esac
