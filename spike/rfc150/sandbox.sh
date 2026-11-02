#!/usr/bin/env bash
# RFC-150 step 1 spike: a sandbox behind default-deny egress on a GitHub-hosted runner.
#   sandbox.sh probe <copy-dir> <out.json>
#   sandbox.sh ecosystem <eco> <copy-dir> <out.json>
# Only variable *names* leave the sandbox, never values. All commands are fixed
# strings from this file: nothing model- or repo-supplied is evaluated on the host.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
source "$here/images.env"
trap 'docker rm -f rsolv-sbx rsolv-proxy >/dev/null 2>&1 || true; docker network rm rsolv-net >/dev/null 2>&1 || true' EXIT

start_proxy() { # $1 = allowlist file
  docker network create --internal rsolv-net >/dev/null
  docker run -d --name rsolv-proxy \
    -v "$here/squid.conf:/etc/squid/squid.conf:ro" -v "$1:/etc/squid/allowlist.txt:ro" \
    "$PROXY_IMAGE" >/dev/null
  docker network connect rsolv-net rsolv-proxy
  proxy_ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "rsolv-net").IPAddress}}' rsolv-proxy)
  local bridge_ip
  bridge_ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "bridge").IPAddress}}' rsolv-proxy)
  for _ in $(seq 30); do curl -s -o /dev/null -m 1 "http://$bridge_ip:3128/" && return 0; sleep 1; done
  echo "proxy did not start" >&2; docker logs rsolv-proxy >&2; return 1
}

start_sandbox() { # $1 = image, $2 = copy dir
  docker run -d --name rsolv-sbx --network rsolv-net --dns 127.0.0.1 \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /tmp:exec --env-file "$here/sandbox.env" \
    -e "HTTP_PROXY=http://$proxy_ip:3128" -e "HTTPS_PROXY=http://$proxy_ip:3128" \
    -e "http_proxy=http://$proxy_ip:3128" -e "https_proxy=http://$proxy_ip:3128" \
    -e "PROXY_HOST=$proxy_ip" \
    -v "$2:/work" -v "$here/eco:/rsolv:ro" -w /work \
    --entrypoint sleep "$1" 86400 >/dev/null
  docker exec rsolv-sbx mkdir -p /tmp/home /tmp/report
}

sbx() { docker exec rsolv-sbx sh -c "$1"; }
code() { if sbx "$1" >/dev/null 2>&1; then echo 0; else echo $?; fi; }

probe() { # $1 = copy dir, $2 = out.json
  start_proxy "$here/allowlist/common.txt"
  start_sandbox "$PROBE_IMAGE" "$1"
  local env_names uid sock pid1 direct dns allowed denied default_dns offline
  env_names=$(sbx 'env | cut -d= -f1 | sort' | jq -R . | jq -s .)
  uid=$(sbx 'id -u')
  sock=$(sbx 'test -e /var/run/docker.sock && echo present || echo absent')
  pid1=$(sbx 'tr "\0" " " < /proc/1/cmdline')
  direct=$(code 'curl -sS -m 5 --noproxy "*" https://example.com')
  dns=$(code 'getent hosts example.com')
  allowed=$(sbx 'curl -sS -m 10 -o /dev/null -w "%{http_code}" https://api.github.com/zen' || true)
  denied=$(code 'curl -sS -m 10 -o /dev/null https://example.com')
  if docker run --rm --network rsolv-net --entrypoint getent "$PROBE_IMAGE" hosts example.com >/dev/null 2>&1; then default_dns=0; else default_dns=$?; fi
  docker network disconnect rsolv-net rsolv-sbx
  offline=$(code 'curl -sS -m 5 https://api.github.com/zen')
  jq -n --argjson env_names "$env_names" --arg uid "$uid" --arg sock "$sock" --arg pid1 "$pid1" \
    --arg direct "$direct" --arg dns "$dns" --arg allowed "$allowed" --arg denied "$denied" \
    --arg default_dns "$default_dns" --arg offline "$offline" \
    '{sandbox: {env_names: $env_names, uid: $uid, docker_sock: $sock, pid1: ($pid1 | rtrimstr(" "))},
      egress: {direct_exit: $direct, dns_exit: $dns, allowed_status: $allowed, denied_exit: $denied,
               offline_exit: $offline, default_dns_exit: $default_dns}}' > "$2"
}

ecosystem() { # $1 = eco, $2 = copy dir, $3 = out.json
  local eco=$1 image format install_exit=0 test_exit=0 allowlist="$RUNNER_TEMP/allowlist.txt"
  case $eco in
    node) image=$NODE_IMAGE format=jest ;;
    python) image=$PYTHON_IMAGE format=junit ;;
    ruby) image=$RUBY_IMAGE format=rspec ;;
    elixir) image=$ELIXIR_IMAGE format=exunit ;;
    java) image=$JAVA_IMAGE format=junit ;;
    php) image=$PHP_IMAGE format=junit ;;
    *) echo "unknown ecosystem $eco" >&2; return 1 ;;
  esac
  cat "$here/allowlist/common.txt" "$here/allowlist/$eco.txt" > "$allowlist"
  start_proxy "$allowlist"
  start_sandbox "$image" "$2"
  sbx "sh /rsolv/$eco.sh install" > "$RUNNER_TEMP/install.log" 2>&1 || install_exit=$?
  docker network disconnect rsolv-net rsolv-sbx
  sbx "sh /rsolv/$eco.sh test" > "$RUNNER_TEMP/test.log" 2>&1 || test_exit=$?
  sbx 'cat /tmp/report/report.* 2>/dev/null' > "$RUNNER_TEMP/report" || true
  docker exec rsolv-proxy cat /var/log/squid/access.log > "$RUNNER_TEMP/access.log" || true
  tail -n 40 "$RUNNER_TEMP/install.log" "$RUNNER_TEMP/test.log"
  jq -n --arg eco "$eco" --arg install_exit "$install_exit" --arg test_exit "$test_exit" \
    --arg format "$format" --rawfile report "$RUNNER_TEMP/report" \
    --argjson allowed "$(awk '$4 !~ /DENIED/ && $7 != "/" {print $7}' "$RUNNER_TEMP/access.log" | sort -u | jq -R . | jq -s .)" \
    --argjson denied "$(awk '$4 ~ /DENIED/ {print $7}' "$RUNNER_TEMP/access.log" | sort -u | jq -R . | jq -s .)" \
    '{ecosystem: $eco, install_exit: $install_exit, test_exit: $test_exit, report_format: $format,
      report: $report, allowed_hosts: $allowed, denied_hosts: $denied}' > "$3"
}

mode=$1; shift
case $mode in
  probe) probe "$@" ;;
  ecosystem) ecosystem "$@" ;;
  *) echo "usage: sandbox.sh probe|ecosystem ..." >&2; exit 2 ;;
esac
