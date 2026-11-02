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
# Sandbox-controlled text reaches the Actions log only inside stop-commands, so it
# cannot issue workflow commands (::add-mask::, ::set-output:: and the like).
quoted() { local t rc=0; t=$(openssl rand -hex 16); echo "::stop-commands::$t"; "$@" || rc=$?; echo "::$t::"; return "$rc"; }
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
  echo "proxy did not start" >&2; quoted docker logs rsolv-proxy 2>&1 || true; return 1
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
code() { # exit status of a sandbox command; 125-127 are docker/tooling errors, not blocks
  local rc=0
  sbx "$1" >/dev/null 2>&1 || rc=$?
  case $rc in 125|126|127) echo "docker-error-$rc" ;; *) echo "$rc" ;; esac
}

probe() { # $1 = copy dir, $2 = out.json
  start_proxy "$here/allowlist/common.txt"
  start_sandbox "$PROBE_IMAGE" "$1"
  local env_names uid sock pid1 direct direct_ip dns allowed denied ip_via_proxy gw gateway default_dns offline
  env_names=$(sbx "env -0 | sed -z 's/=.*//' | tr '\\0' '\\n' | sort" | jq -R . | jq -s .)
  uid=$(sbx 'id -u')
  sock=$(sbx 'test -e /var/run/docker.sock && echo present || echo absent')
  pid1=$(sbx 'tr "\0" " " < /proc/1/cmdline')
  direct=$(code 'curl -sS -m 5 --noproxy "*" https://example.com')
  direct_ip=$(code 'curl -sS -m 5 --noproxy "*" https://1.1.1.1')
  dns=$(code 'getent hosts example.com')
  allowed=$(sbx 'curl -sS -m 10 -o /dev/null -w "%{http_code}" https://api.github.com/zen' || true)
  denied=$(sbx 'curl -s -m 10 -o /dev/null -w "%{http_connect}" https://example.com' || true)
  ip_via_proxy=$(sbx 'curl -s -m 10 -o /dev/null -w "%{http_connect}" https://1.1.1.1' || true)
  gw=$(docker network inspect rsolv-net -f '{{(index .IPAM.Config 0).Gateway}}')
  gateway=$(code "curl -sS -m 3 --noproxy \"*\" http://$gw:80/")
  if docker run --rm --network rsolv-net --entrypoint getent "$PROBE_IMAGE" hosts example.com >/dev/null 2>&1; then default_dns=0; else default_dns=$?; fi
  docker network disconnect rsolv-net rsolv-sbx
  sbx true
  offline=$(code 'curl -sS -m 5 https://api.github.com/zen')
  jq -n --argjson env_names "$env_names" --arg uid "$uid" --arg sock "$sock" --arg pid1 "$pid1" \
    --arg direct "$direct" --arg direct_ip "$direct_ip" --arg dns "$dns" --arg allowed "$allowed" \
    --arg denied "$denied" --arg ip_via_proxy "$ip_via_proxy" --arg gateway "$gateway" \
    --arg default_dns "$default_dns" --arg offline "$offline" \
    '{sandbox: {env_names: $env_names, uid: $uid, docker_sock: $sock, pid1: ($pid1 | rtrimstr(" "))},
      egress: {direct_exit: $direct, direct_ip_exit: $direct_ip, dns_exit: $dns, allowed_status: $allowed,
               denied_connect: $denied, ip_via_proxy_connect: $ip_via_proxy, gateway_exit: $gateway,
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
  sbx true
  sbx "sh /rsolv/$eco.sh test" > "$RUNNER_TEMP/test.log" 2>&1 || test_exit=$?
  sbx 'cat /tmp/report/report.* 2>/dev/null' > "$RUNNER_TEMP/report" || true
  docker exec rsolv-proxy cat /var/log/squid/access.log > "$RUNNER_TEMP/access.log" || true
  quoted tail -n 40 "$RUNNER_TEMP/install.log" "$RUNNER_TEMP/test.log"
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
