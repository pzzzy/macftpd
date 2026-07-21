#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/macftpd}"
VAR_DIR="${VAR_DIR:-${APP_DIR}/var}"
CONFIG_PATH="${CONFIG_PATH:-${APP_DIR}/config.json}"
REPORT_DIR="${REPORT_DIR:-${VAR_DIR}/reports}"
WINDOW_DAYS="${WINDOW_DAYS:-7}"
HOST="${HOST:-127.0.0.1}"
HTTP_PORT="${HTTP_PORT:-8080}"
FTP_PORT="${FTP_PORT:-2121}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_PATH="${REPORT_PATH:-${REPORT_DIR}/weekly-${STAMP}.md}"

mkdir -p "${REPORT_DIR}"

storage_root="$(
  python3 - "${CONFIG_PATH}" <<'PY' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.load(f).get("storage", {}).get("root", ""))
except Exception:
    pass
PY
)"

{
  printf '# macftpd weekly report\n\n'
  printf -- '- generated_utc: `%s`\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf -- '- window_days: `%s`\n' "${WINDOW_DAYS}"
  printf -- '- app_dir: `%s`\n' "${APP_DIR}"
  if [[ -n "${storage_root}" ]]; then
    printf -- '- storage_root: `%s`\n' "${storage_root}"
  fi
  printf '\n## Health\n\n'
  if curl -fsS --max-time 10 "http://${HOST}:${HTTP_PORT}/healthz" >/tmp/macftpd-weekly-health.$$ 2>/tmp/macftpd-weekly-health-err.$$; then
    printf -- '- local_http: ok `%s`\n' "$(cat /tmp/macftpd-weekly-health.$$)"
  else
    printf -- '- local_http: failed `%s`\n' "$(cat /tmp/macftpd-weekly-health-err.$$ 2>/dev/null || true)"
  fi
  rm -f /tmp/macftpd-weekly-health.$$ /tmp/macftpd-weekly-health-err.$$
  if command -v cloudflared >/dev/null 2>&1; then
    printf -- '- system_cloudflared: `%s`\n' "$(cloudflared --version 2>/dev/null || true)"
  elif [[ -x "${APP_DIR}/bin/cloudflared" ]]; then
    printf -- '- bundled_cloudflared: `%s`\n' "$("${APP_DIR}/bin/cloudflared" --version 2>/dev/null || true)"
  fi
  if [[ -x "${APP_DIR}/bin/macftpd" ]]; then
    printf -- '- bundled_macftpd: present\n'
  fi
  printf '\n## Disk\n\n'
  if [[ -n "${storage_root}" && -d "${storage_root}" ]]; then
    df -h "${storage_root}" | sed 's/^/- /'
    du -sh "${storage_root}/._macftpd_trash" "${storage_root}/._macftpd_versions" 2>/dev/null | sed 's/^/- /' || true
  else
    printf -- '- storage_root unavailable\n'
  fi
  printf '\n## Activity\n\n'
  python3 - "${VAR_DIR}" "${WINDOW_DAYS}" <<'PY'
import collections
import datetime as dt
import gzip
import json
import pathlib
import re
import sys

var_dir = pathlib.Path(sys.argv[1])
window_days = int(sys.argv[2])
cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=window_days)
paths = [var_dir / "activity.jsonl"]
paths.extend(sorted(var_dir.glob("activity.jsonl.*.gz")))

counts = collections.Counter()
monitor_counts = collections.Counter()
failures = collections.Counter()
cancellations = collections.Counter()
monitor_failures = collections.Counter()
bytes_by_action = collections.Counter()
paths_by_action = collections.Counter()
first = None
last = None
total = 0
monitor_total = 0
maintenance_total = 0
human_total = 0

def parse_time(value):
    if not value:
        return None
    value = value.replace("Z", "+00:00")
    match = re.match(r"(.*\.)(\d+)([+-]\d\d:\d\d)$", value)
    if match:
        value = match.group(1) + (match.group(2) + "000000")[:6] + match.group(3)
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed

def is_loopback(remote):
    host = str(remote or "").strip()
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]
    return host in ("127.0.0.1", "::1", "localhost")

def is_monitor_event(event):
    path_value = str(event.get("path") or "").lstrip("/")
    dest_value = str(event.get("dest_path") or "").lstrip("/")
    if path_value == "_monitor" or path_value.startswith("_monitor/"):
        return True
    if dest_value == "_monitor" or dest_value.startswith("_monitor/"):
        return True
    detail = f"{event.get('detail') or ''} {event.get('message') or ''}".lower()
    if "monitor" in detail:
        return True
    return (
        event.get("type") == "ftp_login"
        and event.get("protocol") == "ftp"
        and event.get("action") == "login"
        and event.get("actor") == "admin"
        and path_value in ("",)
        and is_loopback(event.get("remote"))
    )

def is_maintenance_probe_event(event):
    return (
        event.get("type") == "http_login"
        and event.get("protocol") == "http"
        and event.get("action") == "login"
        and event.get("outcome") == "failed"
        and event.get("path") == "/api/activity"
        and is_loopback(event.get("remote"))
    )

for path in paths:
    if not path.exists():
        continue
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                when = parse_time(event.get("time"))
                if when is None or when < cutoff:
                    continue
                total += 1
                first = when if first is None or when < first else first
                last = when if last is None or when > last else last
                action = event.get("action") or "unknown"
                outcome = event.get("outcome") or event.get("status") or "unknown"
                monitor = is_monitor_event(event)
                maintenance = is_maintenance_probe_event(event)
                if monitor:
                    monitor_total += 1
                    monitor_counts[(action, outcome)] += 1
                elif maintenance:
                    maintenance_total += 1
                else:
                    human_total += 1
                    counts[(action, outcome)] += 1
                try:
                    detail = event.get("detail") or {}
                    if isinstance(detail, dict):
                        size = detail.get("bytes") or detail.get("size") or 0
                    else:
                        size = event.get("bytes") or 0
                    if not monitor and not maintenance:
                        bytes_by_action[action] += int(size or 0)
                except (TypeError, ValueError):
                    pass
                if outcome in ("canceled", "cancelled"):
                    if not monitor and not maintenance:
                        cancellations[(action, event.get("detail") or "canceled")] += 1
                elif outcome not in ("ok", "success"):
                    if monitor:
                        monitor_failures[(action, event.get("detail") or "failed")] += 1
                    elif not maintenance:
                        failures[(action, event.get("detail") or "failed")] += 1
                path_value = event.get("path") or ""
                if not monitor and not maintenance and path_value:
                    paths_by_action[(action, path_value)] += 1
    except OSError:
        continue

print(f"- total_events: `{total}`")
print(f"- human_visible_events: `{human_total}`")
print(f"- monitor_events: `{monitor_total}`")
print(f"- maintenance_probe_events: `{maintenance_total}`")
if first and last:
    print(f"- first_event: `{first.isoformat()}`")
    print(f"- last_event: `{last.isoformat()}`")
for (action, status), count in counts.most_common():
    print(f"- {action}.{status}: `{count}`")
for action, size in bytes_by_action.most_common():
    if size:
        print(f"- {action}_bytes: `{size}`")
if failures:
    print("\n### Failures\n")
    for (action, detail), count in failures.most_common(10):
        detail = str(detail).replace("`", "'")
        print(f"- {action}: `{count}` `{detail[:160]}`")
if cancellations:
    print("\n### Client Cancellations\n")
    for (action, detail), count in cancellations.most_common(10):
        detail = str(detail).replace("`", "'")
        print(f"- {action}: `{count}` `{detail[:160]}`")
if monitor_counts:
    print("\n### Monitor Summary\n")
    for (action, status), count in monitor_counts.most_common():
        print(f"- {action}.{status}: `{count}`")
if monitor_failures:
    print("\n### Monitor Failures\n")
    for (action, detail), count in monitor_failures.most_common(10):
        detail = str(detail).replace("`", "'")
        print(f"- {action}: `{count}` `{detail[:160]}`")
if paths_by_action:
    print("\n### Busiest Paths\n")
    for (action, path_value), count in paths_by_action.most_common(12):
        print(f"- {action}: `{count}` `{str(path_value).replace('`', chr(39))}`")
PY
  printf '\n## Launchd\n\n'
  for label in com.example.macftpd com.example.macftpd-cloudflared com.example.macftpd-monitor com.example.macftpd-logrotate com.example.macftpd-weekly-report com.example.macftpd.cert-renew; do
    if launchctl print "gui/$(id -u)/${label}" >/tmp/macftpd-weekly-launchd.$$ 2>/dev/null; then
      state="$(awk -F'= ' '/state = / {print $2; exit}' /tmp/macftpd-weekly-launchd.$$)"
      pid="$(awk -F'= ' '/pid = / {print $2; exit}' /tmp/macftpd-weekly-launchd.$$)"
      exit_status="$(awk -F'= ' '/last exit code = / {print $2; exit}' /tmp/macftpd-weekly-launchd.$$)"
      printf -- '- %s: state=`%s` pid=`%s` last_exit=`%s`\n' "${label}" "${state:-unknown}" "${pid:-}" "${exit_status:-}"
    else
      printf -- '- %s: unavailable\n' "${label}"
    fi
    rm -f /tmp/macftpd-weekly-launchd.$$
  done
  printf '\n## Recent Error Log Signals\n\n'
  for path in "${VAR_DIR}/macftpd.launchd.err.log" "${VAR_DIR}/cloudflared.launchd.err.log" "${VAR_DIR}/monitor.launchd.err.log" "${VAR_DIR}/cert-renew.err.log"; do
    [[ -f "${path}" ]] || continue
    printf '### %s\n\n' "$(basename "${path}")"
    tail -80 "${path}" | grep -Ei 'error|fail|denied|reset|timeout|panic|fatal|warn' | tail -20 | sed 's/^/- `/' | sed 's/$/`/' || printf -- '- no recent matching lines\n'
    printf '\n'
  done
} >"${REPORT_PATH}"

printf '%s\n' "${REPORT_PATH}"
