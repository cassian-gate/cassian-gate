#!/usr/bin/env bash
set -euo pipefail

# vm_health_check.sh
# Preflight health check for ai-netsim runtime hosts (Ubuntu VM / Hyper-V).
#
# Catches the exact issues we hit during setup:
# - Docker socket activation mismatch (dockerd -H fd:// but docker.socket inactive)
# - Docker daemon not reachable / user not in docker group
# - KVM missing or permission issues (/dev/kvm, kvm group)
# - Missing br_netfilter -> missing /proc/sys/net/bridge/* -> fw container sysctl failure
# - containerlab present
# - Optional GHCR pull test (private images auth)
#
# Usage:
#   vm_health_check.sh
#   vm_health_check.sh --ghcr ghcr.io/cassian-gate/nft-fw:latest
#   vm_health_check.sh --quick
#
# Env:
#   NETSIM_GHCR_TEST_IMAGE=...   (alternative to --ghcr)

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
fail=0

GHCR_TEST_IMAGE="${NETSIM_GHCR_TEST_IMAGE:-}"
QUICK=0

usage() {
  cat <<'USAGE'
ai-netsim VM health check

Usage:
  vm_health_check.sh [--quick] [--ghcr <image>] [--help]

Options:
  --quick           Run core checks only (less output).
  --ghcr <image>    Attempt "docker pull <image>" to validate GHCR auth/existence.
                    Useful when images are private (requires prior docker login).
  --help            Show this help.

Env:
  NETSIM_GHCR_TEST_IMAGE=<image>   Alternative to --ghcr.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --quick) QUICK=1; shift ;;
    --ghcr)
      [[ $# -ge 2 ]] || { echo "ERROR: --ghcr requires an image argument" >&2; exit 2; }
      GHCR_TEST_IMAGE="$2"
      shift 2
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

ok()   { echo "${GREEN}OK${RESET}: $*"; }
warn() { echo "${YELLOW}WARN${RESET}: $*"; }
bad()  { echo "${RED}FAIL${RESET}: $*"; fail=1; }

section() { echo; echo "=== $* ==="; }

need_cmd() {
  local c="$1"
  if ! command -v "$c" >/dev/null 2>&1; then
    bad "missing command: $c"
    return 1
  fi
  ok "found command: $c"
  return 0
}

check_group() {
  local g="$1"
  if id -nG "$USER" | tr ' ' '\n' | grep -qx "$g"; then
    ok "user '$USER' in group '$g'"
  else
    warn "user '$USER' not in group '$g' (may cause permission issues)"
  fi
}

is_active() { systemctl is-active --quiet "$1"; }
is_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }

require_systemd() {
  if ! command -v systemctl >/dev/null 2>&1; then
    bad "systemctl not found. This script expects a systemd-based host (typical for Ubuntu VM)."
    return 1
  fi
  return 0
}

check_sudo() {
  section "sudo readiness"
  if sudo -n true >/dev/null 2>&1; then
    ok "sudo non-interactive available (no password prompt right now)"
  else
    warn "sudo may prompt for password during verify"
    warn "Tip: run 'sudo -v' before long scripts to cache credentials"
  fi
}

check_kvm() {
  section "KVM (/dev/kvm) + permissions"
  if [[ -e /dev/kvm ]]; then
    ok "/dev/kvm exists"
    ls -l /dev/kvm || true
  else
    bad "/dev/kvm missing (KVM not available). Fix: enable Hyper-V nested virt + install qemu-kvm."
    warn "Hyper-V host: Set-VMProcessor -VMName '<VM>' -ExposeVirtualizationExtensions \$true"
    return
  fi

  check_group kvm

  if grep -Eqi '(vmx|svm)' /proc/cpuinfo; then
    ok "CPU virtualization flag present (vmx/svm)"
  else
    warn "CPU virtualization flag not detected in /proc/cpuinfo (may still work, but suspicious)"
  fi
}

check_containerd_presence() {
  # containerd may not always appear as an obvious standalone unit depending on packaging.
  # Consider it present if any of these indicate it's running/available.
  if systemctl list-unit-files 2>/dev/null | grep -q '^containerd\.service'; then
    if is_active containerd.service; then
      ok "containerd.service active"
      return 0
    else
      warn "containerd.service exists but is not active"
      # fall through
    fi
  fi

  if [[ -S /run/containerd/containerd.sock ]]; then
    ok "containerd socket present: /run/containerd/containerd.sock"
    return 0
  fi

  if pgrep -x containerd >/dev/null 2>&1; then
    ok "containerd process running"
    return 0
  fi

  warn "containerd not detected via unit/socket/process (may still be OK if Docker bundles it differently)"
  return 0
}

check_docker() {
  section "Docker + socket activation (fd://) + daemon access"
  need_cmd docker || return

  require_systemd || return

  check_containerd_presence

  if is_enabled docker.service; then ok "docker.service enabled"; else warn "docker.service not enabled"; fi

  local execstart
  execstart="$(systemctl show -p ExecStart docker.service | sed 's/^ExecStart=//')"

  if echo "$execstart" | grep -q 'fd://'; then
    ok "docker.service uses socket activation (fd://)"
    if is_active docker.socket; then
      ok "docker.socket active"
    else
      bad "docker.socket is NOT active but docker.service uses fd:// (causes: 'no sockets found via socket activation')"
      warn "Fix:"
      warn "  sudo systemctl enable --now docker.socket"
      warn "  sudo systemctl reset-failed docker.service"
      warn "  sudo systemctl restart docker.service"
    fi
  else
    warn "docker.service does not appear to use fd:// (socket activation). OK if binds directly to /run/docker.sock."
  fi

  if is_active docker.service; then
    ok "docker.service active"
  else
    bad "docker.service NOT active"
    warn "Inspect: sudo journalctl -u docker.service -n 200 --no-pager"
  fi

  if docker version >/dev/null 2>&1; then
    ok "docker CLI can talk to daemon"
  else
    bad "docker CLI cannot talk to daemon"
    warn "Common fix:"
    warn "  sudo usermod -aG docker \$USER && newgrp docker"
    warn "Or run as root to test:"
    warn "  sudo docker ps"
  fi

  check_group docker
}

check_containerlab() {
  section "containerlab"
  need_cmd containerlab || return
  if containerlab version >/dev/null 2>&1; then
    ok "containerlab runs"
    if [[ "$QUICK" -eq 0 ]]; then
      containerlab version || true
    fi
  else
    bad "containerlab not working"
  fi
}

check_bridge_netfilter() {
  section "Bridge netfilter (br_netfilter) + required sysctl files/values"
  need_cmd sysctl || return

  if lsmod | grep -q '^br_netfilter'; then
    ok "br_netfilter module loaded"
  else
    warn "br_netfilter not loaded (this previously caused fw container start failure)"
    warn "Fix:"
    warn "  sudo modprobe br_netfilter"
    warn "  echo br_netfilter | sudo tee /etc/modules-load.d/br_netfilter.conf"
  fi

  if [[ -d /proc/sys/net/bridge ]]; then
    ok "/proc/sys/net/bridge exists"
  else
    bad "/proc/sys/net/bridge missing (br_netfilter not available/loaded)"
    warn "Fix: sudo modprobe br_netfilter"
    return
  fi

  if [[ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
    ok "sysctl file exists: bridge-nf-call-iptables"
  else
    bad "missing /proc/sys/net/bridge/bridge-nf-call-iptables"
    warn "Fix: sudo modprobe br_netfilter"
  fi

  if [[ -f /proc/sys/net/bridge/bridge-nf-call-ip6tables ]]; then
    ok "sysctl file exists: bridge-nf-call-ip6tables"
  else
    bad "missing /proc/sys/net/bridge/bridge-nf-call-ip6tables (this caused OCI runtime failure earlier)"
    warn "Fix: sudo modprobe br_netfilter"
  fi

  local v4 v6
  v4="$(sysctl -n net.bridge.bridge-nf-call-iptables 2>/dev/null || echo 'ERR')"
  v6="$(sysctl -n net.bridge.bridge-nf-call-ip6tables 2>/dev/null || echo 'ERR')"

  if [[ "$v4" == "1" ]]; then ok "net.bridge.bridge-nf-call-iptables = 1"; else warn "net.bridge.bridge-nf-call-iptables = $v4 (recommended 1)"; fi
  if [[ "$v6" == "1" ]]; then ok "net.bridge.bridge-nf-call-ip6tables = 1"; else warn "net.bridge.bridge-nf-call-ip6tables = $v6 (recommended 1)"; fi

  [[ -f /etc/modules-load.d/br_netfilter.conf ]] && ok "persistent module load configured: /etc/modules-load.d/br_netfilter.conf" \
    || warn "no /etc/modules-load.d/br_netfilter.conf (module may not persist after reboot)"

  [[ -f /etc/sysctl.d/99-bridge-nf.conf ]] && ok "persistent sysctls configured: /etc/sysctl.d/99-bridge-nf.conf" \
    || warn "no /etc/sysctl.d/99-bridge-nf.conf (sysctls may not persist after reboot)"
}

check_runtime_essentials() {
  section "Runtime essentials"
  need_cmd python3 || return
  if [[ "$QUICK" -eq 0 ]]; then
    python3 --version || true
  fi

  if command -v ip >/dev/null 2>&1; then ok "found command: ip"; [[ "$QUICK" -eq 0 ]] && ip -V || true; else warn "missing 'ip' (iproute2)"; fi
  if command -v jq >/dev/null 2>&1; then ok "found command: jq"; [[ "$QUICK" -eq 0 ]] && jq --version || true; else warn "missing 'jq' (some scripts may rely on it)"; fi
  if command -v git >/dev/null 2>&1; then ok "found command: git"; [[ "$QUICK" -eq 0 ]] && git --version || true; else warn "missing 'git'"; fi
}

check_ghcr_pull() {
  section "Optional GHCR pull test (auth + existence)"
  if [[ -z "$GHCR_TEST_IMAGE" ]]; then
    warn "no GHCR test image set; skipping"
    echo "      Tip: --ghcr ghcr.io/cassian-gate/nft-fw:latest"
    return
  fi

  echo "Attempting: docker pull $GHCR_TEST_IMAGE"
  if docker pull "$GHCR_TEST_IMAGE" >/dev/null 2>&1; then
    ok "docker pull succeeded: $GHCR_TEST_IMAGE"
  else
    bad "docker pull failed: $GHCR_TEST_IMAGE"
    warn "If private, login once:"
    warn "  echo '<TOKEN>' | docker login ghcr.io -u <USERNAME> --password-stdin"
  fi
}

main() {
  section "Host info"
  echo "User: $USER"
  echo "Kernel: $(uname -a)"
  echo "OS: $( (lsb_release -ds 2>/dev/null) || true )"
  echo "Time: $(date)"

  check_sudo
  check_kvm
  check_docker
  check_containerlab
  check_bridge_netfilter
  check_runtime_essentials
  check_ghcr_pull

  section "Summary"
  if [[ $fail -eq 0 ]]; then
    echo "${GREEN}✅ HEALTH CHECK PASS${RESET}"
    exit 0
  else
    echo "${RED}❌ HEALTH CHECK FAIL${RESET} (see messages above)"
    exit 1
  fi
}

main "$@"
