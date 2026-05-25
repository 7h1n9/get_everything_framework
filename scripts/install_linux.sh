#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REQUIREMENTS_FILE="$ROOT_DIR/requirement.txt"
LOCAL_TOOLS_DIR="$ROOT_DIR/tools"

CHECK_ONLY=0
SKIP_SYSTEM=0
SKIP_PYTHON_DEPS=0
SKIP_GO_TOOLS=0
WITH_OPTIONAL=0
DRY_RUN=0

GO_TOOLS=(
  "subfinder=github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "shuffledns=github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "alterx=github.com/projectdiscovery/alterx/cmd/alterx@latest"
  "gospider=github.com/jaeles-project/gospider@latest"
  "dnsx=github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "httpx=github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "naabu=github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "waybackurls=github.com/tomnomnom/waybackurls@latest"
  "katana=github.com/projectdiscovery/katana/cmd/katana@latest"
  "assetfinder=github.com/tomnomnom/assetfinder@latest"
)

EXPECTED_TOOLS=(
  alterx amass assetfinder dirsearch dnsx feroxbuster gospider httpx http-x
  katana naabu nmap shuffledns subfinder waybackurls
)

usage() {
  cat <<'EOF'
Usage: bash scripts/install_linux.sh [options]

Options:
  --check-only        Only check installed tools.
  --skip-system      Skip OS package installation.
  --skip-python-deps Skip Python dependency installation.
  --skip-go-tools    Skip Go recon tool installation.
  --with-optional    Install Rust/feroxbuster and clone dirsearch.
  --dry-run          Print commands without executing them.
  -h, --help         Show this help.
EOF
}

run() {
  echo "[*] $*"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    "$@"
  fi
}

exists() {
  command -v "$1" >/dev/null 2>&1
}

sudo_cmd() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  elif exists sudo; then
    sudo "$@"
  else
    echo "[!] This step requires root privileges or sudo: $*" >&2
    return 1
  fi
}

run_root() {
  echo "[*] $*"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    sudo_cmd "$@"
  fi
}

python_cmd() {
  if exists python3; then
    echo "python3"
  elif exists python; then
    echo "python"
  else
    echo ""
  fi
}

pip_install_user() {
  local py="$1"
  shift

  if run "$py" -m pip install --user "$@"; then
    return 0
  fi

  echo "[i] pip rejected user-site installation; retrying with --break-system-packages."
  run "$py" -m pip install --user --break-system-packages "$@"
}

go_bin() {
  if [[ -n "${GOBIN:-}" ]]; then
    echo "$GOBIN"
  elif exists go; then
    echo "$(go env GOPATH)/bin"
  else
    echo "$HOME/go/bin"
  fi
}

add_go_path() {
  local bin_path
  bin_path="$(go_bin)"
  export PATH="$PATH:$bin_path"

  local profile="$HOME/.profile"
  local line='export PATH="$PATH:$HOME/go/bin"'
  if [[ "$bin_path" == "$HOME/go/bin" && -f "$profile" ]]; then
    if ! grep -Fq "$line" "$profile"; then
      echo "[*] Add Go bin to $profile"
      if [[ "$DRY_RUN" -eq 0 ]]; then
        printf '\n# Go user binaries\n%s\n' "$line" >> "$profile"
      fi
    fi
  fi
}

resolve_tool_path() {
  command -v "$1" 2>/dev/null || true
}

ensure_httpx_alias() {
  local bin_path target alias_path
  bin_path="$(go_bin)"
  target="$bin_path/httpx"
  alias_path="$bin_path/http-x"

  if [[ ! -f "$target" ]]; then
    echo "[!] ProjectDiscovery httpx was not found at: $target"
    return 1
  fi

  echo "[*] Create http-x alias: $alias_path"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    cat >"$alias_path" <<EOF
#!/usr/bin/env bash
"$target" "\$@"
EOF
    chmod +x "$alias_path"
  fi

  export PATH="$PATH:$bin_path"
}

go_tool_path() {
  local tool_name="$1"
  echo "$(go_bin)/$tool_name"
}

test_httpx_installation() {
  local bin_path expected_httpx expected_alias resolved_httpx resolved_alias
  bin_path="$(go_bin)"
  expected_httpx="$bin_path/httpx"
  expected_alias="$bin_path/http-x"
  resolved_httpx="$(resolve_tool_path httpx)"
  resolved_alias="$(resolve_tool_path http-x)"

  echo "[i] Expected ProjectDiscovery httpx: $expected_httpx"
  echo "[i] which httpx => ${resolved_httpx:-<missing>}"
  echo "[i] which http-x => ${resolved_alias:-<missing>}"

  [[ -f "$expected_httpx" ]] || { echo "[!] ProjectDiscovery httpx is missing."; return 1; }
  [[ -f "$expected_alias" ]] || { echo "[!] http-x alias is missing."; return 1; }
  [[ "$resolved_alias" == "$expected_alias" ]] || { echo "[!] http-x does not resolve to the expected alias path."; return 1; }

  if [[ -n "$resolved_httpx" && "$resolved_httpx" != "$expected_httpx" ]]; then
    echo "[!] httpx resolves to another executable. The project will use http-x instead."
  fi

  echo "[ok] ProjectDiscovery httpx alias is ready"
}

install_system_dependencies() {
  echo
  echo "=== System dependencies ==="

  if exists apt-get; then
    run_root apt-get update
    run_root apt-get install -y python3 python3-pip golang-go git nmap curl wget unzip ca-certificates
  elif exists dnf; then
    run_root dnf install -y python3 python3-pip golang git nmap curl wget unzip ca-certificates
  elif exists yum; then
    run_root yum install -y python3 python3-pip golang git nmap curl wget unzip ca-certificates
  elif exists pacman; then
    run_root pacman -Sy --needed --noconfirm python python-pip go git nmap curl wget unzip ca-certificates
  elif exists zypper; then
    run_root zypper install -y python3 python3-pip go git nmap curl wget unzip ca-certificates
  elif exists apk; then
    run_root apk add --no-cache python3 py3-pip go git nmap curl wget unzip ca-certificates
  else
    echo "[!] Unsupported package manager. Install python3, pip, go, git, nmap, curl, wget, and unzip manually."
  fi

  add_go_path
}

install_python_dependencies() {
  echo
  echo "=== Python dependencies ==="
  local py
  py="$(python_cmd)"
  if [[ -z "$py" ]]; then
    echo "[!] Python is not installed or not in PATH."
    return
  fi
  if [[ ! -f "$REQUIREMENTS_FILE" ]]; then
    echo "[!] Missing requirements file: $REQUIREMENTS_FILE"
    return
  fi
  pip_install_user "$py" --upgrade pip
  pip_install_user "$py" -r "$REQUIREMENTS_FILE"
}

install_amass() {
  echo
  echo "=== amass ==="
  if exists amass; then
    echo "[=] amass already exists in PATH"
    return
  fi

  if ! exists wget; then
    echo "[!] wget is required to install amass from GitHub."
    return
  fi

  if ! exists unzip; then
    echo "[!] unzip is required to install amass from GitHub."
    return
  fi

  local amass_url="https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip"
  local amass_zip="$LOCAL_TOOLS_DIR/amass_Linux_amd64.zip"
  local amass_extract_dir="$LOCAL_TOOLS_DIR/amass"
  local amass_bin="$amass_extract_dir/amass"

  run mkdir -p "$LOCAL_TOOLS_DIR"
  run wget "$amass_url" -O "$amass_zip"
  run mkdir -p "$amass_extract_dir"
  run unzip -o "$amass_zip" -d "$amass_extract_dir"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[i] Dry run: skip amass binary lookup and version check."
    return
  fi

  local found_bin=""
  if [[ -f "$amass_bin" ]]; then
    found_bin="$amass_bin"
  else
    found_bin="$(find "$amass_extract_dir" -type f -name amass 2>/dev/null | head -n 1 || true)"
  fi

  if [[ -z "$found_bin" ]]; then
    echo "[!] amass binary was not found after extracting: $amass_extract_dir"
    return
  fi

  run chmod +x "$found_bin"
  if [[ "$found_bin" != "$amass_bin" ]]; then
    run cp "$found_bin" "$amass_bin"
  fi

  export PATH="$PATH:$amass_extract_dir"

  local profile="$HOME/.profile"
  local line="export PATH=\"\$PATH:$amass_extract_dir\""
  if [[ -f "$profile" ]] && ! grep -Fq "$line" "$profile"; then
    echo "[*] Add amass to $profile"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      printf '\n# get_everything_framework tools\n%s\n' "$line" >> "$profile"
    fi
  fi

  if "$amass_bin" -version >/dev/null 2>&1; then
    "$amass_bin" -version
  else
    echo "[+] amass installed at: $amass_bin"
  fi
}

install_go_tools() {
  echo
  echo "=== Go tools ==="
  if ! exists go; then
    echo "[!] Go is not installed or not in PATH."
    return
  fi

  add_go_path

  local entry tool module
  for entry in "${GO_TOOLS[@]}"; do
    tool="${entry%%=*}"
    module="${entry#*=}"
    if [[ "$tool" == "httpx" ]]; then
      local expected_httpx
      expected_httpx="$(go_tool_path httpx)"
      if [[ -f "$expected_httpx" ]]; then
        echo "[=] httpx already installed in Go bin: $expected_httpx"
        continue
      fi

      echo "[*] Installing ProjectDiscovery httpx into Go bin"
      run go install "$module"
      continue
    fi

    if exists "$tool"; then
      echo "[=] $tool already exists in PATH"
      continue
    fi
    run go install "$module"
  done

  ensure_httpx_alias || true
  test_httpx_installation || true

  install_amass
}

install_optional_tools() {
  echo
  echo "=== Optional tools ==="

  if ! exists cargo; then
    if exists apt-get; then
      run_root apt-get install -y cargo
    elif exists dnf; then
      run_root dnf install -y cargo
    elif exists yum; then
      run_root yum install -y cargo
    elif exists pacman; then
      run_root pacman -S --needed --noconfirm rust
    elif exists zypper; then
      run_root zypper install -y cargo
    elif exists apk; then
      run_root apk add --no-cache cargo
    else
      echo "[!] Install Rust/Cargo manually to enable feroxbuster."
    fi
  fi

  if exists cargo; then
    if exists feroxbuster; then
      echo "[=] feroxbuster already exists in PATH"
    else
      run cargo install feroxbuster
    fi
  fi

  if ! exists git; then
    echo "[!] Git is required to install dirsearch."
    return
  fi

  local target="$LOCAL_TOOLS_DIR/dirsearch"
  if [[ -d "$target" ]]; then
    echo "[=] dirsearch repository already exists: $target"
  else
    run mkdir -p "$LOCAL_TOOLS_DIR"
    run git clone https://github.com/maurosoria/dirsearch.git "$target"
  fi

  local py
  py="$(python_cmd)"
  if [[ -n "$py" && -f "$target/requirements.txt" ]]; then
    pip_install_user "$py" -r "$target/requirements.txt"
  fi
}

verify_environment() {
  echo
  echo "=== Verification ==="
  local tool
  for tool in "${EXPECTED_TOOLS[@]}"; do
    if exists "$tool"; then
      echo "[ok] $tool"
    elif [[ "$tool" == "dirsearch" && -f "$LOCAL_TOOLS_DIR/dirsearch/dirsearch.py" ]]; then
      echo "[ok] dirsearch in tools/dirsearch"
    else
      echo "[--] $tool not found"
    fi
  done

  test_httpx_installation || true
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-only) CHECK_ONLY=1 ;;
    --skip-system) SKIP_SYSTEM=1 ;;
    --skip-python-deps) SKIP_PYTHON_DEPS=1 ;;
    --skip-go-tools) SKIP_GO_TOOLS=1 ;;
    --with-optional) WITH_OPTIONAL=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[!] Unknown argument: $1"; usage; exit 1 ;;
  esac
  shift
done

echo "get_everything_framework Linux installer"
echo "Project root: $ROOT_DIR"

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  verify_environment
  echo
  echo "Go bin: $(go_bin)"
  exit 0
fi

if [[ "$SKIP_SYSTEM" -eq 0 ]]; then
  install_system_dependencies
fi

if [[ "$SKIP_PYTHON_DEPS" -eq 0 ]]; then
  install_python_dependencies
fi

if [[ "$SKIP_GO_TOOLS" -eq 0 ]]; then
  install_go_tools
fi

if [[ "$WITH_OPTIONAL" -eq 1 ]]; then
  install_optional_tools
else
  echo
  echo "=== Optional tools skipped ==="
  echo "Run again with --with-optional to install Rust/feroxbuster and clone dirsearch."
fi

verify_environment
echo
echo "[+] Done. Restart the shell if newly installed commands are still not found."
