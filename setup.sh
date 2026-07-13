#!/bin/bash
set -euo pipefail

# setup.sh - Install dependencies and configure mitmproxy CA trust
# Supports macOS (Homebrew) and Linux (apt/dnf)

echo "=== Grok Network Monitor - Setup ==="
echo ""

# Detect OS
OS="$(uname -s)"
echo "[*] Detected OS: $OS"

# Check for grok binary
GROK_BIN=""
if [[ -x "$HOME/.grok/bin/grok" ]]; then
    GROK_BIN="$HOME/.grok/bin/grok"
elif command -v grok &>/dev/null; then
    GROK_BIN="$(which grok)"
fi

if [[ -n "$GROK_BIN" ]]; then
    echo "[+] Found grok binary: $GROK_BIN"
else
    echo "[!] WARNING: grok binary not found. Install it before running tests."
    echo "    Expected locations: ~/.grok/bin/grok or in PATH"
fi

# Install mitmproxy
echo ""
echo "[*] Installing mitmproxy..."

if [[ "$OS" == "Darwin" ]]; then
    if ! command -v brew &>/dev/null; then
        echo "[!] Homebrew not found. Install from https://brew.sh"
        exit 1
    fi
    if command -v mitmproxy &>/dev/null; then
        echo "[+] mitmproxy already installed: $(mitmproxy --version | head -1)"
    else
        brew install mitmproxy
        echo "[+] mitmproxy installed successfully"
    fi
elif [[ "$OS" == "Linux" ]]; then
    if command -v mitmproxy &>/dev/null; then
        echo "[+] mitmproxy already installed: $(mitmproxy --version | head -1)"
    else
        if command -v apt-get &>/dev/null; then
            sudo apt-get update && sudo apt-get install -y mitmproxy
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y mitmproxy
        else
            echo "[!] Package manager not detected. Install mitmproxy manually:"
            echo "    pip install mitmproxy"
            exit 1
        fi
        echo "[+] mitmproxy installed successfully"
    fi
else
    echo "[!] Unsupported OS: $OS"
    exit 1
fi

# Install Python dependencies (for protobuf decoding)
echo ""
echo "[*] Installing Python dependencies..."
pip3 install --quiet protobuf 2>/dev/null || pip install --quiet protobuf 2>/dev/null || true
echo "[+] Python dependencies ready"

# CA Certificate trust
echo ""
echo "=== CA Certificate Setup ==="
echo ""
echo "mitmproxy generates a CA certificate on first run."
echo "You need to trust it for HTTPS interception to work."
echo ""
echo "Steps:"
echo "  1. Run 'mitmproxy' once to generate the CA cert"
echo "  2. The cert is at: ~/.mitmproxy/mitmproxy-ca-cert.pem"
echo ""

if [[ "$OS" == "Darwin" ]]; then
    echo "  macOS trust:"
    echo "    sudo security add-trusted-cert -d -r trustRoot \\"
    echo "      -k /Library/Keychains/System.keychain \\"
    echo "      ~/.mitmproxy/mitmproxy-ca-cert.pem"
elif [[ "$OS" == "Linux" ]]; then
    echo "  Linux trust (Debian/Ubuntu):"
    echo "    sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt"
    echo "    sudo update-ca-certificates"
fi

echo ""
echo "  Alternatively, set these env vars to skip OS trust:"
echo "    export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem"
echo "    export REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem"
echo ""

# Create capture directory
CAPTURE_DIR="$(dirname "$0")/captures"
mkdir -p "$CAPTURE_DIR"
echo "[+] Created captures directory: $CAPTURE_DIR"

# Create default markers file
MARKERS_FILE="$CAPTURE_DIR/markers.txt"
if [[ ! -f "$MARKERS_FILE" ]]; then
    cat > "$MARKERS_FILE" << 'EOF'
# markers.txt - One secret/canary string per line
# These are searched for in outbound request bodies during tests
# Lines starting with # are ignored
AKIAIOSFODNN7EXAMPLE
sk_test_FAKEFAKEFAKEFAKEFAKE
sk-proj-FAKE-openai-key-1234567890
super_secret_database_password_12345
NEVER_READ_PROBE_ae4f92c1
production-api-key-do-not-share
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
EOF
    echo "[+] Created default markers file: $MARKERS_FILE"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Quick start:"
echo "  1. Trust the CA cert (see above)"
echo "  2. ./scripts/run-tests.sh       # Create/rebuild the canary fixture and run all monitoring tests"
echo "  3. ./scripts/make-canary.sh     # Optional: rebuild only the canary fixture"
echo ""
