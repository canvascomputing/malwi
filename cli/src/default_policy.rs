//! Embedded default security policy YAML.
//!
//! Observe-mode policy: nothing is blocked. Uses `warn:` for credential/secret
//! access and `log:` for general network/command visibility.

pub const DEFAULT_SECURITY_YAML: &str = r#"
version: 1

# Native symbols (C/system functions)
symbols:
  warn:
    - getpass
    - crypt

# Python functions
python:
  warn:
    - getpass.getpass
    - keyring.get_password
    - keyring.set_password
    - ctypes.CDLL
    - ctypes.cdll.LoadLibrary
  log:
    - socket.create_connection
    - socket.socket.connect
    - urllib.request.urlopen
    - "requests.Session.request"
    - "http.client.HTTPConnection.request"
    - "http.client.HTTPSConnection.request"
    - ssl.wrap_socket
    - ssl.SSLContext.wrap_socket

# Node.js functions
nodejs:
  log:
    - dns.lookup
    - dns.resolve
    - net.connect
    - tls.connect
    - fetch
    - "http.request"
    - "https.request"
    - "http.get"
    - "https.get"

# Executed commands
commands:
  warn:
    - sudo
    - su
    - doas
    - ssh
    - scp
    - sftp
    - nc
    - ncat
    - socat
    - telnet
    - base64
    - xxd
    - crontab
    - launchctl
    - systemctl
  log:
    - curl
    - wget
    - git
    - npm
    - pip
    - gem
    - cargo
    - docker
    - nmap

# Warn on cloud metadata endpoints (SSRF indicators)
# Warn on suspicious TLDs and anonymity networks
# Log all other network traffic
network:
  warn:
    - "169.254.169.254/**"
    - "metadata.google.internal/**"
    - "*.onion"
    - "*.i2p"
    - "*.bit"
    - "*.loki"
  log:
    - "*"
    - "*/**"
    - "*:*"

# Warn on access to sensitive files
files:
  warn:
    - "~/.ssh/**"
    - "*/.ssh/**"
    - "~/.aws/**"
    - "*/.aws/**"
    - "~/.config/gcloud/**"
    - "~/.azure/**"
    - "~/.gnupg/**"
    - "~/.config/gh/**"
    - "*/.kube/config"
    - "*.pem"
    - "*.key"
    - "*id_rsa*"
    - "*id_ed25519*"

# Warn on access to sensitive environment variables
envvars:
  warn:
    - "*SECRET*"
    - "*TOKEN*"
    - "*PASSWORD*"
    - "*API_KEY*"
    - "*PRIVATE_KEY*"
    - "AWS_*"
    - "GITHUB_*"
    - "GCP_*"
    - "AZURE_*"
    - "OPENAI_*"
    - "ANTHROPIC_*"
    - HF_TOKEN
    - DYLD_INSERT_LIBRARIES
    - LD_PRELOAD
"#;
