# Maintainer: Ovenoboyo <your-email@example.com>
pkgname=bw-ssh-agent
_repo=bw-ssh-agent
pkgver=0.1.0
pkgrel=1
pkgdesc="Hardened SSH agent backed by Bitwarden CLI with Polkit and Pinentry support"
arch=('x86_64' 'aarch64')
url="https://github.com/Ovenoboyo/${_repo}"
license=('MIT')
depends=(
  'bitwarden-cli'
  'polkit'
)
optdepends=(
  'pinentry: native GUI/curses password dialogs'
  'gnome-keyring: libsecret session persistence'
  'kwallet: KDE Wallet session persistence'
  'zenity: GTK fallback password dialog'
  'kdialog: KDE fallback password dialog'
)
makedepends=('go')
source=("${pkgname}-${pkgver}.tar.gz::${url}/archive/refs/tags/v${pkgver}.tar.gz")
sha256sums=('SKIP')

prepare() {
  cd "${srcdir}/${_repo}-${pkgver}"
  export GOPATH="${srcdir}/go"
  go mod download -x
}

build() {
  cd "${srcdir}/${_repo}-${pkgver}"
  export CGO_ENABLED=0
  export GOPATH="${srcdir}/go"
  export GOFLAGS="-buildmode=pie -trimpath -mod=readonly -modcacherw"

  go build -ldflags="-s -w -linkmode=external" -o "${pkgname}" ./cmd
}

package() {
  cd "${srcdir}/${_repo}-${pkgver}"

  install -Dm755 "${pkgname}" "${pkgdir}/usr/bin/${pkgname}"

  install -Dm644 /dev/stdin "${pkgdir}/usr/lib/systemd/user/bw-ssh-agent.service" << 'EOF'
[Unit]
Description=Bitwarden CLI SSH Agent
Documentation=https://github.com/Ovenoboyo/bw-ssh-agent
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart=/usr/bin/bw-ssh-agent
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2

NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=graphical-session.target
EOF

  install -Dm644 /dev/stdin "${pkgdir}/usr/lib/environment.d/90-bw-ssh-agent.conf" << 'EOF'
SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/bw-ssh-agent.sock
EOF

  if [ -f LICENSE ]; then
    install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
  fi
}