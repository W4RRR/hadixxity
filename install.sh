#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="2025-11-14"
WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

banner(){
  cat <<'EOF'
H   H   AAAAA  DDDD   III  XXXXX  XXXXX  III  TTTTT  Y   Y
H   H   A   A  D   D   I   X   X X   X   I     T     Y Y
HHHHH   AAAAA  D   D   I    X X   X X    I     T      Y
H   H   A   A  D   D   I   X   X X   X   I     T      Y
H   H   A   A  DDDD   III  XXXXX  XXXXX  III    T      Y
EOF
}

info(){ echo -e "\033[36m[INFO]\033[0m $*"; }
ok(){   echo -e "\033[32m[OK]\033[0m   $*"; }
warn(){ echo -e "\033[33m[WARN]\033[0m $*"; }
die(){  echo -e "\033[31m[ERR]\033[0m  $*"; exit 1; }

ensure_package(){
  local pkg="$1"
  command -v "$pkg" >/dev/null 2>&1 && return 0
  if command -v apt >/dev/null 2>&1; then
    info "Instalando ${pkg} con apt..."
    sudo apt update -y && sudo apt install -y "$pkg"
  else
    warn "No se pudo instalar ${pkg} automáticamente; instálalo manualmente."
  fi
}

main(){
  banner
  info "Configurando Hadixxity (v${VERSION}) en ${WORKDIR}"

  ensure_package git
  ensure_package curl
  ensure_package dos2unix

  if [[ ! -f "${WORKDIR}/hadixxity.sh" ]]; then
    die "No encuentro hadixxity.sh en ${WORKDIR}. Ejecuta este script desde el directorio del repositorio."
  fi

  if [[ ! -f "${WORKDIR}/.hadixxity.env" ]]; then
    info "Copiando config.env.example a .hadixxity.env"
    cp "${WORKDIR}/config.env.example" "${WORKDIR}/.hadixxity.env"
  else
    warn ".hadixxity.env ya existe; no se sobreescribe."
  fi

  info "Normalizando finales de línea (dos2unix) en .hadixxity.env"
  dos2unix "${WORKDIR}/.hadixxity.env" >/dev/null 2>&1 || warn "dos2unix no pudo convertir .hadixxity.env (quizá ya está en LF)"

  info "Marcando scripts como ejecutables"
  chmod +x "${WORKDIR}/hadixxity.sh"
  chmod +x "${WORKDIR}/install.sh"

  info "Dependencias opcionales recomendadas: jq, subfinder, httpx, shodan"
  ok "Instalación base completada. Edita .hadixxity.env con tus API keys antes de ejecutar hadixxity.sh."
}

main "$@"

