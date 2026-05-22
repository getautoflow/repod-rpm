#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# repod-cli.sh — CLI portable pour l'API repod (RPM)
# Compatible : GitHub Actions, GitLab CI, Jenkins, Drone, tout shell POSIX
#
# Usage :
#   ./repod-cli.sh login
#   ./repod-cli.sh upload <fichier.rpm> [distribution] [arch]
#   ./repod-cli.sh vulnerabilities [distribution]
#   ./repod-cli.sh sarif [distribution] [fichier-sortie.sarif.json]
#   ./repod-cli.sh packages [distribution]
#
# Variables d'environnement requises :
#   REPOD_URL       URL de l'instance repod (ex. https://repo.example.com)
#   REPOD_USERNAME  Nom d'utilisateur repod
#   REPOD_PASSWORD  Mot de passe repod
#
# Variable optionnelle (renseignée automatiquement par 'login') :
#   REPOD_TOKEN     JWT d'accès (si déjà obtenu, skip login)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Couleurs (désactivées si pas de terminal) ─────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; RESET=''
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

info()  { echo -e "${GREEN}[repod]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[repod]${RESET} $*" >&2; }
error() { echo -e "${RED}[repod] ERREUR${RESET} : $*" >&2; exit 1; }

_require_env() {
  for var in "$@"; do
    [ -n "${!var:-}" ] || error "Variable d'environnement requise non définie : $var"
  done
}

_api() {
  # Usage : _api GET /api/v1/packages  (retourne le corps JSON)
  local METHOD="$1"
  local PATH="$2"
  shift 2
  curl -sf -X "$METHOD" \
    -H "Authorization: Bearer $REPOD_TOKEN" \
    -H "Accept: application/json" \
    "$@" \
    "${REPOD_URL}${PATH}"
}

# ── Commande : login ──────────────────────────────────────────────────────────

cmd_login() {
  _require_env REPOD_URL REPOD_USERNAME REPOD_PASSWORD
  info "Authentification sur $REPOD_URL..."

  local RESPONSE
  RESPONSE=$(curl -sf -X POST \
    --data-urlencode "username=$REPOD_USERNAME" \
    --data-urlencode "password=$REPOD_PASSWORD" \
    "$REPOD_URL/api/v1/auth/token")

  REPOD_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')
  [ -n "$REPOD_TOKEN" ] && [ "$REPOD_TOKEN" != "null" ] \
    || error "Authentification échouée (vérifiez REPOD_USERNAME / REPOD_PASSWORD)"

  export REPOD_TOKEN
  info "Token obtenu (valide ~60 min)"
  echo "$REPOD_TOKEN"
}

_ensure_token() {
  if [ -z "${REPOD_TOKEN:-}" ]; then
    warn "REPOD_TOKEN non défini — tentative de login automatique"
    _require_env REPOD_USERNAME REPOD_PASSWORD
    cmd_login > /dev/null
  fi
}

# ── Commande : upload ─────────────────────────────────────────────────────────

cmd_upload() {
  local RPM="${1:-}"
  local DISTRIBUTION="${2:-almalinux8}"
  local ARCH="${3:-x86_64}"

  [ -n "$RPM" ] || error "Usage: $0 upload <fichier.rpm> [distribution] [arch]"
  [ -f "$RPM" ] || error "Fichier introuvable : $RPM"
  _require_env REPOD_URL
  _ensure_token

  info "Upload de $RPM → distribution=$DISTRIBUTION arch=$ARCH"
  local HTTP_CODE
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $REPOD_TOKEN" \
    -F "file=@$RPM" \
    -F "distribution=$DISTRIBUTION" \
    "$REPOD_URL/api/v1/upload")

  case "$HTTP_CODE" in
    200|201) info "✅ $RPM publié avec succès (HTTP $HTTP_CODE)" ;;
    409)     warn "⚠️  Paquet déjà présent dans le dépôt (HTTP 409)" ;;
    *)       error "Upload échoué pour $RPM (HTTP $HTTP_CODE)" ;;
  esac
}

# ── Commande : vulnerabilities ────────────────────────────────────────────────

cmd_vulnerabilities() {
  local DISTRIBUTION="${1:-}"
  _require_env REPOD_URL
  _ensure_token

  local URL="$REPOD_URL/api/v1/security/vulnerabilities?per_page=200"
  [ -n "$DISTRIBUTION" ] && URL="${URL}&distribution=${DISTRIBUTION}"

  info "Récupération des vulnérabilités${DISTRIBUTION:+ (distribution: $DISTRIBUTION)}..."
  local RESPONSE
  RESPONSE=$(_api GET "/api/v1/security/vulnerabilities?per_page=200${DISTRIBUTION:+&distribution=$DISTRIBUTION}")

  local TOTAL CRITICAL HIGH MEDIUM
  TOTAL=$(echo "$RESPONSE"    | jq '.vulnerabilities.total // 0')
  CRITICAL=$(echo "$RESPONSE" | jq '[.vulnerabilities.items[] | select(.severity == "Critical")] | length')
  HIGH=$(echo "$RESPONSE"     | jq '[.vulnerabilities.items[] | select(.severity == "High")]     | length')
  MEDIUM=$(echo "$RESPONSE"   | jq '[.vulnerabilities.items[] | select(.severity == "Medium")]   | length')

  echo "📊 Vulnérabilités repod :"
  echo "   Total    : $TOTAL"
  echo "   Critical : $CRITICAL"
  echo "   High     : $HIGH"
  echo "   Medium   : $MEDIUM"

  # Sortie JSON brute sur stdout (pipe-friendly)
  echo "$RESPONSE"

  # Exit code non-nul si CVE critique détectée
  [ "$CRITICAL" -eq 0 ] || { warn "$CRITICAL CVE critique(s) détectée(s)"; exit 2; }
}

# ── Commande : sarif ──────────────────────────────────────────────────────────

cmd_sarif() {
  local DISTRIBUTION="${1:-}"
  local OUTPUT="${2:-repod.sarif.json}"
  _require_env REPOD_URL
  _ensure_token

  local URL="/api/v1/sbom/sarif"
  [ -n "$DISTRIBUTION" ] && URL="${URL}?distribution=${DISTRIBUTION}"

  info "Export SARIF${DISTRIBUTION:+ (distribution: $DISTRIBUTION)} → $OUTPUT"
  _api GET "$URL" > "$OUTPUT"

  local VERSION RESULTS
  VERSION=$(jq -r '.version' "$OUTPUT")
  RESULTS=$(jq '.runs[0].results | length' "$OUTPUT")
  info "✅ SARIF $VERSION exporté : $RESULTS résultat(s) dans $OUTPUT"
}

# ── Commande : packages ───────────────────────────────────────────────────────

cmd_packages() {
  local DISTRIBUTION="${1:-}"
  _require_env REPOD_URL
  _ensure_token

  local PATH="/api/v1/packages/"
  [ -n "$DISTRIBUTION" ] && PATH="${PATH}?distribution=${DISTRIBUTION}"

  info "Liste des paquets${DISTRIBUTION:+ (distribution: $DISTRIBUTION)}..."
  _api GET "$PATH"
}

# ── Aide ──────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage : $(basename "$0") <commande> [arguments]

Commandes :
  login                              Obtenir un token JWT (stocké dans REPOD_TOKEN)
  upload <fichier.rpm> [dist] [arch] Publier un paquet .rpm
  vulnerabilities [distribution]     Lister les vulnérabilités (exit 2 si CVE critique)
  sarif [distribution] [output.json] Exporter au format SARIF 2.1.0
  packages [distribution]            Lister les paquets du dépôt

Variables d'environnement :
  REPOD_URL       (requis) URL de l'instance repod
  REPOD_USERNAME  (requis) Nom d'utilisateur
  REPOD_PASSWORD  (requis) Mot de passe
  REPOD_TOKEN     (optionnel) JWT pré-obtenu (skip login)

Exemples :
  export REPOD_URL=https://repo.example.com
  export REPOD_USERNAME=ci-bot
  export REPOD_PASSWORD=secret

  $(basename "$0") upload mypackage-1.0.0-1.x86_64.rpm almalinux8
  $(basename "$0") vulnerabilities almalinux8
  $(basename "$0") sarif almalinux8 scan-results.sarif.json
EOF
  exit 0
}

# ── Point d'entrée ────────────────────────────────────────────────────────────

CMD="${1:-}"
case "$CMD" in
  login)           shift; cmd_login "$@" ;;
  upload)          shift; cmd_upload "$@" ;;
  vulnerabilities) shift; cmd_vulnerabilities "$@" ;;
  sarif)           shift; cmd_sarif "$@" ;;
  packages)        shift; cmd_packages "$@" ;;
  help|--help|-h)  usage ;;
  "")              usage ;;
  *)               error "Commande inconnue : '$CMD'. Lancez '$0 help' pour l'aide." ;;
esac
