#!/bin/bash
# RVT2 — Caso de prueba sobre Mac vivo (sin imagen, sin copiar archivos)
#
# Crea la estructura de caso apuntando con un symlink al Mac real e indexa
# el filesystem completo automáticamente. Después puedes lanzar los módulos
# macOS directamente sin pasar por mount/allocfiles.
#
# Requisitos:
#   - Terminal con Acceso Total al Disco activado
#     Ajustes del Sistema → Privacidad y Seguridad → Acceso Total al Disco
#   - sudo (se pide al indexar /private/var/db, /private/var/log, etc.)
#
# Uso:
#   bash plugins/macos/setup_test_mac.sh [/ruta/morgue]
#
# Después de ejecutar este script:
#   python3 rvt2.py -v \
#     --morgue <morgue> --client TEST --casename CASO -s mac_local \
#     -j plugins.macos.RVT_macos.BasicInfo          # módulo individual
#     -j plugins.macos.RVT_network.NetworkUsage     # otro módulo
#     # ... o cualquier módulo de plugins/macos/

set -uo pipefail

# ─── Configuración ────────────────────────────────────────────────────────────
MORGUE="${1:-/tmp/rvt2_morgue}"
CLIENT="TEST"
CASENAME="CASO"
SOURCE="mac_local"

CASEDIR="${MORGUE}/${CLIENT}/${CASENAME}"
SOURCEDIR="${CASEDIR}/${SOURCE}"
MOUNTDIR="${SOURCEDIR}/mnt"
AUXDIR="${SOURCEDIR}/output/auxdir"
ALLOC="${AUXDIR}/alloc_files.txt"

# Ruta relativa desde casedir al punto de montaje (= raíz del Mac)
# Coincide con la convención real de RVT2: mnt/p01/ es la raíz del filesystem
REL_P01="${SOURCE}/mnt/p01"

RVT2_HOME="$(cd "$(dirname "$0")/../.." && pwd)"

# ─── Colores ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}!${NC}  $*"; }
hdr()  { echo -e "\n${BOLD}── $* ──${NC}"; }

# ─── 1. Crear estructura ──────────────────────────────────────────────────────
hdr "Creando estructura del caso"

mkdir -p "${MOUNTDIR}"
mkdir -p "${SOURCEDIR}/output/macos"
mkdir -p "${AUXDIR}"
mkdir -p "${SOURCEDIR}/log"

# mnt/p01 → /   (convención RVT2: p01 es la raíz del filesystem montado)
ln -sfn / "${MOUNTDIR}/p01"

ok "Caso creado en: ${CASEDIR}"
ok "Symlink: ${MOUNTDIR}/p01 → /"

# ─── 2. Generar alloc_files.txt indexando el Mac completo ─────────────────────
hdr "Indexando filesystem del Mac"
echo "  Usando find -L (sigue el symlink p01 → /) con exclusiones inteligentes"
echo "  Puede tardar 1-3 minutos..."

# Resolver la ruta real del morgue para excluirla del índice
# (evita el bucle: p01 → / → morgue → p01 → ...)
MORGUE_REAL="$(cd "${MORGUE}" 2>/dev/null && pwd -P)"
MORGUE_REL="${MORGUE_REAL#/}"  # ruta relativa desde /

# Generar el índice con find -L
# - find -L sigue symlinks (a diferencia del allocfiles normal que usa -P)
# - find detecta ciclos automáticamente y no entra en bucle infinito
# - Excluimos directorios que no interesan forense o causan el bucle
(cd "${CASEDIR}" && \
  sudo find -L "${REL_P01}" \
    \( \
      -path "${REL_P01}/System/Volumes"               \
      -o -path "${REL_P01}/Volumes"                   \
      -o -path "${REL_P01}/dev"                       \
      -o -path "${REL_P01}/cores"                     \
      -o -path "${REL_P01}/.Spotlight-V100"           \
      -o -path "${REL_P01}/private/var/vm"            \
      -o -path "${REL_P01}/private/tmp"               \
      -o -path "${REL_P01}/${MORGUE_REL}"             \
      -o -path "${REL_P01}/Users/*/Library/Caches"   \
      -o -path "${REL_P01}/Users/*/Library/CloudStorage" \
      -o -path "${REL_P01}/Users/*/Pictures"          \
      -o -path "${REL_P01}/Users/*/Movies"            \
      -o -path "${REL_P01}/Users/*/Music"             \
      -o -path "${REL_P01}/Library/Application Support/MobileSync" \
    \) -prune \
    -o -print \
  2>/dev/null \
) > "${ALLOC}"

TOTAL=$(wc -l < "${ALLOC}" | tr -d ' ')
ok "Indexadas ${TOTAL} entradas → ${ALLOC}"

# ─── 3. Instrucciones ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                  Listo para analizar                     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Activar entorno:${NC}"
echo "  cd ${RVT2_HOME} && source .venv/bin/activate"
echo ""
echo -e "${BOLD}Ejecutar un módulo individual (recomendado para pruebas):${NC}"
echo "  python3 rvt2.py -v \\"
echo "    --morgue ${MORGUE} --client ${CLIENT} --casename ${CASENAME} -s ${SOURCE} \\"
echo "    -j plugins.macos.RVT_network.NetworkUsage"
echo ""
echo -e "${BOLD}Ejecutar todos los módulos macOS de golpe:${NC}"
echo "  # IMPORTANTE: usar los módulos directamente, NO 'macforensics'"
echo "  # (macforensics incluye 'mount' y 'allocfiles' que sobreescribirían el índice)"
echo "  for job in \\"
echo "    plugins.macos.RVT_macos.BasicInfo \\"
echo "    plugins.macos.RVT_network.NetworkUsage \\"
echo "    plugins.macos.RVT_network.Network \\"
echo "    plugins.macos.RVT_filesystem.Quarantine \\"
echo "    plugins.macos.RVT_filesystem.ParseDSStore \\"
echo "    plugins.macos.RVT_filesystem.FSEvents \\"
echo "    plugins.macos.RVT_logs.ASL \\"
echo "    plugins.macos.RVT_logs.ParseUnifiedLogReader \\"
echo "    plugins.macos.RVT_knowledgec.KnowledgeC \\"
echo "    plugins.macos.RVT_apps.MacMRU; do"
echo "    python3 rvt2.py -v \\"
echo "      --morgue ${MORGUE} --client ${CLIENT} --casename ${CASENAME} -s ${SOURCE} \\"
echo "      -j \"\${job}\""
echo "  done"
echo ""
echo -e "${BOLD}Ver resultados:${NC}"
echo "  ls -lh ${SOURCEDIR}/output/macos/"
echo ""
echo -e "${BOLD}Ver errores de paths (artefacto no encontrado):${NC}"
echo "  grep -i 'not found\|error\|warning' ${SOURCEDIR}/log/*.log 2>/dev/null | head -40"
echo ""
