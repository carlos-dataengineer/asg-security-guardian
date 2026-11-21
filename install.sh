#!/usr/bin/env bash
set -euo pipefail
MODE="${1:---user}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "Python 3.10+ não encontrado." >&2; exit 1; }
python3 - <<'PY'
import sys
if sys.version_info < (3, 10): raise SystemExit("Python 3.10+ é obrigatório.")
print("Python", sys.version.split()[0], "OK")
PY
SKILL_SOURCE="$ROOT/.claude/skills/asg-security-guardian"
[[ -d "$SKILL_SOURCE" ]] || { echo "Skill não encontrada: $SKILL_SOURCE" >&2; exit 1; }
if [[ "$MODE" == "--project" ]]; then
  SKILL_DEST="$PWD/.claude/skills/asg-security-guardian"
else
  SKILL_DEST="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/skills/asg-security-guardian"
fi
APP="$HOME/.asg/app"
BIN="$HOME/.asg/bin"
[[ ! -e "$SKILL_DEST" ]] || { echo "Skill já existe: $SKILL_DEST. Faça backup/remova manualmente antes de reinstalar." >&2; exit 1; }
[[ ! -e "$APP" ]] || { echo "Aplicação já existe: $APP. Faça backup/remova manualmente antes de reinstalar." >&2; exit 1; }
mkdir -p "$(dirname "$SKILL_DEST")" "$BIN" "$(dirname "$APP")"
cp -R "$SKILL_SOURCE" "$SKILL_DEST"
mkdir -p "$APP/protection_core"
cp "$ROOT/protection_core/"*.py "$APP/protection_core/"
cp -R "$ROOT/config" "$APP/config"
cat > "$BIN/asg" <<EOF
#!/usr/bin/env bash
set -euo pipefail
ASG_ROOT="$APP"
if [[ \$# -lt 1 ]]; then echo "Uso: asg <scan|baseline|check|watch|propose-quarantine|approve|verify-audit> [argumentos]"; exit 2; fi
COMMAND="\$1"; shift
case "\$COMMAND" in
  scan) exec python3 "\$ASG_ROOT/protection_core/asg_guard.py" "\$@" ;;
  baseline|check|watch|propose-quarantine|approve|verify-audit) exec python3 "\$ASG_ROOT/protection_core/asg_local.py" "\$COMMAND" "\$@" ;;
  *) echo "Comando desconhecido: \$COMMAND" >&2; exit 2 ;;
esac
EOF
chmod +x "$BIN/asg"
echo "ASG instalado."
echo "Skill: $SKILL_DEST"
echo "Core:  $APP"
echo "CLI:   $BIN/asg"
echo "Adicione $BIN ao PATH para chamar 'asg' de qualquer pasta."
