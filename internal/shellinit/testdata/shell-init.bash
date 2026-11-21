# precinto shell integration for bash, printed by: precinto shell-init bash
# Harness wrappers start agents through precinto (unlock before launch, lock
# screen, sealing at exit); the folder-entry hook offers to unlock a
# protected folder when you enter it.

function claude {
  if [ -n "${PRECINTO_ACTIVE-}" ]; then
    command claude "$@"
  else
    command '/opt/precinto/bin/precinto' run --harness claude-code -- claude "$@"
  fi
}

function codex {
  if [ -n "${PRECINTO_ACTIVE-}" ]; then
    command codex "$@"
  else
    command '/opt/precinto/bin/precinto' run --harness codex -- codex "$@"
  fi
}

_precinto_prompt_command() {
  local rc=$?
  case $- in *i*) ;; *) return $rc ;; esac
  [ "${BASH_SUBSHELL:-0}" = 0 ] || return $rc
  { [ -z "${VSCODE_RESOLVING_ENVIRONMENT-}" ] && [ -z "${PRECINTO_ACTIVE-}" ]; } || return $rc
  local first=
  if [ -z "${_precinto_started-}" ]; then
    _precinto_started=1
    first=--first
  elif [ "$PWD" = "${_precinto_pwd-}" ]; then
    return $rc
  fi
  local prev=${_precinto_pwd-}
  _precinto_pwd=$PWD
  local out line action= root= epoch= dir= msg=
  out=$(command '/opt/precinto/bin/precinto' shell-hook --shell bash --pwd "$PWD" --prev "$prev" --skip "${_PRECINTO_SKIP-}" ${first:+"$first"} 2>/dev/null) || return $rc
  while IFS= read -r line; do
    case $line in
      action=*) action=${line#action=} ;;
      root=*) root=${line#root=} ;;
      epoch=*) epoch=${line#epoch=} ;;
      path=*) dir=${line#path=} ;;
      message=*) msg=${line#message=} ;;
    esac
  done <<<"$out"
  { [ -n "$action" ] && [ -n "$msg" ]; } || return $rc
  [ -n "$root" ] && _PRECINTO_SKIP="$root:$epoch"
  if [ "$action" = prompt ] && [ -t 0 ] && [ -t 1 ]; then
    printf '%s ' "$msg"
    local key=
    IFS= read -r -s -n 1 key || { printf '\n'; return $rc; }
    printf '\n'
    if [ -z "$key" ] && [ -n "$dir" ]; then
      command '/opt/precinto/bin/precinto' unlock --root "$dir"
    fi
  else
    printf '%s\n' "$msg"
  fi
  return $rc
}

case ";${PROMPT_COMMAND-};" in
  *";_precinto_prompt_command;"*) ;;
  *) PROMPT_COMMAND="_precinto_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
