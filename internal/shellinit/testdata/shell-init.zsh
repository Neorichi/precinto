# precinto shell integration for zsh, printed by: precinto shell-init zsh
# Harness wrappers start agents through precinto (unlock before launch, lock
# screen, sealing at exit); the folder-entry hook offers to unlock a
# protected folder when you enter it.

function claude {
  if [[ -n ${PRECINTO_ACTIVE-} ]]; then
    command claude "$@"
  else
    command '/opt/precinto/bin/precinto' run --harness claude-code -- claude "$@"
  fi
}

function codex {
  if [[ -n ${PRECINTO_ACTIVE-} ]]; then
    command codex "$@"
  else
    command '/opt/precinto/bin/precinto' run --harness codex -- codex "$@"
  fi
}

_precinto_chpwd() {
  typeset -g _precinto_moved=1
}

_precinto_precmd() {
  emulate -L zsh
  [[ -o interactive ]] || return 0
  (( ZSH_SUBSHELL == 0 )) || return 0
  [[ -z ${VSCODE_RESOLVING_ENVIRONMENT-} && -z ${PRECINTO_ACTIVE-} ]] || return 0
  local first=
  if [[ -z ${_precinto_started-} ]]; then
    typeset -g _precinto_started=1
    first=--first
  elif [[ -z ${_precinto_moved-} || $PWD == "${_precinto_pwd-}" ]]; then
    typeset -g _precinto_moved=
    return 0
  fi
  typeset -g _precinto_moved=
  local prev=${_precinto_pwd-}
  typeset -g _precinto_pwd=$PWD
  local out line action= root= epoch= msg=
  out=$(command '/opt/precinto/bin/precinto' shell-hook --shell zsh --pwd "$PWD" --prev "$prev" --skip "${_PRECINTO_SKIP-}" $first 2>/dev/null) || return 0
  for line in "${(@f)out}"; do
    case $line in
      action=*) action=${line#action=} ;;
      root=*) root=${line#root=} ;;
      epoch=*) epoch=${line#epoch=} ;;
      message=*) msg=${line#message=} ;;
    esac
  done
  [[ -n $action && -n $msg ]] || return 0
  [[ -n $root ]] && typeset -g _PRECINTO_SKIP="$root:$epoch"
  if [[ $action == prompt && -t 0 && -t 1 ]]; then
    print -rn -- "$msg "
    local key=
    read -rs -k 1 key || { print; return 0; }
    print
    if [[ $key == $'\n' || $key == $'\r' ]]; then
      command '/opt/precinto/bin/precinto' unlock
    fi
  else
    print -r -- "$msg"
  fi
  return 0
}

autoload -Uz add-zsh-hook
add-zsh-hook chpwd _precinto_chpwd
add-zsh-hook precmd _precinto_precmd
