package shellinit

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

// Errors of Script.
var (
	errShell   = errors.New("shellinit: unsupported shell (zsh, bash or fish)")
	errExe     = errors.New("shellinit: the precinto executable must be an absolute path")
	errHarness = errors.New("shellinit: harness names must be lower-case executable names")
)

// harnessName is a command name a wrapper function may take.
var harnessName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// harnessIDs maps the executable names that differ from their harness id.
var harnessIDs = map[string]string{"claude": "claude-code"}

// wrapper is one harness wrapper function.
type wrapper struct {
	Name    string // command name (claude)
	Harness string // harness id passed to precinto run (claude-code)
}

// scriptData fills the templates.
type scriptData struct {
	Exe      string // quoted for the shell
	Wrappers []wrapper
}

// script implements Script.
func script(o Options) (string, error) {
	tmpl, ok := templates[o.Shell]
	if !ok {
		return "", errShell
	}
	if c, ok := cleanAbs(o.Exe); !ok || c != o.Exe || strings.ContainsAny(o.Exe, "\x00\n\r") {
		return "", errExe
	}
	data := scriptData{Exe: quote(o.Shell, o.Exe)}
	seen := map[string]bool{}
	for _, h := range o.Harnesses {
		if !harnessName.MatchString(h) {
			return "", fmt.Errorf("%w: %q", errHarness, h)
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		id := h
		if v, ok := harnessIDs[h]; ok {
			id = v
		}
		data.Wrappers = append(data.Wrappers, wrapper{Name: h, Harness: id})
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

func cleanAbs(p string) (string, bool) {
	if p == "" || !filepath.IsAbs(p) {
		return "", false
	}
	return filepath.Clean(p), true
}

// quote returns s as one single-quoted word of shell (POSIX quoting for
// zsh and bash; fish escapes \ and ' inside single quotes).
func quote(shell, s string) string {
	if shell == Fish {
		return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// installLine implements InstallLine.
func installLine(shell string) string {
	switch shell {
	case Zsh, Bash:
		return `eval "$(precinto shell-init ` + shell + `)"`
	case Fish:
		return "precinto shell-init fish | source"
	}
	return ""
}

// rcFile implements RCFile.
func rcFile(shell, home string) string {
	if home == "" {
		return ""
	}
	switch shell {
	case Zsh:
		return filepath.Join(home, ".zshrc")
	case Bash:
		return filepath.Join(home, ".bashrc")
	case Fish:
		return filepath.Join(home, ".config", "fish", "config.fish")
	}
	return ""
}

// Wrappers use the function keyword, so that a user alias of the same name
// is not expanded in the definition (zsh and bash expand aliases there).
//
// The folder-entry hook (SPEC §15.5, D29). It runs before a prompt, only in
// an interactive shell that is not a subshell, not while VS Code resolves
// the shell environment and not inside a precinto-wrapped harness; it asks
// `precinto shell-hook` (a ≤150 ms daemon query that never reads the
// terminal) only on the first prompt and after the directory changed, and
// remembers in _PRECINTO_SKIP the folder and lock epoch it already asked
// about. shell-hook prints key=value lines (EnterResult.Lines) that the
// scripts parse without eval (D69); only "prompt" reads one key from the
// terminal: Enter runs `precinto unlock --root <path>`, anything else
// skips. (The path is kept in a variable named dir: in zsh, path is PATH.)
var templates = map[string]*template.Template{
	Zsh:  template.Must(template.New(Zsh).Parse(zshScript)),
	Bash: template.Must(template.New(Bash).Parse(bashScript)),
	Fish: template.Must(template.New(Fish).Parse(fishScript)),
}

const zshScript = `# precinto shell integration for zsh, printed by: precinto shell-init zsh
# Harness wrappers start agents through precinto (unlock before launch, lock
# screen, sealing at exit); the folder-entry hook offers to unlock a
# protected folder when you enter it.
{{range .Wrappers}}
function {{.Name}} {
  if [[ -n ${PRECINTO_ACTIVE-} ]]; then
    command {{.Name}} "$@"
  else
    command {{$.Exe}} run --harness {{.Harness}} -- {{.Name}} "$@"
  fi
}
{{end}}
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
  local out line action= root= epoch= dir= msg=
  out=$(command {{.Exe}} shell-hook --shell zsh --pwd "$PWD" --prev "$prev" --skip "${_PRECINTO_SKIP-}" $first 2>/dev/null) || return 0
  for line in "${(@f)out}"; do
    case $line in
      action=*) action=${line#action=} ;;
      root=*) root=${line#root=} ;;
      epoch=*) epoch=${line#epoch=} ;;
      path=*) dir=${line#path=} ;;
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
    if [[ $key == $'\n' || $key == $'\r' ]] && [[ -n $dir ]]; then
      command {{.Exe}} unlock --root "$dir"
    fi
  else
    print -r -- "$msg"
  fi
  return 0
}

autoload -Uz add-zsh-hook
add-zsh-hook chpwd _precinto_chpwd
add-zsh-hook precmd _precinto_precmd
`

const bashScript = `# precinto shell integration for bash, printed by: precinto shell-init bash
# Harness wrappers start agents through precinto (unlock before launch, lock
# screen, sealing at exit); the folder-entry hook offers to unlock a
# protected folder when you enter it.
{{range .Wrappers}}
function {{.Name}} {
  if [ -n "${PRECINTO_ACTIVE-}" ]; then
    command {{.Name}} "$@"
  else
    command {{$.Exe}} run --harness {{.Harness}} -- {{.Name}} "$@"
  fi
}
{{end}}
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
  out=$(command {{.Exe}} shell-hook --shell bash --pwd "$PWD" --prev "$prev" --skip "${_PRECINTO_SKIP-}" ${first:+"$first"} 2>/dev/null) || return $rc
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
      command {{.Exe}} unlock --root "$dir"
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
`

const fishScript = `# precinto shell integration for fish, printed by: precinto shell-init fish
# Harness wrappers start agents through precinto (unlock before launch, lock
# screen, sealing at exit); the folder-entry hook offers to unlock a
# protected folder when you enter it.
{{range .Wrappers}}
function {{.Name}} --wraps {{.Name}} --description 'Run {{.Name}} through precinto'
    if set -q PRECINTO_ACTIVE
        command {{.Name}} $argv
    else
        command {{$.Exe}} run --harness {{.Harness}} -- {{.Name}} $argv
    end
end
{{end}}
function _precinto_enter --argument-names first
    status is-interactive; or return 0
    set -q VSCODE_RESOLVING_ENVIRONMENT; and return 0
    set -q PRECINTO_ACTIVE; and return 0
    if test -z "$first"; and test "$PWD" = "$_precinto_pwd"
        return 0
    end
    set -l prev "$_precinto_pwd"
    set -g _precinto_pwd $PWD
    set -l args --shell fish --pwd $PWD --prev "$prev" --skip "$_PRECINTO_SKIP"
    if test -n "$first"
        set -a args --first
    end
    set -l out (command {{.Exe}} shell-hook $args 2>/dev/null); or return 0
    set -l action ''
    set -l root ''
    set -l epoch ''
    set -l dir ''
    set -l msg ''
    for line in $out
        switch $line
            case 'action=*'
                set action (string replace -- 'action=' '' $line)
            case 'root=*'
                set root (string replace -- 'root=' '' $line)
            case 'epoch=*'
                set epoch (string replace -- 'epoch=' '' $line)
            case 'path=*'
                set dir (string replace -- 'path=' '' $line)
            case 'message=*'
                set msg (string replace -- 'message=' '' $line)
        end
    end
    if test -z "$action"; or test -z "$msg"
        return 0
    end
    if test -n "$root"
        set -g _PRECINTO_SKIP "$root:$epoch"
    end
    if test "$action" = prompt; and isatty stdin; and isatty stdout
        printf '%s ' "$msg"
        set -l key ''
        read --nchars 1 --silent --prompt-str '' key; or begin
            printf '\n'
            return 0
        end
        printf '\n'
        if test -z "$key"; and test -n "$dir"
            command {{.Exe}} unlock --root "$dir"
        end
    else
        printf '%s\n' "$msg"
    end
end

function _precinto_on_pwd --on-variable PWD
    _precinto_enter
end

function _precinto_first_prompt --on-event fish_prompt
    functions --erase _precinto_first_prompt
    _precinto_enter first
end
`
