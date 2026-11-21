# precinto shell integration for fish, printed by: precinto shell-init fish
# Harness wrappers start agents through precinto (unlock before launch, lock
# screen, sealing at exit); the folder-entry hook offers to unlock a
# protected folder when you enter it.

function claude --wraps claude --description 'Run claude through precinto'
    if set -q PRECINTO_ACTIVE
        command claude $argv
    else
        command '/opt/precinto/bin/precinto' run --harness claude-code -- claude $argv
    end
end

function codex --wraps codex --description 'Run codex through precinto'
    if set -q PRECINTO_ACTIVE
        command codex $argv
    else
        command '/opt/precinto/bin/precinto' run --harness codex -- codex $argv
    end
end

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
    set -l out (command '/opt/precinto/bin/precinto' shell-hook $args 2>/dev/null); or return 0
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
            command '/opt/precinto/bin/precinto' unlock --root "$dir"
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
