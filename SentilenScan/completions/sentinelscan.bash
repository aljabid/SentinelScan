# Bash completion for sentinelscan
# Install: source this file, or copy to /usr/share/bash-completion/completions/sentinelscan

_sentinelscan_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD - 1]}"

    opts="-iL --input-list -m --modules --plugin-dir --no-plugins -f --format -o --output
          -T --timing --timeout --retries --crawl-max-pages --severity --user-agent
          -H --header --cookie --follow-redirects --no-follow-redirects --no-color
          -v --verbose --version --exit-on-critical --score-threshold --update-db
          --update-url --doctor --help"

    case "$prev" in
        -m | --modules)
            COMPREPLY=($(compgen -W "headers ssl_tls owasp cookies cors dns ports subdomains crawler cve_fingerprint all" -- "$cur"))
            return 0
            ;;
        -f | --format)
            COMPREPLY=($(compgen -W "text json html sarif" -- "$cur"))
            return 0
            ;;
        --severity)
            COMPREPLY=($(compgen -W "critical high medium low info" -- "$cur"))
            return 0
            ;;
        -T | --timing)
            COMPREPLY=($(compgen -W "0 1 2 3 4 5" -- "$cur"))
            return 0
            ;;
        -o | --output | -iL | --input-list | --plugin-dir)
            COMPREPLY=($(compgen -f -- "$cur"))
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    else
        COMPREPLY=($(compgen -f -- "$cur"))
    fi
}
complete -F _sentinelscan_completions sentinelscan
