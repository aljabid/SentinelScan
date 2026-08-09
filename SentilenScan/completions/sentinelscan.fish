# Fish completion for sentinelscan
# Install: copy to ~/.config/fish/completions/sentinelscan.fish

complete -c sentinelscan -f

complete -c sentinelscan -s m -l modules -d "Modules to run" -xa "headers ssl_tls owasp cookies cors dns ports subdomains crawler cve_fingerprint all"
complete -c sentinelscan -l input-list -d "Read targets from file" -F
complete -c sentinelscan -l plugin-dir -d "Custom analyzer plugin directory" -xa "(__fish_complete_directories)"
complete -c sentinelscan -l no-plugins -d "Disable plugin loading"
complete -c sentinelscan -s f -l format -d "Output format" -xa "text json html sarif"
complete -c sentinelscan -s o -l output -d "Write report to file" -F
complete -c sentinelscan -s T -l timing -d "Timing template 0-5" -xa "0 1 2 3 4 5"
complete -c sentinelscan -l timeout -d "Request timeout (seconds)"
complete -c sentinelscan -l retries -d "Connection retries"
complete -c sentinelscan -l crawl-max-pages -d "Max pages for crawler module"
complete -c sentinelscan -l severity -d "Filter by severity" -xa "critical high medium low info"
complete -c sentinelscan -l user-agent -d "Custom User-Agent string"
complete -c sentinelscan -s H -l header -d "Custom HTTP header"
complete -c sentinelscan -l cookie -d "Raw Cookie header"
complete -c sentinelscan -l follow-redirects -d "Follow redirects"
complete -c sentinelscan -l no-follow-redirects -d "Do not follow redirects"
complete -c sentinelscan -l no-color -d "Disable colored output"
complete -c sentinelscan -s v -l verbose -d "Verbose output"
complete -c sentinelscan -l version -d "Show version and exit"
complete -c sentinelscan -l exit-on-critical -d "Exit 2 if any critical finding"
complete -c sentinelscan -l score-threshold -d "Exit 2 if risk score exceeds N"
complete -c sentinelscan -l update-db -d "Download latest CVE signature database"
complete -c sentinelscan -l update-url -d "Custom signature database URL"
complete -c sentinelscan -l doctor -d "Run self-diagnosis"
