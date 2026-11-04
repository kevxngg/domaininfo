"""Shell completion scripts for DomainInfo, generated from the argparse definition.

Usage: domaininfo --completion bash|zsh|powershell
"""

import argparse

FILE_OPTIONS = ("-f", "--file", "-o", "--output")
COMMANDS = ("domaininfo", "domaininfo.cmd", "domaininfo.py", "domaininfo.exe")


def _spec(cli):
    options, choices = [], {}
    for action in cli._actions:
        if action.help == argparse.SUPPRESS:
            continue
        options.extend(action.option_strings)
        if action.choices and action.option_strings:
            for option in action.option_strings:
                choices[option] = [str(choice) for choice in action.choices]
    return sorted(options), choices


def bash(cli):
    options, choices = _spec(cli)
    cases = "\n".join(f'        {option}) COMPREPLY=($(compgen -W "{" ".join(values)}" -- "$cur")); return ;;'
                      for option, values in sorted(choices.items()))
    files = "|".join(FILE_OPTIONS)
    return f"""# DomainInfo: autocompletado para Bash
_domaininfo() {{
    local cur prev
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    case "$prev" in
{cases}
        {files}) COMPREPLY=($(compgen -f -- "$cur")); return ;;
    esac
    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "{" ".join(options)}" -- "$cur"))
    fi
}}
complete -o default -F _domaininfo {" ".join(COMMANDS)}"""


def zsh(cli):
    # bashcompinit lets zsh reuse the Bash function without a second definition to maintain.
    return ("# DomainInfo: autocompletado para Zsh\n"
            "(( $+functions[compdef] )) || { autoload -U +X compinit && compinit; }\n"
            "autoload -U +X bashcompinit && bashcompinit\n" + bash(cli))


def powershell(cli):
    options, choices = _spec(cli)
    quoted = lambda values: ", ".join("'" + value + "'" for value in values)
    table = "\n".join(f"        '{option}' = @({quoted(values)})" for option, values in sorted(choices.items()))
    return f"""# DomainInfo: autocompletado para PowerShell
Register-ArgumentCompleter -Native -CommandName {", ".join(COMMANDS)} -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $choices = @{{
{table}
    }}
    $options = @({quoted(options)})
    $words = @($commandAst.CommandElements | ForEach-Object {{ $_.ToString() }})
    $previous = if ($wordToComplete) {{ $words[-2] }} else {{ $words[-1] }}
    if ($choices.ContainsKey($previous)) {{ $list = $choices[$previous] }}
    elseif ($wordToComplete -like '-*') {{ $list = $options }}
    else {{ return }}
    $list | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
}}"""


def script(shell, cli):
    return {"bash": bash, "zsh": zsh, "powershell": powershell}[shell](cli)
