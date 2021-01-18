#!/bin/bash

# Script que hace un resumen de tablas de artefactos préviamente parseados con rvt2
# Para su uso, se tiene que entrar en la carpeta del source, p.ej. /morgue/102086-doctor/102086-04-1 y ejecutar el script
# TODO poner un help y aceptar parámetros como la morgue, el caso y la source

echo '# Users'
echo '## Profiles'
echo
echo 'User folder|SID|LastWrite'
echo '--|--|--'
rg --multiline-dotall -Ui 'ProfileList\n.*...........\n' output/windows/hives/02_user_account_information_p*.txt |  rg -i -A2 "(Users|Documents and Settings)" | tr '\n' '|' | sed -e 's/\\/\//g' -e 's/^[^:][^:]*: //' -e 's/|[^:-][^:]*: /|/g' -e 's/|--|/"/g' -e 's/|$//' |tr '"' '\n' |sed 's/Z$//'
echo
echo
echo '## birth date ntuser.dat'
echo
echo 'Date|Path'
echo '--|--'
rg -i ',...b,.*p[0-9][0-9]/(Users|Documents and settings)/[^/][^/]*/ntuser.dat("| .delete)' output/timeline/*_TL.csv | cut -d ',' -f 1,8 | sed 's/,/|/g' | sed -e 's/"//g' -e 's/|[^/]*\/[^/]*\/[^/]*\//|/' -e 's/^\([0-9-]*\)T\([0-9:]*\)Z/\1 \2/'
echo
echo '# RDP'
echo
echo '## Incomming'
echo
echo 'Login|Logoff|User|IP'
echo '--|--|--|--'
rg -v '^[^0-9]' analysis/events/rdp_incoming.md | sed -e 's/\\/\//g' -e 's/\.[0-9][0-9]* UTC//g' | sort -u
echo
echo '## Outgoing'
echo
echo 'LoginDate|LogoffDate|Address|SID'
echo '--|--|--|--'
rg -v '^[^0-9]' analysis/events/rdp_outgoing.md |cut -d'|' -f1-4 | sed -e 's/\\/\//g' -e 's/\.[0-9][0-9]* UTC/Z/g' | sort -u
echo
echo '# Executions'
echo '## CCM'
echo
echo 'Date|Path|User'
echo '--|--|--'
sort -u output/windows/execution/CCM.csv |cut -d';' -f1,2,3,5 |sed -e 's/"//g' -e 's/^\([^;][^;]*\);\([^;][^;]*\);\([^;][^;]*\)/\1;\2\3/' -e 's/;/|/g'
echo
echo '## Amcache'
echo
echo 'Date|Path|sha1'
echo '--|--|--'
rg --multiline-dotall -Ui 'amcache[^\n]*.*[*]{3}Files[*]{3}' output/windows/hives/07_program_execution_information_p*.txt | rg -A1 'LastWrite' | tr '\n' '|' | sed -e 's/\\/\//g' |sed 's/|--|/\n/g'| sed -e 's/  *LastWrite: /|/' -e 's/Hash: //' -e 's/\([^|]*|\)\([^|]*|\)/\2\1/' |sort -u
echo '--|--|--'
rg --multiline-dotall -Ui '[*]{3}*Files[*]{3}[^\n]*.*bam v' output/windows/hives/07_program_execution_information_p*.txt | rg '(LastWrite|Path|SHA-1)\s+:'| tr '\n' '|'| sed -e 's/LastWrite[ \t]*: //g' -e 's/|Path[ \t]*: /|/g' -e 's/\\/\//g' -e 's/|SHA-1[ \t]*: \([^|]*\)|/|\1\n/g' | sort -u
echo
echo '## AppCompatCache'
echo
echo 'Date|Path|Executed'
echo '--|--|--'
rg --multiline-dotall -Ui 'appcompatcache v.[\n]*.*shimcache' output/windows/hives/07_program_execution_information_p*.txt |sed -n 's/\(.*\)[ \t][ \t]*\([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\)\([ \t]*Executed\|$\)/\2|\1|\3/p' | sed -e 's/\\/\//g' -e 's/[ \t]*|[ \t]*Executed/|Executed/' |sort -u
echo
echo '## Install services'
echo
echo 'Date|File Path|Service Name|SID'
echo '--|--|--|--'
rg '"704[05]"' analysis/events/install.csv| sort -u|cut -d";" -f1,4,9,14 | rg -v ';"";""' | sed -e 's/;/|/g' -e 's/"//g'
echo
echo '# User Activity'
for user in $(rg -i "p[0-9][0-9]/[^/]*/[^/]*/ntuser.dat$" output/auxdir/alloc_files.txt)
do
    USER=$(basename `dirname $user`)
    echo "## User $USER"
    echo "### Userassist $USER"
    echo
    echo 'Date|Path'
    echo '--|--'
    rip -p userassist_tln -r "${user#*/}" | sed -e "s/\\\/\//g"| sed -e "s/^\([^|][^|]*\).*UserAssist - \(.*\)/date -d @\1 \"+%Y-%m-%d %H:%M:%S\" -u| tr \"\n\" \"|\"; echo \"\2\"/e" |sort -u
    echo
    echo "### Shellbags $USER"
    echo
    rg --multiline-dotall -Ui "\** Extracting from User[ \t]*$USER \**\n[^\n]*\nshellbags[^\n]*[^\*]*" output/windows/hives/15_user-account-file-access-activity_p*.txt | tail -n +5 | cut -d "|" -f 1,7 | sed 's/^ *|/-|/' |grep "|" | sed -e 's/ \[[^]]*.//' -e 's/\\/\//g'
    echo
    echo "### Jumplists $USER"
    echo
    echo "Open date|path|network_path"
    echo '--|--|--'
    cut -d";" -f1,6,7 output/windows/recentfiles/*${USER}_jl.csv|grep -v Open|grep -v ";;$" | sed -e 's/\\/\//g' -e 's/;/|/g' |sort -u
done
echo
