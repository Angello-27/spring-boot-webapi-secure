#!/bin/zsh
# Uso: run.sh <nombre-log> '<comando>'
# Ejecuta el comando desde la raíz del repo y guarda en reports/logs/<nombre>.log
# la cabecera (fecha, usuario@host, directorio), la salida completa y el código de salida.
cd "$(dirname "$0")/../.." || exit 1
mkdir -p reports/logs
log="reports/logs/$1.log"
{
  print -r -- "[$(date '+%Y-%m-%d %H:%M:%S %Z')] $(whoami)@$(hostname -s):${PWD/#$HOME/~} \$ $2"
  eval "$2" 2>&1
  print -r -- "[exit $?]"
} > "$log"
tail -1 "$log"
