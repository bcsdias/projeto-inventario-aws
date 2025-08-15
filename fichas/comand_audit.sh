#!/bin/bash

# \==============================================================================

# Script de Log de Comandos do Bash

# 

# Descrição:

# Este script registra todos os comandos executados em sessões de terminal

# do Bash para um arquivo de log centralizado. Ele é implementado de forma

# global para todos os usuários.

# 

# Localização: /etc/profile.d/command\_logger.sh

# \==============================================================================

# \--- Variáveis de Configuração ---

# O arquivo onde todos os comandos serão salvos.

# Certifique-se de que este arquivo tenha as permissões corretas (veja instruções).

LOG\_FILE="/var/log/command\_history.log"

# \--- Função de Log ---

# Esta função será executada toda vez que um comando for concluído.

log\_bash\_command() {
\# Ignora os comandos da própria função de log para evitar loops.
if [ "$(id -u)" -ne 0 ] && [ \! -z "$BASH\_COMMAND" ] && [ "$BASH\_COMMAND" \!= "log\_bash\_command" ]; then
\# Formato do log: [Timestamp] [Usuário@Host Diretório] \# Comando
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$(whoami)@$(hostname) $(pwd)] \# $BASH\_COMMAND" \>\> $LOG\_FILE
fi
}

# \--- Ativação do Log ---

# A variável PROMPT\_COMMAND executa uma função antes de exibir o prompt.

# Usamos 'trap' com o sinal DEBUG, que é executado antes de cada comando simples.

# Isso é mais robusto que usar apenas PROMPT\_COMMAND.

trap 'log\_bash\_command' DEBUG