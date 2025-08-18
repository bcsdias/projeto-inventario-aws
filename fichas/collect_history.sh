#!/bin/bash

# ==============================================================================
# Script para Coleta Única do Histórico de Comandos
#
# Descrição:
# Este script varre o sistema em busca dos arquivos .bash_history existentes
# para o usuário root e para todos os usuários no diretório /home.
# Ele consolida todo o histórico encontrado em um único arquivo de saída.
#
# Uso:
# 1. Salve este script em um arquivo, por exemplo, collect_history.sh
# 2. Dê permissão de execução: chmod +x collect_history.sh
# 3. Execute com privilégios de superusuário: sudo ./collect_history.sh
# ==============================================================================

OUTPUT_FILE="historico_comandos_$(hostname)_$(date +%F).log"

echo "Iniciando a coleta do histórico de comandos em $(hostname)..."
echo "Resultados serão salvos em: $OUTPUT_FILE"

# Limpa ou cria o arquivo de saída
echo "Coleta de Histórico - Servidor: $(hostname) - Data: $(date)" > "$OUTPUT_FILE"
echo "===========================================================" >> "$OUTPUT_FILE"

echo "=======================================================================" >> "$OUTPUT_FILE"
echo " 4. Historico de comandos para cada usuario local                      " >> "$OUTPUT_FILE"
echo "=======================================================================" >> "$OUTPUT_FILE"

# Coleta do histórico do root e de todos os usuários em /home
echo -e "\n--- Histórico para o usuário: root ---" >> "$OUTPUT_FILE"
cat /root/.bash_history 2>/dev/null >> "$OUTPUT_FILE" || echo "Histórico do root não encontrado." >> "$OUTPUT_FILE"

find /home -name .bash_history -print0 | while IFS= read -r -d $'\0' history_file; do
    username=$(basename "$(dirname "$history_file")")
    echo -e "\n\n--- Histórico para o usuário: $username ---" >> "$OUTPUT_FILE"
    cat "$history_file" >> "$OUTPUT_FILE"
done

echo "Coleta concluída. Verifique o arquivo $OUTPUT_FILE."
