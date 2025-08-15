#!/bin/bash
#
# ===================================================================
# Script de Auditoria Completa v1.0
#
# Executa uma auditoria completa em um servidor Linux, verificando:
# 1. Usuários locais e permissões de sudo.
# 2. Tarefas agendadas (cron do sistema e de usuários).
# 3. Discovery detalhado de aplicações web (Nginx/Apache).
# ===================================================================

# --- Configuração e Funções Auxiliares ---

# Garante a execução como root
if [ "$EUID" -ne 0 ]; then
  echo "ERRO: Por favor, execute este script como root ou com sudo."
  exit 1
fi

# Verifica se o WP-CLI está instalado
WP_CLI_INSTALLED=false
if command -v wp &> /dev/null; then
    WP_CLI_INSTALLED=true
fi

print_header() {
    echo "======================================================================="
    echo " $1"
    echo "======================================================================="
}

print_subheader() {
    echo "  ├─ $1"
}

print_detail() {
    echo "  │  ├─ $1: $2"
}

print_final_detail() {
    echo "  │  └─ $1: $2"
}


# --- Funções de Análise do Discovery Web ---
# (Estas são as funções do seu script original)

get_php_ini_value() {
    local php_version=$1
    local param=$2
    local php_ini_path="/etc/php/${php_version}/fpm/php.ini"

    if [ -f "$php_ini_path" ]; then
        grep -E "^\s*${param}\s*=" "$php_ini_path" | tail -n 1 | awk -F'=' '{print $2}' | xargs
    else
        echo "Arquivo php.ini não encontrado"
    fi
}

analyze_php_config() {
    local conf_file=$1
    local php_version

    print_subheader "Análise do PHP"
    php_version=$(grep -o -E 'php[0-9]+\.[0-9]+-fpm.sock' "$conf_file" | head -n 1 | grep -o -E '[0-9]+\.[0-9]+' || echo "Não detectada")
    print_detail "Versão PHP (FPM)" "$php_version"

    if [[ "$php_version" != "Não detectada" ]]; then
        print_detail "memory_limit" "$(get_php_ini_value "$php_version" "memory_limit")"
        print_detail "upload_max_filesize" "$(get_php_ini_value "$php_version" "upload_max_filesize")"
        print_detail "post_max_size" "$(get_php_ini_value "$php_version" "post_max_size")"
        print_final_detail "max_execution_time" "$(get_php_ini_value "$php_version" "max_execution_time")"
    else
        print_final_detail "Status" "Nenhuma versão FPM específica encontrada na configuração."
    fi
}

analyze_security() {
    local conf_file=$1
    print_subheader "Análise de Segurança"

    if grep -qE '^\s*listen\s+443\s+ssl' "$conf_file" || grep -qE '^\s*SSLEngine\s+on' "$conf_file"; then
        print_detail "Protocolo" "HTTPS"
        cert_path=$(grep -E '^\s*ssl_certificate\s+' "$conf_file" | awk '{print $2}' | sed 's/;//' || grep -E '^\s*SSLCertificateFile' "$conf_file" | awk '{print $2}')
        print_final_detail "Caminho do Certificado" "${cert_path:-Não encontrado}"
    else
        print_final_detail "Protocolo" "HTTP"
    fi
}

list_wp_plugins() {
    local root_dir=$1
    local web_user
    web_user=$(ps axo user,group,comm | grep -E '[a]pache|[h]ttpd|[n]ginx' | grep -v root | head -n 1 | awk '{print $1}')
    web_user=${web_user:-www-data}

    print_subheader "Análise de Plugins WordPress"
    if [ "$WP_CLI_INSTALLED" = true ]; then
        echo "  │  └─ Plugins Instalados (Status | Nome | Versão):"
        
        sudo -u "$web_user" wp plugin list --path="$root_dir" --fields=status,name,version --format=csv 2>/dev/null | while IFS=, read -r status name version; do
            if [ "$status" != "status" ]; then
                printf "  │    - [%s] %s (%s)\n" "$status" "$name" "$version"
            fi
        done
    else
        print_final_detail "Status" "WP-CLI não instalado. Análise de plugins pulada."
        echo "  │    (Para listar plugins, instale o WP-CLI: https://wp-cli.org)"
    fi
}

identify_app() {
    local root_dir=$1
    
    print_subheader "Análise da Aplicação"
    if [ ! -d "$root_dir" ]; then
        print_final_detail "Erro" "Diretório raiz não encontrado em '$root_dir'"
        return
    fi
    
    if [ -f "$root_dir/wp-config.php" ]; then
        print_detail "Tipo de Aplicação" "WordPress"
        db_name=$(grep "DB_NAME" "$root_dir/wp-config.php" | cut -d \' -f 4)
        db_user=$(grep "DB_USER" "$root_dir/wp-config.php" | cut -d \' -f 4)
        db_host=$(grep "DB_HOST" "$root_dir/wp-config.php" | cut -d \' -f 4)
        table_prefix=$(grep "\$table_prefix" "$root_dir/wp-config.php" | cut -d \' -f 2)
        
        print_detail "DB Name" "$db_name"
        print_detail "DB User" "$db_user"
        print_detail "DB Host" "$db_host"
        print_detail "Table Prefix" "$table_prefix"

        wp_debug_line=$(grep -E "^\s*define\(\s*'WP_DEBUG'" "$root_dir/wp-config.php" | grep -v '^\s*//')
        if [[ $wp_debug_line == *"true"* ]]; then
            print_final_detail "WP_DEBUG" "Ativado"
        else
            print_final_detail "WP_DEBUG" "Desativado"
        fi
        
        list_wp_plugins "$root_dir"
        
    elif [ -f "$root_dir/sites/default/settings.php" ]; then
        print_final_detail "Tipo de Aplicação" "Drupal"
    elif [ -f "$root_dir/configuration.php" ]; then
        print_final_detail "Tipo de Aplicação" "Joomla"
    elif [ -f "$root_dir/app/etc/env.php" ]; then
        print_final_detail "Tipo de Aplicação" "Magento 2"
    elif [ -f "$root_dir/index.php" ]; then
        print_final_detail "Tipo de Aplicação" "Aplicação PHP Genérica"
    else
        print_final_detail "Tipo de Aplicação" "Site Estático (HTML) ou Desconhecido"
    fi
}

scan_web_server_configs() {
    local web_server=$1
    local sites_dir=$2
    local conf_pattern=$3

    if [ ! -d "$sites_dir" ]; then
        echo "Diretório de configuração $sites_dir não encontrado."
        return
    fi

    echo "Analisando sites ativados em $sites_dir..."
    for conf_file in "$sites_dir"/$conf_pattern; do
        if [ -f "$conf_file" ]; then
            if [ "$web_server" == "Nginx" ]; then
                server_names=$(grep -E '^\s*server_name' "$conf_file" | sed -E 's/^\s*server_name\s+//;s/;\s*$//' | head -n 1)
                root_dir=$(grep -E '^\s*root' "$conf_file" | head -n 1 | awk '{print $2}' | sed 's/;//')
            elif [ "$web_server" == "Apache" ]; then
                server_name=$(grep -E '^\s*ServerName' "$conf_file" | awk '{print $2}')
                server_alias=$(grep -E '^\s*ServerAlias' "$conf_file" | sed 's/^\s*ServerAlias\s*//')
                server_names="$server_name $server_alias"
                root_dir=$(grep -E '^\s*DocumentRoot' "$conf_file" | awk '{print $2}' | tr -d '"')
            fi

            if [ -n "$server_names" ] && [ -n "$root_dir" ]; then
                echo ""
                print_header "Site Encontrado: $server_names"
                echo "  ● Arquivo de Conf: $conf_file"
                echo "  ● Diretório Raiz : $root_dir"
                echo ""
                analyze_security "$conf_file"
                analyze_php_config "$conf_file"
                identify_app "$root_dir"
            fi
        fi
    done
}


# --- Início da Execução Principal ---

print_header "INÍCIO DA AUDITORIA COMPLETA DO SERVIDOR"
echo "Data da Execução: $(date)"
echo ""

# --- 1. AUDITORIA DE USUÁRIOS E PERMISSÕES ---
print_header "1. Análise de Usuários e Permissões"
echo
echo ">> USUÁRIOS COM SHELL DE LOGIN (Usuário:UID:Home)"
getent passwd | grep -vE '(/sbin/nologin|/usr/sbin/nologin|/bin/false)$' | cut -d: -f1,3,6
echo
echo ">> VERIFICAÇÃO DE PERMISSÕES SUDO GLOBAIS"
grep -rE '^\s*[^#]*\s+ALL=\(ALL\)' /etc/sudoers /etc/sudoers.d/ || echo "Nenhuma permissão global de sudo (ALL=ALL) encontrada."
echo
echo

# --- 2. AUDITORIA DE TAREFAS AGENDADAS (CRON) ---
print_header "2. Análise de Tarefas Agendadas (Cron)"
echo
echo ">> CRONTAB DO SISTEMA (/etc/crontab)"
cat /etc/crontab 2>/dev/null || echo "Arquivo /etc/crontab não encontrado."
echo
echo ">> CRON DROP-INS (/etc/cron.d/)"
for f in /etc/cron.d/*; do
  if [ -f "$f" ]; then
    echo "--- Conteúdo de $f ---"
    cat "$f"
    echo
  fi
done
echo ">> CRONTABS DE USUÁRIOS"
for user in $(getent passwd | cut -d: -f1); do
  output=$(crontab -u "$user" -l 2>/dev/null)
  if [ -n "$output" ]; then
    echo "--- Crontab para $user ---"
    echo "$output"
    echo
  fi
done
echo

# --- 3. DISCOVERY DE APLICAÇÕES WEB ---
print_header "3. Análise de Aplicações Web"
echo
if [ "$WP_CLI_INSTALLED" = true ]; then
    echo "Status: WP-CLI detectado. A análise de plugins será realizada."
else
    echo "Status: WP-CLI não encontrado. A análise de plugins será pulada."
fi
echo

# Detecta o servidor web em execução
if pgrep -x "nginx" > /dev/null; then
    print_subheader "Servidor Web Detectado: Nginx"
    scan_web_server_configs "Nginx" "/etc/nginx/sites-enabled" "*"
elif pgrep -x "apache2" > /dev/null || pgrep -x "httpd" > /dev/null; then
    print_subheader "Servidor Web Detectado: Apache"
    if [ -d "/etc/apache2/sites-enabled" ]; then
        scan_web_server_configs "Apache" "/etc/apache2/sites-enabled" "*.conf"
    elif [ -d "/etc/httpd/conf.d" ]; then # Para CentOS/RHEL
        scan_web_server_configs "Apache" "/etc/httpd/conf.d" "*.conf"
    fi
else
    echo "Nenhum servidor web (Nginx ou Apache) parece estar em execução."
fi
echo

print_header "AUDITORIA COMPLETA CONCLUÍDA"
