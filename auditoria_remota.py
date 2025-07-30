# -*- coding: utf-8 -*-
import boto3
import logging
from datetime import datetime
import os
import time

# --- 1. CONFIGURAÇÃO DO LOGGER ---
def setup_logger(log_filename):
    """Configura o logger para enviar saída para o console e para um arquivo."""
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    if logger.hasHandlers():
        logger.handlers.clear()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler = logging.FileHandler(log_filename)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    return logger

# --- 2. FUNÇÕES AUXILIARES ---
def get_all_aws_regions(service_name, logger, start_region='us-east-1'):
    """Obtém uma lista de todos os nomes de regiões para um determinado serviço."""
    try:
        client = boto3.client(service_name, region_name=start_region)
        return [region['RegionName'] for region in client.describe_regions()['Regions']]
    except Exception as e:
        logger.error(f"Erro ao obter lista de regiões para {service_name}: {e}")
        return []

def execute_ssm_command(ssm_client, instance_id, commands, logger, timeout=300):
    """Envia um comando via SSM Run Command, aguarda e retorna a saída."""
    logger.info(f"    Executando comando na instância {instance_id}...")
    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': commands},
            TimeoutSeconds=timeout
        )
        command_id = response['Command']['CommandId']
        
        # Espera o comando completar
        status = 'Pending'
        total_wait_time = 0
        while status in ['Pending', 'InProgress']:
            if total_wait_time > timeout:
                logger.error(f"      Comando {command_id} excedeu o timeout de {timeout}s.")
                return "TIMEOUT", "TIMEOUT"
            
            time.sleep(5)
            total_wait_time += 5
            
            result = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            status = result['Status']

        logger.info(f"      Comando concluído com status: {status}")
        return result.get('StandardOutputContent', ''), result.get('StandardErrorContent', '')
    except Exception as e:
        logger.error(f"      Falha ao executar comando SSM em {instance_id}: {e}")
        return "ERROR", str(e)

# --- 3. SCRIPT DE DISCOVERY WEB (EMBUTIDO) ---
SCRIPT_WEB_DISCOVERY = """
#!/bin/bash
#
# Script de Discovery de Aplicações Web v2.3 (Final e Corrigido)
#
# Varre configurações do Nginx e Apache para gerar documentação detalhada, incluindo:
# - Domínios, diretório raiz e versão do PHP
# - Status de segurança (HTTP/HTTPS) e caminho do certificado
# - Parâmetros chave do php.ini (memory_limit, upload_max_filesize, etc.)
# - Identificação da aplicação (WordPress, Drupal, etc.)
# - Detalhes do WordPress (DB, wp-config, lista de plugins)
#
# Dependência Opcional: WP-CLI para listagem detalhada de plugins.
#

# --- Configuração e Funções Auxiliares ---

# Garante a execução como root
if [ "$EUID" -ne 0 ]; then
  echo "Por favor, execute este script como root ou com sudo."
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

# --- Funções de Análise ---

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
        
        while IFS=, read -r status name version; do
            if [ "$status" != "status" ]; then
                printf "  │     - [%s] %s (%s)\n" "$status" "$name" "$version"
            fi
        done < <(sudo -u "$web_user" wp plugin list --path="$root_dir" --fields=status,name,version --format=csv 2>/dev/null)

    else
        print_final_detail "Status" "WP-CLI não instalado. Análise de plugins pulada."
        echo "  │     (Para listar plugins, instale o WP-CLI: https://wp-cli.org)"
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

# --- Início da Execução ---
echo "Iniciando o script de discovery v2.3 (Corrigido)..."
echo "Data da Execução: $(date)"
if [ "$WP_CLI_INSTALLED" = true ]; then
    echo "WP-CLI detectado. A análise de plugins será realizada."
else
    echo "Aviso: WP-CLI não encontrado. A análise de plugins será pulada."
fi
echo ""

# Detecta o servidor web em execução
if pgrep -x "nginx" > /dev/null; then
    print_header "Servidor Web Detectado: Nginx"
    scan_web_server_configs "Nginx" "/etc/nginx/sites-enabled" "*"
elif pgrep -x "apache2" > /dev/null || pgrep -x "httpd" > /dev/null; then
    print_header "Servidor Web Detectado: Apache"
    if [ -d "/etc/apache2/sites-enabled" ]; then
        scan_web_server_configs "Apache" "/etc/apache2/sites-enabled" "*.conf"
    elif [ -d "/etc/httpd/conf.d" ]; then
        scan_web_server_configs "Apache" "/etc/httpd/conf.d" "*.conf"
    fi
else
    echo "Nenhum servidor web (Nginx ou Apache) parece estar em execução."
fi

echo ""
print_header "Análise Concluída"
"""

# --- 4. FUNÇÕES DE AUDITORIA ---

def auditoria_usuarios(ssm_client, instance_id, logger):
    """Lista usuários, permissões e salva em arquivo."""
    logger.info(f"  -> Iniciando auditoria de usuários em {instance_id}...")
    command = [
        "echo '=== USUÁRIOS COM SHELL DE LOGIN ==='",
        "getent passwd | grep -vE '(/sbin/nologin|/usr/sbin/nologin|/bin/false)$' | cut -d: -f1,3,6",
        "echo; echo '=== VERIFICAÇÃO DE PERMISSÕES SUDO ==='",
        "grep -rE '^\\s*[^#]*\\s+ALL=\\(ALL\\)' /etc/sudoers /etc/sudoers.d/ || echo 'Nenhuma permissão global de sudo encontrada.'"
    ]
    stdout, stderr = execute_ssm_command(ssm_client, instance_id, command, logger)
    return stdout if not stderr else f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}"

def auditoria_cron(ssm_client, instance_id, logger):
    """Lista tarefas cron e salva em arquivo."""
    logger.info(f"  -> Iniciando auditoria de Cron em {instance_id}...")
    command = [
        "echo '=== CRONTAB SISTEMA (/etc/crontab) ==='",
        "cat /etc/crontab",
        "echo; echo '=== CRON DROP-INS (/etc/cron.d/*) ==='",
        "for f in /etc/cron.d/*; do echo \"--- Conteúdo de $f ---\"; cat \"$f\"; done",
        "echo; echo '=== CRONTABS DE USUÁRIOS ==='",
        "for user in $(getent passwd | cut -d: -f1); do output=$(crontab -u $user -l 2>/dev/null); if [ -n \"$output\" ]; then echo \"--- Crontab para $user ---\"; echo \"$output\"; fi; done"
    ]
    stdout, stderr = execute_ssm_command(ssm_client, instance_id, command, logger)
    return stdout if not stderr else f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}"

def discovery_web(ssm_client, instance_id, logger):
    """Executa o script de discovery web e salva em arquivo."""
    logger.info(f"  -> Iniciando discovery de aplicações web em {instance_id}...")
    # ATENÇÃO: Cole seu script bash completo na variável SCRIPT_WEB_DISCOVERY acima
    if "Cole o seu script bash completo aqui" in SCRIPT_WEB_DISCOVERY:
        logger.error("      ERRO: O script de discovery web não foi inserido na variável SCRIPT_WEB_DISCOVERY.")
        return "ERRO", "Script de discovery não configurado na variável SCRIPT_WEB_DISCOVERY."
        
    stdout, stderr = execute_ssm_command(ssm_client, instance_id, [SCRIPT_WEB_DISCOVERY], logger)
    return stdout if not stderr else f"STDOUT:\n{stdout}\n\nSTDERR:\n{stderr}"


# --- 5. EXECUÇÃO PRINCIPAL ---
if __name__ == "__main__":
    today_str = datetime.now().strftime("%d%m%Y")
    log_filename = f"auditoria_remota_{today_str}.log"
    output_base_dir = f"auditoria_remota_resultados_{today_str}"
    
    logger = setup_logger(log_filename)

    logger.info("======================================================")
    logger.info("INICIANDO SCRIPT DE AUDITORIA REMOTA DE INSTÂNCIAS")
    logger.info(f"Resultados serão salvos em: {output_base_dir}")
    logger.info("======================================================")

    if not os.path.exists(output_base_dir):
        os.makedirs(output_base_dir)

    ec2_regions = get_all_aws_regions('ec2', logger)
    for region in ec2_regions:
        logger.info(f"--- Verificando a região {region} ---")
        try:
            ssm = boto3.client('ssm', region_name=region)
            ec2 = boto3.client('ec2', region_name=region)
            
            # Pega apenas instâncias gerenciadas pelo SSM
            managed_instances = ssm.describe_instance_information()['InstanceInformationList']
            managed_instance_ids = [inst['InstanceId'] for inst in managed_instances if inst.get('PingStatus') == 'Online']
            
            if not managed_instance_ids:
                logger.info(f"Nenhuma instância online gerenciada pelo SSM encontrada em {region}.")
                continue
            
            # Pega o nome das instâncias
            instance_details = ec2.describe_instances(InstanceIds=managed_instance_ids)
            instance_name_map = {}
            for res in instance_details['Reservations']:
                for inst in res['Instances']:
                    instance_name_map[inst['InstanceId']] = next((tag['Value'] for tag in inst.get('Tags', []) if tag['Key'] == 'Name'), inst['InstanceId'])

            for instance_id in managed_instance_ids:
                instance_name = instance_name_map.get(instance_id, instance_id)
                logger.info(f"Processando instância: {instance_name} ({instance_id})")

                # Cria diretório para a instância
                instance_dir = os.path.join(output_base_dir, f"{instance_name}_{instance_id}")
                if not os.path.exists(instance_dir):
                    os.makedirs(instance_dir)

                # Executa as auditorias
                resultado_usuarios = auditoria_usuarios(ssm, instance_id, logger)
                with open(os.path.join(instance_dir, 'usuarios_e_permissoes.txt'), 'w', encoding='utf-8') as f:
                    f.write(resultado_usuarios)

                resultado_cron = auditoria_cron(ssm, instance_id, logger)
                with open(os.path.join(instance_dir, 'tarefas_cron.txt'), 'w', encoding='utf-8') as f:
                    f.write(resultado_cron)
                
                resultado_web = discovery_web(ssm, instance_id, logger)
                with open(os.path.join(instance_dir, 'discovery_web.txt'), 'w', encoding='utf-8') as f:
                    f.write(resultado_web)
        
        except Exception as e:
            logger.error(f"     Erro inesperado na região {region}: {e}")
            continue

    logger.info("======================================================")
    logger.info("SCRIPT FINALIZADO.")
    logger.info("======================================================")