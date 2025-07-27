# -*- coding: utf-8 -*-
import boto3
import csv
import logging
from datetime import datetime
import pandas as pd
from tabulate import tabulate

# --- 1. CONFIGURAÇÃO DO LOGGER ---

def setup_logger(log_filename):
    """Configura o logger para enviar saída para o console e para um arquivo."""
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    
    # Evita adicionar handlers duplicados se a função for chamada múltiplas vezes
    if logger.hasHandlers():
        logger.handlers.clear()

    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # File Handler
    file_handler = logging.FileHandler(log_filename)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger

# --- 2. FUNÇÕES AUXILIARES ---

def get_all_aws_regions(service_name, logger, start_region='us-east-1'):
    """Obtém uma lista de todos os nomes de regiões para um determinado serviço."""
    try:
        client = boto3.client(service_name, region_name=start_region)
        if service_name == 'lightsail':
            return [region['name'] for region in client.get_regions()['regions']]
        else:
            return [region['RegionName'] for region in client.describe_regions()['Regions']]
    except Exception as e:
        logger.error(f"Erro ao obter lista de regiões para {service_name}: {e}")
        return []

def write_to_csv(filename, headers, data_rows, logger):
    """Escreve uma lista de dicionários em um arquivo CSV."""
    if not data_rows:
        logger.info(f"Nenhum dado para escrever no arquivo {filename}. Arquivo não gerado.")
        return
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data_rows)
        logger.info(f"Relatório CSV gerado com sucesso: {filename}")
    except Exception as e:
        logger.error(f"Erro ao escrever o arquivo CSV {filename}: {e}")

def write_to_excel(filename, sheets_data, logger):
    """Escreve um dicionário de dados em múltiplas abas de um arquivo Excel."""
    try:
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            for sheet_name, data in sheets_data.items():
                if data:
                    df = pd.DataFrame(data)
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
                else:
                    logger.warning(f"Nenhum dado para a aba '{sheet_name}'. Aba não será criada.")
        logger.info(f"Relatório Excel gerado com sucesso: {filename}")
    except Exception as e:
        logger.error(f"Erro ao escrever o arquivo Excel {filename}: {e}")


# --- 3. FUNÇÕES ---

def gerar_relatorio_1_computacao(ec2_regions, lightsail_regions, logger):
    """Coleta dados de inventário de EC2 e Lightsail e os retorna."""
    logger.info("--- 1: INVENTÁRIO DE COMPUTAÇÃO ---")
    inventario = []
    
    for region in ec2_regions:
        logger.info(f"  -> Verificando EC2 em {region}...")
        try:
            ec2 = boto3.client('ec2', region_name=region)
            ssm = boto3.client('ssm', region_name=region)
            backup = boto3.client('backup', region_name=region)
            
            ssm_managed_ids = {info['InstanceId'] for info in ssm.describe_instance_information()['InstanceInformationList']}
            backup_protected_arns = {res['ResourceArn'] for res in backup.list_protected_resources()['Results']}

            response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}])
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    inst_id = instance['InstanceId']
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    
                    inventario.append({
                        'Serviço': 'EC2',
                        'Região': region,
                        'Proprietário (Tag)': tags.get('Owner', 'N/A'),
                        'Nome da Instância': tags.get('Name', 'N/A'),
                        'ID da Instância': inst_id,
                        'Status': instance['State']['Name'],
                        'Tipo de Instância': instance['InstanceType'],
                        'Data de Criação': instance['LaunchTime'].strftime("%Y-%m-%d"),
                        'IP Público': instance.get('PublicIpAddress', 'N/A'),
                        'Tipo de IP': "Estático (Elastic IP)" if instance.get('AssociationId') else "Dinâmico",
                        'Backup Ativo?': 'Sim' if f'arn:aws:ec2:{region}:{instance["OwnerId"]}:instance/{inst_id}' in backup_protected_arns else 'Não',
                        'Gerenciado por SSM?': 'Sim' if inst_id in ssm_managed_ids else 'Não',
                        'SO (Base)': instance.get('PlatformDetails', 'Linux/UNIX')
                    })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em {region}: {str(e)[:100]}... Pulando.)")
            continue
    
    for region in lightsail_regions:
        logger.info(f"  -> Verificando Lightsail em {region}...")
        try:
            lightsail = boto3.client('lightsail', region_name=region)
            static_ips_response = lightsail.get_static_ips()
            ips_estaticos_map = {ip['attachedTo']: ip['name'] for ip in static_ips_response.get('staticIps', []) if ip.get('isAttached')}
            instances_response = lightsail.get_instances()
            for instance in instances_response.get('instances', []):
                nome_instancia = instance['name']
                
                instancia_info = {
                    'Serviço': 'Lightsail',
                    'Região': region,
                    'Proprietário (Tag)': 'N/A', # Não aplicável para Lightsail
                    'Nome da Instância': nome_instancia,
                    'ID da Instância': instance['arn'],
                    'Status': instance['state']['name'],
                    'Tipo de Instância': instance['bundleId'],
                    'Data de Criação': instance['createdAt'].strftime("%Y-%m-%d"),
                    'IP Público': instance.get('publicIpAddress', 'N/A'),
                    'Tipo de IP': "Estático" if nome_instancia in ips_estaticos_map else "Dinâmico",
                    'Backup Ativo?': 'Sim' if instance.get('hasAutomaticSnapshots') else 'Não',
                    'Gerenciado por SSM?': 'N/A', # Não aplicável para Lightsail
                    'SO (Base)': instance['blueprintId']
                }
                inventario.append(instancia_info)
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em {region}: {str(e)[:100]}... Pulando.)")
            continue
    
    logger.info("--- 1: INVENTÁRIO DE COMPUTAÇÃO CONCLUÍDO ---")
    return inventario

def gerar_relatorio_2_seguranca(ec2_regions, logger):
    """Coleta dados de segurança e os retorna."""
    logger.info("--- 2: ANÁLISE DE SEGURANÇA ---")
    
    # Firewalls Abertos
    firewalls_abertos = []
    headers_fw = ['Região', 'ID do Security Group', 'Nome do Security Group', 'Porta Aberta', 'Origem Aberta', 'Descrição da Regra']
    for region in ec2_regions:
        logger.info(f"  -> Verificando Firewalls em {region}...")
        try:
            ec2 = boto3.client('ec2', region_name=region)
            response = ec2.describe_security_groups()
            for sg in response['SecurityGroups']:
                for perm in sg.get('IpPermissions', []):
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            firewalls_abertos.append({
                                'Região': region,
                                'ID do Security Group': sg['GroupId'],
                                'Nome do Security Group': sg['GroupName'],
                                'Porta Aberta': perm.get('FromPort', 'Todos'),
                                'Origem Aberta': '0.0.0.0/0',
                                'Descrição da Regra': ip_range.get('Description', 'N/A')
                            })
        except Exception:
            logger.error(f"     (Acesso negado ou erro em {region}. Pulando.)")
            continue
    write_to_csv('relatorio_firewalls_abertos.csv', headers_fw, firewalls_abertos, logger)
    
    # Relatório de Usuários IAM
    logger.info("  -> Verificando usuários IAM...")
    usuarios_iam = []
    headers_iam = ['Nome do Usuário', 'MFA Ativo?', 'Acesso via Console?', 'Data de Criação', 'Último Acesso (Senha)']
    try:
        iam = boto3.client('iam')
        for user_detail in iam.list_users()['Users']:
            user_name = user_detail['UserName']
            mfa_devices = iam.list_mfa_devices(UserName=user_name)['MFADevices']
            try:
                iam.get_login_profile(UserName=user_name)
                console_access = 'Sim'
            except iam.exceptions.NoSuchEntityException:
                console_access = 'Não'
            
            usuarios_iam.append({
                'Nome do Usuário': user_name,
                'MFA Ativo?': 'Sim' if mfa_devices else 'Não',
                'Acesso via Console?': console_access,
                'Data de Criação': user_detail['CreateDate'].strftime("%Y-%m-%d"),
                'Último Acesso (Senha)': user_detail.get('PasswordLastUsed', 'N/A')
            })
    except Exception as e:
        logger.error(f"     Erro ao verificar usuários IAM: {e}")
    write_to_csv('relatorio_usuarios_iam.csv', headers_iam, usuarios_iam, logger)
    
    logger.info("--- 2: ANÁLISE DE SEGURANÇA CONCLUÍDO ---")
    return firewalls_abertos, usuarios_iam

def gerar_relatorio_3_custos(ec2_regions, logger):
    """Coleta dados de otimização de custos e os retorna."""
    logger.info("--- 3: OTIMIZAÇÃO DE CUSTOS ---")
    recursos_orfãos = []
    headers = ['Tipo de Recurso', 'Região', 'ID do Recurso', 'Detalhes (Tamanho/Tipo)', 'Data de Criação']
    for region in ec2_regions:
        logger.info(f"  -> Verificando Recursos Órfãos em {region}...")
        try:
            ec2 = boto3.client('ec2', region_name=region)
            
            # Volumes EBS desanexados
            for vol in ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])['Volumes']:
                recursos_orfãos.append({
                    'Tipo de Recurso': 'Volume EBS',
                    'Região': region,
                    'ID do Recurso': vol['VolumeId'],
                    'Detalhes (Tamanho/Tipo)': f"{vol['Size']} GB / {vol['VolumeType']}",
                    'Data de Criação': vol['CreateTime'].strftime("%Y-%m-%d")
                })
            
            # Elastic IPs desanexados
            for addr in ec2.describe_addresses()['Addresses']:
                if 'AssociationId' not in addr:
                    recursos_orfãos.append({
                        'Tipo de Recurso': 'Elastic IP',
                        'Região': region,
                        'ID do Recurso': addr['PublicIp'],
                        'Detalhes (Tamanho/Tipo)': f"Domínio: {addr['Domain']}",
                        'Data de Criação': 'N/A'
                    })
        except Exception:
            logger.error(f"     (Acesso negado ou erro em {region}. Pulando.)")
            continue
            
    write_to_csv('relatorio_recursos_orfãos.csv', headers, recursos_orfãos, logger)

    logger.info("--- 3: OTIMIZAÇÃO DE CUSTOS CONCLUÍDO ---")
    return recursos_orfãos

# --- 4. EXECUÇÃO PRINCIPAL ---
if __name__ == "__main__":
    # Nomes de arquivo dinâmicos
    today_str = datetime.now().strftime("%d%m%Y")
    log_filename = f"inventario_aws_{today_str}.log"
    excel_filename = f"relatorio_aws_completo_{today_str}.xlsx"
    
    # Configura o logger
    logger = setup_logger(log_filename)

    logger.info("======================================================")
    logger.info("INICIANDO SCRIPT DE INVENTÁRIO COMPLETO DA CONTA AWS")
    logger.info(f"Data da Execução: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Logs sendo salvos em: {log_filename}")
    logger.info("======================================================")

    # Dicionário para armazenar todos os dados para o Excel
    relatorios_para_excel = {}

    # Busca as regiões uma única vez
    logger.info("Buscando listas de regiões disponíveis...")
    lista_regioes_ec2 = get_all_aws_regions('ec2', logger)
    lista_regioes_lightsail = get_all_aws_regions('lightsail', logger)
    logger.info(f"Encontradas {len(lista_regioes_ec2)} regiões para EC2 e {len(lista_regioes_lightsail)} para Lightsail.")
    logger.debug(f"Regiões EC2: {lista_regioes_ec2}")
    logger.debug(f"Regiões Lightsail: {lista_regioes_lightsail}")
    if not lista_regioes_ec2 and not lista_regioes_lightsail:
        logger.error("Nenhuma região encontrada para EC2 ou Lightsail. Encerrando o script.")
        exit(1)
    logger.info("Listas de regiões obtidas com sucesso.")
    logger.info("Iniciando execução dos relatórios...")

    # --- Execução 1: INVENTÁRIO DE COMPUTAÇÃO ---
    headers_p1 = [
        'Serviço', 'Região', 'Proprietário (Tag)', 'Nome da Instância', 'ID da Instância', 'Status', 
        'Tipo de Instância', 'Data de Criação', 'IP Público', 'Tipo de IP', 'Backup Ativo?', 
        'Gerenciado por SSM?', 'SO (Base)'
    ]
    dados_p1 = gerar_relatorio_1_computacao(lista_regioes_ec2, lista_regioes_lightsail, logger)
    write_to_csv('relatorio_computacao.csv', headers_p1, dados_p1, logger)
    relatorios_para_excel['Computacao'] = dados_p1
    logger.info("Tabela de Computação:\n" + tabulate(dados_p1, headers="keys", tablefmt="grid"))

    # --- Execução 2: ANÁLISE DE SEGURANÇA ---
    headers_p2_fw = ['Região', 'ID do Security Group', 'Nome do Security Group', 'Porta Aberta', 'Origem Aberta', 'Descrição da Regra']
    headers_p2_iam = ['Nome do Usuário', 'MFA Ativo?', 'Acesso via Console?', 'Data de Criação', 'Último Acesso (Senha)']
    dados_p2_fw, dados_p2_iam = gerar_relatorio_2_seguranca(lista_regioes_ec2, logger)
    write_to_csv('relatorio_firewalls_abertos.csv', headers_p2_fw, dados_p2_fw, logger)
    write_to_csv('relatorio_usuarios_iam.csv', headers_p2_iam, dados_p2_iam, logger)
    relatorios_para_excel['Firewalls_Abertos'] = dados_p2_fw
    relatorios_para_excel['Usuarios_IAM'] = dados_p2_iam
    logger.info("Tabela de Firewalls Abertos:\n" + tabulate(dados_p2_fw, headers="keys", tablefmt="grid"))
    logger.info("Tabela de Usuários IAM:\n" + tabulate(dados_p2_iam, headers="keys", tablefmt="grid"))
    
    # --- Execução 3: OTIMIZAÇÃO DE CUSTOS ---
    headers_p3 = ['Tipo de Recurso', 'Região', 'ID do Recurso', 'Detalhes (Tamanho/Tipo)', 'Data de Criação']
    dados_p3 = gerar_relatorio_3_custos(lista_regioes_ec2, logger)
    write_to_csv('relatorio_recursos_orfãos.csv', headers_p3, dados_p3, logger)
    relatorios_para_excel['Recursos_Orfaos'] = dados_p3
    logger.info("Tabela de Recursos Órfãos:\n" + tabulate(dados_p3, headers="keys", tablefmt="grid"))
    
    # --- Geração do arquivo Excel consolidado ---
    logger.info("\nIniciando geração do arquivo Excel consolidado...")
    write_to_excel(excel_filename, relatorios_para_excel, logger)

    logger.info("======================================================")
    logger.info("SCRIPT FINALIZADO.")
    logger.info("======================================================")