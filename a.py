# -*- coding: utf-8 -*-
import boto3
import csv
import logging
from datetime import datetime, timedelta 
import pandas as pd
from tabulate import tabulate

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
            for sheet_name, data_info in sheets_data.items():
                if data_info['data']:
                    df = pd.DataFrame(data_info['data'])
                    # Garante que a ordem das colunas no Excel seja a mesma dos headers
                    df = df[data_info['headers']] 
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
                else:
                    logger.warning(f"Nenhum dado para a aba '{sheet_name}'. Aba não será criada.")
        logger.info(f"Relatório Excel gerado com sucesso: {filename}")
    except Exception as e:
        logger.error(f"Erro ao escrever o arquivo Excel {filename}: {e}")


# --- 3. FUNÇÕES DOS PILARES ---

def gerar_relatorio_1_computacao(ec2_regions, lightsail_regions, logger):
    """Coleta dados de inventário de EC2 e Lightsail e os retorna."""
    logger.info("--- 1: INVENTÁRIO DE COMPUTAÇÃO ---")
    inventario = []
    
    # Nomes das colunas padronizados com a API da AWS.
    headers = [
        'Service', 'Region', 'Tag:Owner', 'Tag:Name', 'InstanceId', 'State', 
        'InstanceType', 'LaunchTime', 'PublicIpAddress', 'PrivateIpAddresses', 'Ipv6Addresses', 'IpType', 
        'BackupEnabled', 'IsSsmManaged'
    ]
    
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()['Account']

    # EC2
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
                    
                    # Coleta de múltiplos IPs privados e IPv6
                    private_ips = [ni.get('PrivateIpAddress') for ni in instance.get('NetworkInterfaces', [])]
                    ipv6_ips = []
                    for ni in instance.get('NetworkInterfaces', []):
                        ipv6_ips.extend([ipv6['Ipv6Address'] for ipv6 in ni.get('Ipv6Addresses', [])])

                    inventario.append({
                        'Service': 'EC2',
                        'Region': region,
                        'Tag:Owner': tags.get('Owner', 'N/A (Tag não definida)'),
                        'Tag:Name': tags.get('Name', 'N/A'),
                        'InstanceId': inst_id,
                        'State': instance['State']['Name'],
                        'InstanceType': instance['InstanceType'],
                        'LaunchTime': instance['LaunchTime'].strftime("%Y-%m-%d"),
                        'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                        'PrivateIpAddresses': ", ".join(filter(None, private_ips)),
                        'Ipv6Addresses': ", ".join(filter(None, ipv6_ips)),
                        'IpType': "Elastic" if instance.get('AssociationId') else "Dynamic",
                        'BackupEnabled': 'Yes' if f'arn:aws:ec2:{region}:{account_id}:instance/{inst_id}' in backup_protected_arns else 'No',
                        'IsSsmManaged': 'Yes' if inst_id in ssm_managed_ids else 'No'
                    })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em EC2 {region}: {str(e)[:100]})")
            continue
    
    # Lightsail
    for region in lightsail_regions:
        logger.info(f"  -> Verificando Lightsail em {region}...")
        try:
            lightsail = boto3.client('lightsail', region_name=region)
            ips_estaticos_map = {ip['attachedTo']: ip['name'] for ip in lightsail.get_static_ips().get('staticIps', []) if ip.get('isAttached')}
            for instance in lightsail.get_instances().get('instances', []):
                nome_instancia = instance['name']
                inventario.append({
                    'Service': 'Lightsail',
                    'Region': region,
                    'Tag:Owner': 'N/A',
                    'Tag:Name': nome_instancia,
                    'InstanceId': instance['arn'],
                    'State': instance['state']['name'],
                    'InstanceType': instance['bundleId'],
                    'LaunchTime': instance['createdAt'].strftime("%Y-%m-%d"),
                    'PublicIpAddress': instance.get('publicIpAddress', 'N/A'),
                    'PrivateIpAddresses': instance.get('privateIpAddress', 'N/A'),
                    'Ipv6Addresses': ", ".join(instance.get('ipv6Addresses', [])),
                    'IpType': "Static" if nome_instancia in ips_estaticos_map else "Dynamic",
                    'BackupEnabled': 'Yes' if instance.get('hasAutomaticSnapshots') else 'No',
                    'IsSsmManaged': 'N/A'
                })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em Lightsail {region}: {str(e)[:100]})")
            continue

    logger.info("--- 1: INVENTÁRIO DE COMPUTAÇÃO CONCLUÍDO ---")
    return inventario, headers

def gerar_relatorio_2_seguranca(ec2_regions, logger):
    """Coleta dados de segurança e os retorna."""
    logger.info("--- 2: ANÁLISE DE SEGURANÇA ---")
    
    # Relatório de Firewalls Abertos
    logger.info("  -> Verificando Firewalls Abertos...")
    firewalls_abertos = []
    headers_fw = ['Region', 'InstanceId', 'Tag:Name', 'SecurityGroupId', 'OffendingRule(Port)', 'OffendingRule(Source)']
    for region in ec2_regions:
        logger.info(f"  -> Verificando Firewalls e Instâncias em {region}...")
        try:
            ec2 = boto3.client('ec2', region_name=region)
            
            # Mapeia todos os security groups da região para suas regras abertas
            regras_abertas_map = {}
            for sg in ec2.describe_security_groups()['SecurityGroups']:
                regras_inseguras = []
                for perm in sg.get('IpPermissions', []):
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            regras_inseguras.append(f"Port(s): {perm.get('FromPort', 'All')}, Protocol: {perm.get('IpProtocol', 'All')}")
                if regras_inseguras:
                    regras_abertas_map[sg['GroupId']] = regras_inseguras

            if not regras_abertas_map:
                continue

            # Itera sobre as instâncias e verifica se usam os SGs inseguros
            for reservation in ec2.describe_instances()['Reservations']:
                for instance in reservation['Instances']:
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    for sg_anexado in instance.get('SecurityGroups', []):
                        sg_id = sg_anexado['GroupId']
                        if sg_id in regras_abertas_map:
                            for regra in regras_abertas_map[sg_id]:
                                firewalls_abertos.append({
                                    'Region': region,
                                    'InstanceId': instance['InstanceId'],
                                    'Tag:Name': tags.get('Name', 'N/A'),
                                    'SecurityGroupId': sg_id,
                                    'OffendingRule(Port)': regra,
                                    'OffendingRule(Source)': '0.0.0.0/0'
                                })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em {region}: {str(e)[:100]})")
            continue

    # Relatório de Usuários IAM
    logger.info("  -> Verificando usuários IAM...")
    usuarios_iam = []
    headers_iam = ['UserName', 'MfaEnabled', 'ConsoleAccess', 'CreateDate', 'PasswordLastUsed (GMT -03:00)']
    
    try:
        iam = boto3.client('iam')
        for user_detail in iam.list_users()['Users']:
            user_name = user_detail['UserName']
            mfa_devices = iam.list_mfa_devices(UserName=user_name)['MFADevices']
            
            try:
                iam.get_login_profile(UserName=user_name)
                console_access = 'Yes'
            except iam.exceptions.NoSuchEntityException:
                console_access = 'No'
            
            # Lógica para converter o fuso horário
            password_last_used_utc = user_detail.get('PasswordLastUsed')
            password_last_used_str = 'N/A'
            if password_last_used_utc:
                # Converte de UTC para GMT-3 subtraindo 3 horas
                password_last_used_gmt3 = password_last_used_utc - timedelta(hours=3)
                password_last_used_str = password_last_used_gmt3.strftime("%Y-%m-%d %H:%M:%S")

            usuarios_iam.append({
                'UserName': user_name,
                'MfaEnabled': 'Yes' if mfa_devices else 'No',
                'ConsoleAccess': console_access,
                'CreateDate': user_detail['CreateDate'].strftime("%Y-%m-%d"),
                'PasswordLastUsed (GMT -03:00)': password_last_used_str
            })
    except Exception as e:
        logger.error(f"     Erro ao verificar usuários IAM: {e}")
    
    logger.info("--- 2: ANÁLISE DE SEGURANÇA CONCLUÍDO ---")
    return (firewalls_abertos, headers_fw), (usuarios_iam, headers_iam)

def gerar_relatorio_3_custos(ec2_regions, logger):
    """Coleta dados de otimização de custos e os retorna."""
    logger.info("--- 3: OTIMIZAÇÃO DE CUSTOS ---")
    recursos_orfãos = []
    headers = ['ResourceType', 'Region', 'ResourceId', 'Details', 'CreateDate']
    
    for region in ec2_regions:
        logger.info(f"  -> Verificando Recursos Órfãos em {region}...")
        try:
            ec2 = boto3.client('ec2', region_name=region)
            
            for vol in ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])['Volumes']:
                recursos_orfãos.append({
                    'ResourceType': 'EBS Volume',
                    'Region': region,
                    'ResourceId': vol['VolumeId'],
                    'Details': f"{vol['Size']} GB / {vol['VolumeType']}",
                    'CreateDate': vol['CreateTime'].strftime("%Y-%m-%d")
                })
            
            for addr in ec2.describe_addresses()['Addresses']:
                if 'AssociationId' not in addr:
                    recursos_orfãos.append({
                        'ResourceType': 'Elastic IP',
                        'Region': region,
                        'ResourceId': addr['PublicIp'],
                        'Details': f"Domain: {addr['Domain']}",
                        'CreateDate': 'N/A'
                    })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em {region}: {str(e)[:100]})")
            continue
            
    logger.info("--- 3: OTIMIZAÇÃO DE CUSTOS CONCLUÍDO ---")
    return recursos_orfãos, headers

# --- 4. EXECUÇÃO PRINCIPAL ---
if __name__ == "__main__":
    today_str = datetime.now().strftime("%d%m%Y")
    log_filename = f"inventario_aws_{today_str}.log"
    excel_filename = f"relatorio_aws_completo_{today_str}.xlsx"
    
    logger = setup_logger(log_filename)

    logger.info("======================================================")
    logger.info("INICIANDO SCRIPT DE INVENTÁRIO COMPLETO DA CONTA AWS")
    logger.info(f"Logs sendo salvos em: {log_filename}")
    logger.info("======================================================")

    relatorios_para_excel = {}

    logger.info("Buscando listas de regiões disponíveis...")
    lista_regioes_ec2 = get_all_aws_regions('ec2', logger)
    lista_regioes_lightsail = get_all_aws_regions('lightsail', logger)
    logger.info(f"Encontradas {len(lista_regioes_ec2)} regiões para EC2 e {len(lista_regioes_lightsail)} para Lightsail.")

    # --- Execução Pilar 1 ---
    dados_p1, headers_p1 = gerar_relatorio_1_computacao(lista_regioes_ec2, lista_regioes_lightsail, logger)
    write_to_csv('relatorio_computacao.csv', headers_p1, dados_p1, logger)
    relatorios_para_excel['Computacao'] = {'data': dados_p1, 'headers': headers_p1}
    logger.info("Tabela de Computação:\n" + tabulate(dados_p1, headers="keys", tablefmt="grid"))
    
    # --- Execução Pilar 2 ---
    (dados_p2_fw, headers_p2_fw), (dados_p2_iam, headers_p2_iam) = gerar_relatorio_2_seguranca(lista_regioes_ec2, logger)
    write_to_csv('relatorio_firewalls_abertos.csv', headers_p2_fw, dados_p2_fw, logger)
    write_to_csv('relatorio_usuarios_iam.csv', headers_p2_iam, dados_p2_iam, logger)
    relatorios_para_excel['Firewalls_Abertos'] = {'data': dados_p2_fw, 'headers': headers_p2_fw}
    relatorios_para_excel['Usuarios_IAM'] = {'data': dados_p2_iam, 'headers': headers_p2_iam}
    logger.info("Tabela de Firewalls Abertos:\n" + tabulate(dados_p2_fw, headers="keys", tablefmt="grid"))
    logger.info("Tabela de Usuários IAM:\n" + tabulate(dados_p2_iam, headers="keys", tablefmt="grid"))
    
    # --- Execução Pilar 3 ---
    dados_p3, headers_p3 = gerar_relatorio_3_custos(lista_regioes_ec2, logger)
    write_to_csv('relatorio_recursos_orfãos.csv', headers_p3, dados_p3, logger)
    relatorios_para_excel['Recursos_Orfaos'] = {'data': dados_p3, 'headers': headers_p3}
    logger.info("Tabela de Recursos Órfãos:\n" + tabulate(dados_p3, headers="keys", tablefmt="grid"))
    
    # --- Geração do arquivo Excel consolidado ---
    logger.info("\nIniciando geração do arquivo Excel consolidado...")
    write_to_excel(excel_filename, relatorios_para_excel, logger)

    logger.info("======================================================")
    logger.info("SCRIPT FINALIZADO.")
    logger.info("======================================================")