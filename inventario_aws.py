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
        else: # ec2 e rds
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
                    df = df[data_info['headers']] 
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
                else:
                    logger.warning(f"Nenhum dado para a aba '{sheet_name}'. Aba não será criada.")
        logger.info(f"Relatório Excel gerado com sucesso: {filename}")
    except Exception as e:
        logger.error(f"Erro ao escrever o arquivo Excel {filename}: {e}")

def format_tags(tags_list):
    """Formata uma lista de dicionários de tags em uma string única,
       aceitando chaves em maiúsculo (Key/Value) ou minúsculo (key/value)."""
    if not tags_list:
        return 'N/A'
    
    formatted_tags = []
    for tag in tags_list:
        # Procura por 'Key' ou 'key' e 'Value' ou 'value'
        key = tag.get('Key', tag.get('key'))
        value = tag.get('Value', tag.get('value'))
        if key is not None: # Garante que a tag tem uma chave
            formatted_tags.append(f"{key}={value}")
            
    return "; ".join(formatted_tags) if formatted_tags else 'N/A'

# --- 3. FUNÇÕES DOS PILARES ---

def gerar_relatorio_1_computacao(ec2_regions, lightsail_regions, logger):
    """Coleta dados de inventário de EC2 e Lightsail e os retorna."""
    logger.info("--- 1: INVENTÁRIO DE COMPUTAÇÃO ---")
    inventario = []
    
    # Nomes das colunas padronizados com a API da AWS.
    headers = [
        'Service', 'Region', 'Tag:Owner', 'Tag:Name', 'InstanceId', 'State', 
        'InstanceType', 'LaunchTime', 'PublicIpAddress', 'PrivateIpAddresses', 'Ipv6Addresses', 'IpType', 
        'BackupEnabled', 'IsSsmManaged', 'Tags'
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

                    tags_list = instance.get('Tags', [])
                    tags_str = format_tags(tags_list)
                    instance_name = next((tag['Value'] for tag in tags_list if tag['Key'] == 'Name'), 'N/A')

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
                        'IsSsmManaged': 'Yes' if inst_id in ssm_managed_ids else 'No',
                        'Tags': tags_str
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
                tags_str = format_tags(instance.get('tags', []))
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
                    'IsSsmManaged': 'N/A',
                    'Tags': tags_str
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
    # << CORREÇÃO >>: Cabeçalho ajustado para corresponder aos dados.
    headers_fw = ['Region', 'InstanceId', 'InstanceName', 'SecurityGroupId', 'OffendingRule', 'Source', 'InstanceTags']
    for region in ec2_regions:
        logger.info(f"  -> Verificando Firewalls e Instâncias em {region}...")
        try:
            ec2 = boto3.client('ec2', region_name=region)
            
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

            for reservation in ec2.describe_instances()['Reservations']:
                for instance in reservation['Instances']:
                    instance_tags = instance.get('Tags', [])
                    instance_name = next((tag['Value'] for tag in instance_tags if tag['Key'] == 'Name'), 'N/A')
                    for sg_anexado in instance.get('SecurityGroups', []):
                        sg_id = sg_anexado['GroupId']
                        if sg_id in regras_abertas_map:
                            for regra in regras_abertas_map[sg_id]:
                                # << CORREÇÃO >>: Chaves do dicionário agora correspondem ao cabeçalho.
                                firewalls_abertos.append({
                                    'Region': region,
                                    'InstanceId': instance['InstanceId'],
                                    'InstanceName': instance_name,
                                    'SecurityGroupId': sg_id,
                                    'OffendingRule': regra,
                                    'Source': '0.0.0.0/0',
                                    'InstanceTags': format_tags(instance_tags)
                                })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em {region}: {str(e)[:100]})")
            continue

    # Relatório de Usuários IAM (sem alterações nesta parte)
    logger.info("  -> Verificando usuários IAM...")
    usuarios_iam = []
    headers_iam = ['UserName', 'MfaEnabled', 'ConsoleAccess', 'CreateDate', 'PasswordLastUsed (GMT -03:00)', 'Tags']
    
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
            
            password_last_used_utc = user_detail.get('PasswordLastUsed')
            password_last_used_str = 'N/A'
            if password_last_used_utc:
                password_last_used_gmt3 = password_last_used_utc - timedelta(hours=3)
                password_last_used_str = password_last_used_gmt3.strftime("%Y-%m-%d %H:%M:%S")

            usuarios_iam.append({
                'UserName': user_name,
                'MfaEnabled': 'Yes' if mfa_devices else 'No',
                'ConsoleAccess': console_access,
                'CreateDate': user_detail['CreateDate'].strftime("%Y-%m-%d"),
                'PasswordLastUsed (GMT -03:00)': password_last_used_str,
                'Tags': format_tags(user_detail.get('Tags', []))
            })
    except Exception as e:
        logger.error(f"     Erro ao verificar usuários IAM: {e}")
    
    logger.info("--- 2: ANÁLISE DE SEGURANÇA CONCLUÍDO ---")
    return (firewalls_abertos, headers_fw), (usuarios_iam, headers_iam)

def gerar_relatorio_3_custos(ec2_regions, logger):
    """Coleta dados de otimização de custos para recursos órfãos, incluindo suas tags."""
    logger.info("--- 3: OTIMIZAÇÃO DE CUSTOS ---")
    recursos_orfãos = []
    headers = ['ResourceType', 'Region', 'ResourceId', 'Details', 'CreateDate', 'Tags']
    
    for region in ec2_regions:
        logger.info(f"  -> Verificando Recursos Órfãos em {region}...")
        try:
            ec2 = boto3.client('ec2', region_name=region)
            
            # Volumes EBS desanexados
            for vol in ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])['Volumes']:
                tags_str = format_tags(vol.get('Tags', []))
                recursos_orfãos.append({
                    'ResourceType': 'EBS Volume',
                    'Region': region,
                    'ResourceId': vol['VolumeId'],
                    'Details': f"{vol['Size']} GB / {vol['VolumeType']}",
                    'CreateDate': vol['CreateTime'].strftime("%Y-%m-%d"),
                    'Tags': tags_str
                })
            
            # Elastic IPs desanexados
            for addr in ec2.describe_addresses()['Addresses']:
                if 'AssociationId' not in addr:
                    tags_str = format_tags(addr.get('Tags', []))
                    recursos_orfãos.append({
                        'ResourceType': 'Elastic IP',
                        'Region': region,
                        'ResourceId': addr['PublicIp'],
                        'Details': f"Domain: {addr['Domain']}",
                        'CreateDate': 'N/A',
                        'Tags': tags_str
                    })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em {region}: {str(e)[:100]})")
            continue
            
    logger.info("--- 3: OTIMIZAÇÃO DE CUSTOS CONCLUÍDO ---")
    return recursos_orfãos, headers

def gerar_relatorio_4_armazenamento(logger):
    """Coleta dados de inventário de buckets S3, incluindo suas tags."""
    logger.info("--- 4: INVENTÁRIO DE ARMAZENAMENTO (S3) ---")
    s3_buckets = []

    headers = ['BucketName', 'CreationDate', 'Region', 'PublicAccessBlock', 'PolicyIsPublic', 'Tags']
    
    try:
        s3 = boto3.client('s3')
        response = s3.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            logger.info(f"  -> Verificando Bucket S3: {bucket_name}...")
            
            # Pega a região do bucket
            try:
                location = s3.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
                region = location if location else 'us-east-1'
            except Exception:
                region = "Acesso Negado"

            # Verifica o status do Block Public Access
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                block_status = f"BlockAll:{pab['BlockPublicAcls']}/{pab['BlockPublicPolicy']}/{pab['IgnorePublicAcls']}/{pab['RestrictPublicBuckets']}"
            except s3.exceptions.ClientError:
                block_status = "Não Configurado"
            
            # Verifica se a política torna o bucket público
            try:
                policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)['PolicyStatus']
                policy_is_public = 'Yes' if policy_status.get('IsPublic') else 'No'
            except s3.exceptions.ClientError:
                policy_is_public = "Sem Política"

            tags_str = 'N/A'
            try:
                tag_response = s3.get_bucket_tagging(Bucket=bucket_name)
                tags_str = format_tags(tag_response.get('TagSet', []))
            except s3.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchTagSet':
                    tags_str = 'Nenhuma Tag'
                else:
                    tags_str = 'Erro ao buscar tags'

            s3_buckets.append({
                'BucketName': bucket_name,
                'CreationDate': bucket['CreationDate'].strftime("%Y-%m-%d"),
                'Region': region,
                'PublicAccessBlock': block_status,
                'PolicyIsPublic': policy_is_public,
                'Tags': tags_str
            })
    except Exception as e:
        logger.error(f"     Erro crítico ao listar buckets S3: {e}")

    logger.info("--- 4: INVENTÁRIO DE ARMAZENAMENTO CONCLUÍDO ---")
    return s3_buckets, headers

def gerar_relatorio_5_banco_de_dados(ec2_regions, logger):
    """Coleta dados de inventário de instâncias RDS, incluindo suas tags."""
    logger.info("--- 5: INVENTÁRIO DE BANCO DE DADOS (RDS) ---")
    rds_instances = []
 
    headers = ['DBInstanceIdentifier', 'Region', 'DBInstanceStatus', 'DBInstanceClass', 'Engine', 'EngineVersion', 'PubliclyAccessible', 'MultiAZ', 'StorageType', 'AllocatedStorage', 'Tags']
    
    for region in ec2_regions:
        logger.info(f"  -> Verificando RDS em {region}...")
        try:
            rds = boto3.client('rds', region_name=region)
            paginator = rds.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    tags_str = format_tags(instance.get('TagList', []))
                    rds_instances.append({
                        'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                        'Region': region,
                        'DBInstanceStatus': instance['DBInstanceStatus'],
                        'DBInstanceClass': instance['DBInstanceClass'],
                        'Engine': instance['Engine'],
                        'EngineVersion': instance['EngineVersion'],
                        'PubliclyAccessible': 'Yes' if instance['PubliclyAccessible'] else 'No',
                        'MultiAZ': 'Yes' if instance['MultiAZ'] else 'No',
                        'StorageType': instance['StorageType'],
                        'AllocatedStorage': instance.get('AllocatedStorage', 'N/A'),
                        'Tags': tags_str
                    })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em RDS {region}: {str(e)[:100]})")
            continue
            
    logger.info("--- 5: INVENTÁRIO DE BANCO DE DADOS CONCLUÍDO ---")
    return rds_instances, headers

def gerar_relatorio_6_rede(ec2_regions, logger):
    """Coleta dados de inventário de VPCs e Subnets, incluindo suas tags."""
    logger.info("--- 6: INVENTÁRIO DE REDE (VPC) ---")
    vpcs, subnets = [], []
    headers_vpc = ['VpcId', 'Region', 'State', 'CidrBlock', 'IsDefault', 'Tag:Name', 'Tags']
    headers_subnet = ['SubnetId', 'Region', 'VpcId', 'State', 'CidrBlock', 'AvailabilityZone', 'AvailableIpAddressCount', 'MapPublicIpOnLaunch', 'Tag:Name', 'Tags']

    for region in ec2_regions:
        logger.info(f"  -> Verificando VPC/Subnets em {region}...")
        try:
            ec2 = boto3.client('ec2', region_name=region)
            # Coleta de VPCs
            for vpc in ec2.describe_vpcs()['Vpcs']:
                tags_list = vpc.get('Tags', [])
                tags_str = format_tags(tags_list)
                tag_name = next((tag['Value'] for tag in tags_list if tag['Key'] == 'Name'), 'N/A')
                vpcs.append({
                    'VpcId': vpc['VpcId'],
                    'Region': region,
                    'State': vpc['State'],
                    'CidrBlock': vpc['CidrBlock'],
                    'IsDefault': 'Yes' if vpc['IsDefault'] else 'No',
                    'Tag:Name': tag_name,
                    'Tags': tags_str
                })
            # Coleta de Subnets
            for subnet in ec2.describe_subnets()['Subnets']:
                tags_list = subnet.get('Tags', [])
                tags_str = format_tags(tags_list)
                tag_name = next((tag['Value'] for tag in tags_list if tag['Key'] == 'Name'), 'N/A')
                subnets.append({
                    'SubnetId': subnet['SubnetId'],
                    'Region': region,
                    'VpcId': subnet['VpcId'],
                    'State': subnet['State'],
                    'CidrBlock': subnet['CidrBlock'],
                    'AvailabilityZone': subnet['AvailabilityZone'],
                    'AvailableIpAddressCount': subnet['AvailableIpAddressCount'],
                    'MapPublicIpOnLaunch': 'Yes' if subnet['MapPublicIpOnLaunch'] else 'No',
                    'Tag:Name': tag_name,
                    'Tags': tags_str
                })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em Rede {region}: {str(e)[:100]})")
            continue

    logger.info("--- 6: INVENTÁRIO DE REDE CONCLUÍDO ---")
    return (vpcs, headers_vpc), (subnets, headers_subnet)

# --- 4. EXECUÇÃO PRINCIPAL ---
if __name__ == "__main__":
    today_str = datetime.now().strftime("%d%m%Y")
    log_filename = f"inventario_aws_total_{today_str}.log"
    excel_filename = f"relatorio_aws_total_{today_str}.xlsx"
    
    logger = setup_logger(log_filename)

    logger.info("======================================================")
    logger.info("INICIANDO SCRIPT DE INVENTÁRIO TOTAL DA CONTA AWS")
    logger.info(f"Logs sendo salvos em: {log_filename}")
    logger.info("======================================================")

    relatorios_para_excel = {}

    logger.info("Buscando listas de regiões disponíveis...")
    lista_regioes_ec2 = get_all_aws_regions('ec2', logger)
    lista_regioes_lightsail = get_all_aws_regions('lightsail', logger)
    logger.info(f"Encontradas {len(lista_regioes_ec2)} regiões para EC2/RDS/VPC e {len(lista_regioes_lightsail)} para Lightsail.")

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

    # --- Execução Pilar 4: Armazenamento ---
    dados_p4, headers_p4 = gerar_relatorio_4_armazenamento(logger)
    write_to_csv('relatorio_s3_buckets.csv', headers_p4, dados_p4, logger)
    relatorios_para_excel['S3_Buckets'] = {'data': dados_p4, 'headers': headers_p4}
    logger.info("Tabela de S3 Buckets:\n" + tabulate(dados_p4, headers="keys", tablefmt="grid"))
    
    # --- Execução Pilar 5: Banco de Dados ---
    dados_p5, headers_p5 = gerar_relatorio_5_banco_de_dados(lista_regioes_ec2, logger)
    write_to_csv('relatorio_rds_instances.csv', headers_p5, dados_p5, logger)
    relatorios_para_excel['RDS_Instances'] = {'data': dados_p5, 'headers': headers_p5}
    logger.info("Tabela de RDS Instances:\n" + tabulate(dados_p5, headers="keys", tablefmt="grid"))
    
    # --- Execução Pilar 6: Rede ---
    (dados_p6_vpc, headers_p6_vpc), (dados_p6_subnet, headers_p6_subnet) = gerar_relatorio_6_rede(lista_regioes_ec2, logger)
    write_to_csv('relatorio_vpcs.csv', headers_p6_vpc, dados_p6_vpc, logger)
    write_to_csv('relatorio_subnets.csv', headers_p6_subnet, dados_p6_subnet, logger)
    relatorios_para_excel['VPCs'] = {'data': dados_p6_vpc, 'headers': headers_p6_vpc}
    relatorios_para_excel['Subnets'] = {'data': dados_p6_subnet, 'headers': headers_p6_subnet}
    logger.info("Tabela de VPCs:\n" + tabulate(dados_p6_vpc, headers="keys", tablefmt="grid"))
    logger.info("Tabela de Subnets:\n" + tabulate(dados_p6_subnet, headers="keys", tablefmt="grid"))
    
    # --- Geração do arquivo Excel consolidado ---
    logger.info("\nIniciando geração do arquivo Excel consolidado...")
    write_to_excel(excel_filename, relatorios_para_excel, logger)

    logger.info("======================================================")
    logger.info("SCRIPT DE INVENTÁRIO TOTAL FINALIZADO.")
    logger.info("======================================================")