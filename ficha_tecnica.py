# -*- coding: utf-8 -*-
import boto3
import logging
import json
from datetime import datetime, timedelta
import os


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
# (Estas funções permanecem as mesmas)
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


def format_tags(tags_list):
    """Formata uma lista de dicionários de tags em uma string única."""
    if not tags_list:
        return 'N/A'
    
    formatted_tags = []
    for tag in tags_list:
        key = tag.get('Key', tag.get('key'))
        value = tag.get('Value', tag.get('value'))
        if key is not None:
            formatted_tags.append(f"{key}={value}")
            
    return "; ".join(formatted_tags) if formatted_tags else 'N/A'

# --- 3. FUNÇÕES DE COLETA DE DADOS ---

def gerar_relatorio_ec2(ec2_regions, logger):
    """Coleta dados de inventário de instâncias EC2, com detalhes avançados de custo, segurança e performance."""
    logger.info("--- 1a: INVENTÁRIO DE COMPUTAÇÃO (EC2) ---")
    inventario_ec2 = []
    headers_ec2 = [
        'Region', 'Tag:Name', 'InstanceId', 'State', 'PlatformDetails', 'InstanceType', 
        'VcpuCount', 'MemoryInfo(GiB)', 'CPU_Avg_7d (%)', 'AttachedVolumes', # Performance & Discos
        'VpcId', 'SubnetId', 'LaunchTime', 'PublicIpAddress', 'PrivateIpAddresses', 'IpType', 
        'IamInstanceProfile', 'IMDSv2_Enforced', # Segurança
        'SecurityGroups', 'InboundRules', 'OutboundRules', 'Ipv6Addresses',
        'BackupEnabled', 'IsSsmManaged', 'EstimatedMonthlyCost', 'Tags' # Custo
    ]
    
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()['Account']

    for region in ec2_regions:
        logger.info(f"  -> Verificando EC2 em {region}...")
        try:
            # Clientes para os serviços necessários na região
            ec2 = boto3.client('ec2', region_name=region)
            ssm = boto3.client('ssm', region_name=region)
            backup = boto3.client('backup', region_name=region)
            cloudwatch = boto3.client('cloudwatch', region_name=region)
            pricing = boto3.client('pricing', region_name='us-east-1') # API de Preços é apenas em us-east-1

            ssm_managed_ids = {info['InstanceId'] for info in ssm.describe_instance_information()['InstanceInformationList']}
            backup_protected_arns = {res['ResourceArn'] for res in backup.list_protected_resources()['Results']}
            
            instance_types_cache = {}
            pricing_cache = {}
            
            # Mapeamento de Security Groups (código existente)
            sg_rules_map = {}
            for sg in ec2.describe_security_groups()['SecurityGroups']:
                inbound_rules, outbound_rules = [], []
                
                # Regras de Entrada (Inbound)
                for perm in sg.get('IpPermissions', []):
                    protocol = "All" if perm.get('IpProtocol') == '-1' else perm.get('IpProtocol', 'N/A')
                    port_info = f"Port(s): {perm.get('FromPort', 'All')}, Protocolo: {protocol}"
                    
                    if perm.get('IpRanges'):
                        for ip_range in perm['IpRanges']:
                            description = ip_range.get('Description', 'Sem descrição')
                            inbound_rules.append(f"{port_info}, Origem: {ip_range.get('CidrIp', 'N/A')}, Descrição: {description}")
                    if perm.get('UserIdGroupPairs'):
                        for group in perm['UserIdGroupPairs']:
                            description = group.get('Description', 'Sem descrição')
                            inbound_rules.append(f"{port_info}, Origem: {group.get('GroupId', 'N/A')}, Descrição: {description}")

                # Regras de Saída (Outbound)
                for perm in sg.get('IpPermissionsEgress', []):
                    protocol = "All" if perm.get('IpProtocol') == '-1' else perm.get('IpProtocol', 'N/A')
                    port_info = f"Porta(s): {perm.get('FromPort', 'All')}, Protocolo: {protocol}"
                    
                    if perm.get('IpRanges'):
                        for ip_range in perm['IpRanges']:
                            description = ip_range.get('Description', 'Sem descrição')
                            outbound_rules.append(f"{port_info}, Destino: {ip_range.get('CidrIp', 'N/A')}, Descrição: {description}")
                    if perm.get('UserIdGroupPairs'):
                        for group in perm['UserIdGroupPairs']:
                            description = group.get('Description', 'Sem descrição')
                            outbound_rules.append(f"{port_info}, Destino: {group.get('GroupId', 'N/A')}, Descrição: {description}")

                sg_rules_map[sg['GroupId']] = {
                    "inbound": "\n".join(inbound_rules) if inbound_rules else "Nenhuma",
                    "outbound": "\n".join(outbound_rules) if outbound_rules else "Nenhuma"
                }

            response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}])
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    inst_id = instance['InstanceId']
                    instance_type = instance['InstanceType']
                    
                    # Coleta de Métricas de Performance (CloudWatch)
                    try:
                        cw_response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName='CPUUtilization',
                            Dimensions=[{'Name': 'InstanceId', 'Value': inst_id}],
                            StartTime=datetime.now(datetime.UTC) - timedelta(days=7),
                            EndTime=datetime.now(datetime.UTC),
                            Period=86400,
                            Statistics=['Average']
                        )
                        cpu_avg_7d = f"{cw_response['Datapoints'][0]['Average']:.2f}%" if cw_response['Datapoints'] else "N/A"
                    except Exception:
                        cpu_avg_7d = "Erro ao Coletar"

                    # Estimativa de Custo Mensal
                    if instance_type not in pricing_cache:
                        try:
                            price_response = pricing.get_products(
                                ServiceCode='AmazonEC2',
                                Filters=[
                                    {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_type},
                                    {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': region},
                                    {'Type': 'TERM_MATCH', 'Field': 'operatingSystem', 'Value': 'Linux'}, # Simplificação para Linux
                                    {'Type': 'TERM_MATCH', 'Field': 'preInstalledSw', 'Value': 'NA'},
                                    {'Type': 'TERM_MATCH', 'Field': 'tenancy', 'Value': 'Shared'}
                                ]
                            )
                            price_data = json.loads(price_response['PriceList'][0])
                            on_demand_terms = price_data['terms']['OnDemand']
                            price_per_hour = float(list(list(on_demand_terms.values())[0]['priceDimensions'].values())[0]['pricePerUnit']['USD'])
                            pricing_cache[instance_type] = f"USD ${price_per_hour * 730:.2f}" # 730 horas/mês
                        except Exception:
                            pricing_cache[instance_type] = "N/A"
                    estimated_cost = pricing_cache[instance_type]

                    # Detalhes de todos os discos anexados
                    attached_volumes = []
                    for bd in instance.get('BlockDeviceMappings', []):
                        vol_id = bd.get('Ebs', {}).get('VolumeId')
                        if vol_id:
                            attached_volumes.append(f"{bd.get('DeviceName')}({vol_id})")
                    
                    if instance_type not in instance_types_cache:
                        try:
                            type_info = ec2.describe_instance_types(InstanceTypes=[instance_type])['InstanceTypes'][0]
                            instance_types_cache[instance_type] = type_info
                        except Exception as e:
                            logger.warning(f"Não foi possível obter detalhes para o tipo de instância {instance_type}: {e}")
                            instance_types_cache[instance_type] = {}
                    
                    type_details = instance_types_cache[instance_type]
                    vcpu_count = type_details.get('VCpuInfo', {}).get('DefaultVCpus', 'N/A')
                    memory_mib = type_details.get('MemoryInfo', {}).get('SizeInMiB', 0)
                    memory_gib = round(memory_mib / 1024, 2) if memory_mib > 0 else 'N/A'
                    
                    root_device_name = instance.get('RootDeviceName', 'N/A')
                    root_device_size = "N/A"
                    for bd in instance.get('BlockDeviceMappings', []):
                        if bd.get('DeviceName') == root_device_name:
                           volume_id = bd.get('Ebs', {}).get('VolumeId')
                           if volume_id:
                               vol_details = ec2.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]
                               root_device_size = f"{vol_details.get('Size')} GiB"
                    
                    root_device_info = f"{root_device_name} ({root_device_size})"

                    tags_list = instance.get('Tags', [])
                    instance_name = next((tag['Value'] for tag in tags_list if tag['Key'] == 'Name'), 'N/A')
                    
                    private_ips = [ni.get('PrivateIpAddress') for ni in instance.get('NetworkInterfaces', [])]

                    sg_details = [f"{sg['GroupName']}({sg['GroupId']})" for sg in instance.get('SecurityGroups', [])]
                    sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    
                    all_inbound_rules = "\n---\n".join([sg_rules_map.get(sg_id, {}).get('inbound', '') for sg_id in sg_ids])
                    all_outbound_rules = "\n---\n".join([sg_rules_map.get(sg_id, {}).get('outbound', '') for sg_id in sg_ids])
                    
                    net_interfaces = instance.get('NetworkInterfaces', [])
                    ip_type = "Dynamic"
                    if net_interfaces and 'Association' in net_interfaces[0]:
                        ip_type = "Elastic"
                    
                    ipv6_ips = []
                    for ni in instance.get('NetworkInterfaces', []):
                        ipv6_ips.extend([ipv6['Ipv6Address'] for ipv6 in ni.get('Ipv6Addresses', [])])
                    
                    # Coleta de IAM Profile e status do IMDSv2
                    iam_profile_arn = instance.get('IamInstanceProfile', {}).get('Arn', 'N/A')
                    imds_v2_enforced = "Yes" if instance.get('MetadataOptions', {}).get('HttpTokens') == 'required' else 'No'

                    platform_details = instance.get('PlatformDetails', 'N/A')

                    inventario_ec2.append({
                        'Region': region,
                        'Tag:Name': instance_name,
                        'InstanceId': inst_id,
                        'State': instance['State']['Name'],
                        'PlatformDetails': platform_details,
                        'InstanceType': instance_type,
                        'VcpuCount': vcpu_count,
                        'MemoryInfo(GiB)': memory_gib,
                        'CPU_Avg_7d (%)': cpu_avg_7d,
                        'AttachedVolumes': "; ".join(attached_volumes),
                        'VpcId': instance.get('VpcId', 'N/A'),
                        'SubnetId': instance.get('SubnetId', 'N/A'),
                        'LaunchTime': instance['LaunchTime'].strftime("%Y-%m-%d"),
                        'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                        'PrivateIpAddresses': ", ".join(filter(None, private_ips)),
                        'IpType': ip_type,
                        'IamInstanceProfile': iam_profile_arn,
                        'IMDSv2_Enforced': imds_v2_enforced,
                        'SecurityGroups': ",\n".join(sg_details),
                        'InboundRules': all_inbound_rules,
                        'OutboundRules': all_outbound_rules,
                        'Ipv6Addresses': ", ".join(filter(None, ipv6_ips)),
                        'BackupEnabled': 'Yes' if f'arn:aws:ec2:{region}:{account_id}:instance/{inst_id}' in backup_protected_arns else 'No',
                        'IsSsmManaged': 'Yes' if inst_id in ssm_managed_ids else 'No',
                        'EstimatedMonthlyCost': estimated_cost,
                        'Tags': format_tags(tags_list)
                    })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em EC2 {region}: {e})")
            continue
    
    logger.info("--- 1a: INVENTÁRIO DE EC2 CONCLUÍDO ---")
    return inventario_ec2, headers_ec2

def gerar_relatorio_lightsail(lightsail_regions, logger):
    """Coleta dados de inventário de instâncias Lightsail, incluindo recursos de hardware e regras de firewall."""
    logger.info("--- 1b: INVENTÁRIO DE COMPUTAÇÃO (Lightsail) ---")
    inventario_lightsail = []
    headers_lightsail = [
        'Region', 'Name', 'Arn', 'State', 'BundleId', 
        'VcpuCount', 'RamSizeInGb', 'DiskSizeInGb',
        'BlueprintId', 'CreatedAt', 'PublicIpAddress', 'PrivateIpAddress', 'IpType', 
        'Ipv6Addresses', 'AutoSnapshotEnabled', 'FirewallRules', 'Tags'
    ]

    for region in lightsail_regions:
        logger.info(f"  -> Verificando Lightsail em {region}...")
        try:
            lightsail = boto3.client('lightsail', region_name=region)
            ips_estaticos_map = {ip['attachedTo']: ip['name'] for ip in lightsail.get_static_ips().get('staticIps', []) if ip.get('isAttached')}
            for instance in lightsail.get_instances().get('instances', []):
                nome_instancia = instance['name']
                
                firewall_rules = []
                port_states = lightsail.get_instance_port_states(instanceName=nome_instancia)['portStates']
                for rule in port_states:
                    if rule.get('state') == 'open':
                        # Formata a porta de forma inteligente
                        from_port = rule.get('fromPort', 'All')
                        to_port = rule.get('toPort', 'All')
                        port_str = f"Porta: {from_port}" if from_port == to_port else f"Portas: {from_port}-{to_port}"

                        # Padroniza o protocolo
                        protocol = rule.get('protocol', 'all').upper()

                        # Formata as origens (IPv4 e IPv6)
                        cidrs = rule.get('cidrs', [])
                        ipv6_cidrs = rule.get('ipv6Cidrs', [])
                        all_sources = cidrs + ipv6_cidrs
                        
                        source_str = ", ".join(all_sources) if all_sources else "N/A"
                        if "0.0.0.0/0" in source_str:
                            source_str = source_str.replace("0.0.0.0/0", "Qualquer Lugar (IPv4)")

                        firewall_rules.append(f"{port_str}, Protocolo: {protocol}, Origem: {source_str}")
                
                
                hardware = instance.get('hardware', {})
                disks = hardware.get('disks', [{}])
                disk_size = disks[0].get('sizeInGb', 'N/A') if disks else 'N/A'

                inventario_lightsail.append({
                    'Region': region,
                    'Name': nome_instancia,
                    'Arn': instance['arn'],
                    'State': instance['state']['name'],
                    'BundleId': instance['bundleId'],
                    'VcpuCount': hardware.get('cpuCount', 'N/A'),
                    'RamSizeInGb': hardware.get('ramSizeInGb', 'N/A'),
                    'DiskSizeInGb': disk_size,
                    'BlueprintId': instance['blueprintId'],
                    'CreatedAt': instance['createdAt'].strftime("%Y-%m-%d"),
                    'PublicIpAddress': instance.get('publicIpAddress', 'N/A'),
                    'PrivateIpAddress': instance.get('privateIpAddress', 'N/A'),
                    'IpType': "Static" if nome_instancia in ips_estaticos_map else "Dynamic",
                    'Ipv6Addresses': ", ".join(instance.get('ipv6Addresses', [])),
                    'AutoSnapshotEnabled': 'Yes' if instance.get('isStaticIp') else 'No',
                    'FirewallRules': "\n".join(firewall_rules) if firewall_rules else "Nenhuma",
                    'Tags': format_tags(instance.get('tags', []))
                })
        except Exception as e:
            logger.error(f"     (Acesso negado ou erro em Lightsail {region}: {str(e)[:100]})")
            continue
            
    logger.info("--- 1b: INVENTÁRIO DE LIGHTSAIL CONCLUÍDO ---")
    return inventario_lightsail, headers_lightsail

# --- 4. NOVA FUNÇÃO PARA GERAR ARQUIVOS DE TEXTO ---

def gerar_fichas_individuais(dados_ec2, dados_lightsail, logger):
    """Gera um arquivo de texto detalhado para cada instância."""
    
    output_dir = "inventario_por_instancia"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"Diretório '{output_dir}' criado para salvar as fichas.")

    # Processa instâncias EC2
    logger.info(f"Gerando {len(dados_ec2)} fichas para instâncias EC2...")
    for instance in dados_ec2:
        instance_id = instance['InstanceId']
        # Limpa o nome do arquivo para evitar caracteres inválidos
        instance_name = ''.join(c for c in instance['Tag:Name'] if c.isalnum() or c in (' ', '_')).rstrip()
        filename = os.path.join(output_dir, f"EC2_{instance_name}_{instance_id}.txt")

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"=============================================================\n")
            f.write(f" FICHA TÉCNICA DA INSTÂNCIA: {instance.get('Tag:Name')} ({instance_id})\n")
            f.write(f"=============================================================\n\n")

            f.write(f"[ General Information ]\n")
            f.write(f"  Service             : EC2\n")
            f.write(f"  Region              : {instance.get('Region')}\n")
            f.write(f"  State               : {instance.get('State')}\n")
            f.write(f"  PlatformDetails (OS): {instance.get('PlatformDetails')}\n")
            f.write(f"  LaunchTime          : {instance.get('LaunchTime')}\n")
            f.write(f"  Tags                : {instance.get('Tags')}\n\n")

            f.write(f"[ Hardware & Performance ]\n")
            f.write(f"  InstanceType        : {instance.get('InstanceType')}\n")
            f.write(f"  VcpuCount           : {instance.get('VcpuCount')}\n")
            f.write(f"  MemoryInfo(GiB)     : {instance.get('MemoryInfo(GiB)')}\n")
            f.write(f"  CPU_Avg_7d (%)      : {instance.get('CPU_Avg_7d (%)')}\n")
            f.write(f"  AttachedVolumes     : {instance.get('AttachedVolumes')}\n\n")
            
            f.write(f"[ Cost ]\n")
            f.write(f"  EstimatedMonthlyCost: {instance.get('EstimatedMonthlyCost')}\n\n")

            f.write(f"[ Network Configuration ]\n")
            f.write(f"  VpcId               : {instance.get('VpcId')}\n")
            f.write(f"  SubnetId            : {instance.get('SubnetId')}\n")
            f.write(f"  PublicIpAddress     : {instance.get('PublicIpAddress')}\n")
            f.write(f"  IpType              : {instance.get('IpType')}\n")
            f.write(f"  PrivateIpAddresses  : {instance.get('PrivateIpAddresses')}\n")
            f.write(f"  Ipv6Addresses       : {instance.get('Ipv6Addresses')}\n\n")

            f.write(f"[ Security ]\n")
            f.write(f"  IamInstanceProfile  : {instance.get('IamInstanceProfile')}\n")
            f.write(f"  IMDSv2_Enforced     : {instance.get('IMDSv2_Enforced')}\n")
            f.write(f"  SecurityGroups      :\n  {instance.get('SecurityGroups', '').replace(',\\n', '\\n  ')}\n\n")
            f.write(f"  InboundRules        :\n  {instance.get('InboundRules', '').replace('\\n', '\\n  ')}\n\n")
            f.write(f"  OutboundRules       :\n  {instance.get('OutboundRules', '').replace('\\n', '\\n  ')}\n\n")

            f.write(f"[ Management & Backup ]\n")
            f.write(f"  IsSsmManaged        : {instance.get('IsSsmManaged')}\n")
            f.write(f"  BackupEnabled       : {instance.get('BackupEnabled')}\n")

    # Processa instâncias Lightsail 
    logger.info(f"Gerando {len(dados_lightsail)} fichas para instâncias Lightsail...")
    for instance in dados_lightsail:
        instance_name_safe = instance['Name'].replace(" ", "_").replace("/", "_")
        filename = os.path.join(output_dir, f"Lightsail_{instance_name_safe}.txt")

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"=============================================================\n")
            f.write(f" FICHA TÉCNICA DA INSTÂNCIA: {instance.get('Name')}\n")
            f.write(f"=============================================================\n\n")

            f.write(f"[ General Information ]\n")
            f.write(f"  Service             : Lightsail\n")
            f.write(f"  Region              : {instance.get('Region')}\n")
            f.write(f"  State               : {instance.get('State')}\n")
            f.write(f"  CreatedAt           : {instance.get('CreatedAt')}\n")
            f.write(f"  BlueprintId (OS)    : {instance.get('BlueprintId')}\n")
            f.write(f"  Tags                : {instance.get('Tags')}\n\n")

            f.write(f"[ Hardware Resources ]\n")
            f.write(f"  BundleId (Plan)     : {instance.get('BundleId')}\n")
            f.write(f"  VcpuCount           : {instance.get('VcpuCount')}\n")
            f.write(f"  RamSizeInGb         : {instance.get('RamSizeInGb')}\n")
            f.write(f"  DiskSizeInGb        : {instance.get('DiskSizeInGb')}\n\n")
            
            f.write(f"[ Network Configuration ]\n")
            f.write(f"  PublicIpAddress     : {instance.get('PublicIpAddress')}\n")
            f.write(f"  IpType              : {instance.get('IpType')}\n")
            f.write(f"  PrivateIpAddress    : {instance.get('PrivateIpAddress')}\n")
            f.write(f"  Ipv6Addresses       : {instance.get('Ipv6Addresses')}\n\n")

            f.write(f"[ Security ]\n")
            f.write(f"  FirewallRules       :\n  {instance.get('FirewallRules', '').replace('\\n', '\\n  ')}\n\n")

            f.write(f"[ Management & Backup ]\n")
            f.write(f"  AutoSnapshotEnabled : {instance.get('AutoSnapshotEnabled')}\n")
            
    logger.info("Geração de fichas individuais concluída.")

def concatenar_fichas(output_dir, logger):
    """Lê todos os arquivos .txt de um diretório e os concatena em um único arquivo."""
    logger.info("Iniciando a concatenação das fichas individuais...")
    try:
        # Lista todos os arquivos .txt no diretório de saída
        files_to_concat = sorted([f for f in os.listdir(output_dir) if f.endswith('.txt')])
        
        if not files_to_concat:
            logger.warning(f"Nenhum arquivo .txt encontrado no diretório '{output_dir}' para concatenar.")
            return

        today_str = datetime.now().strftime("%d%m%Y")
        consolidated_filename = f"inventario_consolidado_{today_str}.txt"

        with open(consolidated_filename, 'w', encoding='utf-8') as outfile:
            for i, filename in enumerate(files_to_concat):
                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'r', encoding='utf-8') as infile:
                    outfile.write(infile.read())
                
                # Adiciona um separador entre os arquivos, exceto após o último
                if i < len(files_to_concat) - 1:
                    outfile.write("\n\n" + "="*80 + "\n\n")
        
        logger.info(f"Todas as {len(files_to_concat)} fichas foram consolidadas com sucesso em: {consolidated_filename}")

    except Exception as e:
        logger.error(f"Ocorreu um erro durante a concatenação dos arquivos: {e}")

# --- 5. EXECUÇÃO PRINCIPAL ---
if __name__ == "__main__":
    today_str = datetime.now().strftime("%d%m%Y")
    log_filename = f"gerador_fichas_{today_str}.log"
    
    logger = setup_logger(log_filename)

    logger.info("======================================================")
    logger.info("INICIANDO SCRIPT DE GERAÇÃO DE FICHAS TÉCNICAS")
    logger.info(f"Logs sendo salvos em: {log_filename}")
    logger.info("======================================================")

    # Coleta os dados (passo demorado)
    logger.info("Buscando listas de regiões disponíveis...")
    lista_regioes_ec2 = get_all_aws_regions('ec2', logger)
    lista_regioes_lightsail = get_all_aws_regions('lightsail', logger)
    
    logger.info("Coletando dados de instâncias EC2 e Lightsail...")
    dados_ec2, _ = gerar_relatorio_ec2(lista_regioes_ec2, logger)
    dados_lightsail, _ = gerar_relatorio_lightsail(lista_regioes_lightsail, logger)

    # Gera as fichas de texto com base nos dados coletados
    gerar_fichas_individuais(dados_ec2, dados_lightsail, logger)
    output_directory = "inventario_por_instancia"
    concatenar_fichas(output_directory, logger)

    logger.info("======================================================")
    logger.info("SCRIPT FINALIZADO.")
    logger.info("======================================================")