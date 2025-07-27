import boto3
import csv
from datetime import datetime

# --- Funções Auxiliares ---

def get_all_aws_regions(service_name, start_region='us-east-1'):
    """Obtém uma lista de todos os nomes de regiões para um determinado serviço."""
    try:
        client = boto3.client(service_name, region_name=start_region)
        if service_name == 'lightsail':
            return [region['name'] for region in client.get_regions()['regions']]
        else: # ec2
            return [region['RegionName'] for region in client.describe_regions()['Regions']]
    except Exception as e:
        print(f"Erro ao obter lista de regiões para {service_name}: {e}")
        return []

def write_to_csv(filename, headers, data_rows):
    """Escreve uma lista de dicionários em um arquivo CSV."""
    if not data_rows:
        print(f"Nenhum dado para escrever no arquivo {filename}. Arquivo não gerado.")
        return
    
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data_rows)
        print(f"Relatório gerado com sucesso: {filename}")
    except Exception as e:
        print(f"Erro ao escrever o arquivo {filename}: {e}")


def gerar_relatorio_1_computacao(ec2_regions, lightsail_regions):
    """Gera o inventário de todas as instâncias EC2 e Lightsail."""
    print("\n--- 1: INVENTÁRIO DE COMPUTAÇÃO ---")
    inventario = []
    headers = [
        'Serviço', 'Região', 'Proprietário (Tag)', 'Nome da Instância', 'ID da Instância', 'Status', 
        'Tipo de Instância', 'Data de Criação', 'IP Público', 'Tipo de IP', 'Backup Ativo?', 
        'Gerenciado por SSM?', 'SO (Base)'
    ]
    
    # --- Seção EC2 ---
    for region in ec2_regions:
        print(f"  -> Verificando EC2 em {region}...")
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
            # Adicionado um print do erro para melhor diagnóstico
            print(f"     (Acesso negado ou erro em {region}: {str(e)[:100]}... Pulando.)")
            continue

    # --- Seção Lightsail ---
    for region in lightsail_regions:
        print(f"  -> Verificando Lightsail em {region}...")
        try:
            lightsail = boto3.client('lightsail', region_name=region)
            static_ips_response = lightsail.get_static_ips()
            ips_estaticos_map = {ip['attachedTo']: ip['name'] for ip in static_ips_response.get('staticIps', []) if ip.get('isAttached')}
            instances_response = lightsail.get_instances()
            for instance in instances_response.get('instances', []):
                nome_instancia = instance['name']
                
                # << CORREÇÃO: Cria um dicionário com as mesmas chaves do cabeçalho >>
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
                # << CORREÇÃO: Usa a variável 'inventario' correta >>
                inventario.append(instancia_info)
        except Exception as e:
            print(f"     (Acesso negado ou erro em {region}: {str(e)[:100]}... Pulando.)")
            continue

    write_to_csv('relatorio_computacao.csv', headers, inventario)
    print("--- 1: INVENTÁRIO DE COMPUTAÇÃO CONCLUÍDO ---")

def gerar_relatorio_2_seguranca(ec2_regions):
    """Gera relatórios de segurança para firewalls e usuários IAM."""
    print("\n--- 2: ANÁLISE DE SEGURANÇA ---")
    
    # Relatório de Firewalls Abertos
    firewalls_abertos = []
    headers_fw = ['Região', 'ID do Security Group', 'Nome do Security Group', 'Porta Aberta', 'Origem Aberta', 'Descrição da Regra']
    for region in ec2_regions:
        print(f"  -> Verificando Firewalls em {region}...")
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
            print(f"     (Acesso negado ou erro em {region}. Pulando.)")
            continue
    write_to_csv('relatorio_firewalls_abertos.csv', headers_fw, firewalls_abertos)
    
    # Relatório de Usuários IAM
    print("  -> Verificando usuários IAM...")
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
        print(f"     Erro ao verificar usuários IAM: {e}")
    write_to_csv('relatorio_usuarios_iam.csv', headers_iam, usuarios_iam)
    
    print("--- 2: ANÁLISE DE SEGURANÇA CONCLUÍDO ---")


def gerar_relatorio_3_custos(ec2_regions):
    """Gera relatórios de otimização de custos para recursos órfãos."""
    print("\n--- 3: OTIMIZAÇÃO DE CUSTOS ---")
    recursos_orfãos = []
    headers = ['Tipo de Recurso', 'Região', 'ID do Recurso', 'Detalhes (Tamanho/Tipo)', 'Data de Criação']
    # << ALTERAÇÃO AQUI: Usa a lista de regiões recebida >>
    for region in ec2_regions:
        print(f"  -> Verificando Recursos Órfãos em {region}...")
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
            print(f"     (Acesso negado ou erro em {region}. Pulando.)")
            continue
            
    write_to_csv('relatorio_recursos_orfãos.csv', headers, recursos_orfãos)
    print("--- 3: OTIMIZAÇÃO DE CUSTOS CONCLUÍDO ---")

# --- Execução Principal ---
if __name__ == "__main__":
    print("======================================================")
    print("INICIANDO SCRIPT DE INVENTÁRIO COMPLETO DA CONTA AWS")
    print(f"Data da Execução: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("======================================================")
    
    # << ALTERAÇÃO AQUI: Busca as regiões uma única vez no início >>
    print("\nBuscando listas de regiões disponíveis...")
    lista_regioes_ec2 = get_all_aws_regions('ec2')
    lista_regioes_lightsail = get_all_aws_regions('lightsail')
    print(f"Encontradas {len(lista_regioes_ec2)} regiões para EC2 e {len(lista_regioes_lightsail)} para Lightsail.")
    
    # << ALTERAÇÃO AQUI: Passa as listas de regiões para as funções >>
    gerar_relatorio_1_computacao(lista_regioes_ec2, lista_regioes_lightsail)
    gerar_relatorio_2_seguranca(lista_regioes_ec2)
    gerar_relatorio_3_custos(lista_regioes_ec2)
    
    print("\nSCRIPT FINALIZADO.")