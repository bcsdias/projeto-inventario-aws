import boto3
import csv
from datetime import datetime

def gerar_inventario_geral():
    """
    Gera um inventário completo em CSV de todas as instâncias EC2 e Lightsail
    em todas as regiões da AWS.
    """
    # Lista para armazenar os dados padronizados de todas as instâncias
    inventario_final = []
    
    # Cabeçalhos para o nosso CSV final
    headers = [
        'Serviço', 'Região', 'Nome', 'ID', 'Tipo', 'Status', 
        'IP Público', 'IP Privado', 'Tipo de IP', 'SO (Base)'
    ]

    # --- Parte 1: Inventário de Instâncias EC2 em todas as regiões ---
    print("Iniciando varredura de instâncias EC2 em todas as regiões...")
    try:
        # Pega a lista de todas as regiões disponíveis para o serviço EC2
        ec2_main_client = boto3.client('ec2', region_name='us-east-1')
        regions = ec2_main_client.describe_regions()['Regions']
        region_names = [region['RegionName'] for region in regions]

        for region in region_names:
            print(f"  -> Verificando EC2 na região: {region}...")
            try:
                ec2 = boto3.client('ec2', region_name=region)
                paginator = ec2.get_paginator('describe-instances')
                pages = paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}])
                
                for page in pages:
                    for reservation in page['Reservations']:
                        for instance in reservation['Instances']:
                            nome_tag = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
                            
                            # Verifica se o IP é Elástico (Estático)
                            tipo_ip = "Estático (Elastic IP)" if 'Association' in instance.get('NetworkInterfaces', [{}])[0] else "Dinâmico"

                            instancia_info = {
                                'Serviço': 'EC2',
                                'Região': region,
                                'Nome': nome_tag,
                                'ID': instance['InstanceId'],
                                'Tipo': instance['InstanceType'],
                                'Status': instance['State']['Name'],
                                'IP Público': instance.get('PublicIpAddress', 'N/A'),
                                'IP Privado': instance.get('PrivateIpAddress', 'N/A'),
                                'Tipo de IP': tipo_ip,
                                'SO (Base)': instance.get('PlatformDetails', 'Linux/UNIX')
                            }
                            inventario_final.append(instancia_info)
            except Exception as e:
                if "AuthFailure" in str(e) or "UnauthorizedOperation" in str(e):
                    print(f"     (Região {region} desabilitada ou sem permissão, pulando.)")
                else:
                    print(f"     Erro inesperado em {region}: {e}")
    except Exception as e:
        print(f"Erro ao listar regiões EC2: {e}")

    # --- Parte 2: Inventário de Instâncias Lightsail em todas as regiões ---
    print("\nIniciando varredura de instâncias Lightsail em todas as regiões...")
    try:
        # Lightsail usa sua própria chamada para listar regiões
        lightsail_main_client = boto3.client('lightsail', region_name='us-east-1')
        regions = lightsail_main_client.get_regions(includeAvailabilityZones=False)['regions']
        region_names = [region['name'] for region in regions]

        for region in region_names:
            print(f"  -> Verificando Lightsail na região: {region}...")
            try:
                lightsail = boto3.client('lightsail', region_name=region)
                
                # Mapa de IPs estáticos para a região atual
                static_ips_response = lightsail.get_static_ips()
                ips_estaticos_map = {ip['attachedTo']: ip['name'] for ip in static_ips_response.get('staticIps', []) if ip.get('isAttached')}

                # Lista de instâncias na região atual
                instances_response = lightsail.get_instances()
                for instance in instances_response.get('instances', []):
                    nome_instancia = instance['name']
                    tipo_ip = "Estático" if nome_instancia in ips_estaticos_map else "Dinâmico"
                    
                    instancia_info = {
                        'Serviço': 'Lightsail',
                        'Região': region,
                        'Nome': nome_instancia,
                        'ID': instance['arn'],
                        'Tipo': instance['bundleId'],
                        'Status': instance['state']['name'],
                        'IP Público': instance.get('publicIpAddress', 'N/A'),
                        'IP Privado': instance.get('privateIpAddress', 'N/A'),
                        'Tipo de IP': tipo_ip,
                        'SO (Base)': instance['blueprintId']
                    }
                    inventario_final.append(instancia_info)
            except Exception as e:
                if "AuthFailure" in str(e) or "UnauthorizedOperation" in str(e):
                    print(f"     (Região {region} desabilitada ou sem permissão, pulando.)")
                else:
                    print(f"     Erro inesperado em {region}: {e}")
    except Exception as e:
        print(f"Erro ao listar regiões Lightsail: {e}")
    
    # --- Parte 3: Escrever o resultado consolidado em um arquivo CSV ---
    if not inventario_final:
        print("\nNenhuma instância encontrada em nenhuma região.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    csv_filename = f"inventario_aws_completo_{timestamp}.csv"
    
    print(f"\nEscrevendo inventário completo no arquivo: {csv_filename}...")
    
    try:
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(inventario_final)
        print("\nInventário gerado com sucesso!")
    except Exception as e:
        print(f"\nErro ao escrever o arquivo CSV: {e}")


# Executa a função principal
if __name__ == "__main__":
    gerar_inventario_geral()
