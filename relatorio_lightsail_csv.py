import boto3
import csv
from datetime import datetime

def gerar_relatorio_lightsail_csv():
    """
    Gera um relatório CSV completo das instâncias Lightsail,
    identificando corretamente os IPs estáticos e dinâmicos.
    """
    try:
        # Altere 'us-east-1' se a sua região principal for outra.
        lightsail = boto3.client('lightsail', region_name='us-east-1')
        
        # --- Passo 1: Obter a "fonte da verdade" sobre IPs estáticos ---
        print("Buscando IPs estáticos...")
        static_ips_response = lightsail.get_static_ips()
        
        ips_estaticos_map = {
            ip['attachedTo']: ip['name'] 
            for ip in static_ips_response.get('staticIps', []) if ip.get('isAttached')
        }
        print(f"Encontrados {len(ips_estaticos_map)} IPs estáticos em uso.")

        # --- Passo 2: Obter todos os detalhes das instâncias ---
        print("Buscando detalhes das instâncias...")
        instances_response = lightsail.get_instances()
        instances = instances_response.get('instances', [])
        print(f"Encontradas {len(instances)} instâncias no total.")

        # --- Passo 3: Preparar e escrever o arquivo CSV ---
        
        # Gera um nome de arquivo único com data e hora
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        csv_filename = f"relatorio_lightsail_{timestamp}.csv"
        
        print(f"\nGerando arquivo CSV: {csv_filename}...")

        with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
            # Define o escritor de CSV e o cabeçalho
            csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            
            header = [
                'Instancia', 'SO_Versao_Base', 'Mem_GB', 'CPU', 'Disco_GB', 'Regiao',
                'Tipo_de_IP', 'Nome_IP_Estatico', 'IPv4_Publico', 'IPv4_Privado'
            ]
            csv_writer.writerow(header)

            # Itera sobre as instâncias para escrever cada linha no arquivo
            for instance in instances:
                instance_name = instance.get('name', 'N/A')

                # Lógica para determinar o tipo de IP
                if instance_name in ips_estaticos_map:
                    tipo_ip = "Estático"
                    nome_ip_estatico = ips_estaticos_map[instance_name]
                else:
                    tipo_ip = "Dinâmico"
                    nome_ip_estatico = "N/A"

                # Coleta dos outros dados
                so_versao = instance.get('blueprintId', 'N/A')
                ram_size = instance.get('hardware', {}).get('ramSizeInGb', 'N/A')
                cpu_count = instance.get('hardware', {}).get('cpuCount', 'N/A')
                disk_size = instance.get('hardware', {}).get('disks', [{}])[0].get('sizeInGb', 'N/A')
                region = instance.get('location', {}).get('regionName', 'N/A')
                public_ip = instance.get('publicIpAddress', 'N/A')
                private_ip = instance.get('privateIpAddress', 'N/A')
                
                # Monta a lista de dados para a linha do CSV
                row_data = [
                    instance_name, so_versao, ram_size, cpu_count, disk_size, region,
                    tipo_ip, nome_ip_estatico, public_ip, private_ip
                ]
                csv_writer.writerow(row_data)
        
        print(f"\nRelatório salvo com sucesso no arquivo: {csv_filename}")

    except Exception as e:
        print(f"\nOcorreu um erro: {e}")

# Executa a função principal
if __name__ == "__main__":
    gerar_relatorio_lightsail_csv()
