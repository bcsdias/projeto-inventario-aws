import boto3

def gerar_relatorio_lightsail():
    """
    Gera um relatório completo das instâncias Lightsail,
    identificando corretamente os IPs estáticos e dinâmicos.
    """
    try:
        lightsail = boto3.client('lightsail')
        
        # --- Passo 1: Obter a "fonte da verdade" sobre IPs estáticos ---
        print("Buscando IPs estáticos...")
        static_ips_response = lightsail.get_static_ips()
        
        # Cria um dicionário para busca rápida: {nome_da_instancia: nome_do_ip_estatico}
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

        # --- Passo 3: Combinar os dados e imprimir a tabela ---
        print("\n--- Relatório de Instâncias AWS Lightsail ---")
        
        # Cabeçalho da tabela
        header = (
            f"{'Instância':<25} {'SO (Versão Base)':<20} {'Mem (GB)':<10} {'CPU':<5} "
            f"{'Disco (GB)':<12} {'Região':<14} {'Tipo de IP':<10} {'Nome IP Estático':<20} "
            f"{'IPv4 Público':<18} {'IPv4 Privado':<18}"
        )
        print(header)
        print("-" * len(header))

        for instance in instances:
            instance_name = instance.get('name', 'N/A')

            # Lógica para determinar o tipo de IP usando nosso mapa
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
            
            # Imprime a linha da tabela
            row = (
                f"{instance_name:<25} {so_versao:<20} {str(ram_size):<10} {str(cpu_count):<5} "
                f"{str(disk_size):<12} {region:<14} {tipo_ip:<10} {nome_ip_estatico:<20} "
                f"{public_ip:<18} {private_ip:<18}"
            )
            print(row)

    except Exception as e:
        print(f"\nOcorreu um erro: {e}")

# Executa a função principal
if __name__ == "__main__":
    gerar_relatorio_lightsail()
