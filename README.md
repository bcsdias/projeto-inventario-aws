# projeto-inventario-aws

Scripts em Python (boto3) para fazer o inventário e a auditoria de uma conta AWS. Percorrem todas as regiões, reúnem os recursos em relatórios e exportam o resultado em CSV e Excel.

> Projeto pessoal, feito para uso próprio. Rode apenas em contas AWS que você administra ou tem autorização para auditar.

## O que tem aqui

| Arquivo | O que faz |
|---|---|
| `inventario_aws.py` | Inventário completo da conta, com relatórios em CSV e um Excel consolidado |
| `auditoria_remota.py` | Auditoria remota das instâncias via AWS Systems Manager (SSM) |
| `fichas/ficha_tecnica.py` | Gera uma ficha técnica em texto para cada instância EC2 e Lightsail |
| `auditoria.sh`, `auditoria_manual.sh` | Auditoria de um servidor Linux, para rodar direto na máquina (versão `manual` inclui histórico de comandos) |
| `fichas/collect_history.sh` | Reúne o histórico de comandos (`.bash_history`) dos usuários |
| `fichas/comand_audit.sh` | Registra os comandos das sessões Bash em um log centralizado |
| `a.py` | Versão anterior e independente do gerador de fichas |

## `inventario_aws.py`

Consulta todas as regiões disponíveis e gera seis grupos de relatórios:

| Relatório | Conteúdo |
|---|---|
| Computação | Instâncias EC2 e Lightsail |
| Segurança | Regras de firewall abertas para qualquer origem (`0.0.0.0/0`) e usuários IAM |
| Custos | Recursos órfãos (sem uso) |
| Armazenamento | Buckets S3 |
| Banco de dados | Instâncias RDS |
| Rede | VPCs e sub-redes |

Saídas, na pasta de execução:

- um CSV por relatório (por exemplo `relatorio_ec2.csv`, `relatorio_s3_buckets.csv`);
- `relatorio_aws_total_DDMMAAAA.xlsx`, com uma aba por relatório;
- `inventario_aws_total_DDMMAAAA.log`, com o log da execução.

## `auditoria_remota.py`

Para cada região, localiza as instâncias online gerenciadas pelo SSM (EC2 e Lightsail) e executa comandos remotos com o `AWS-RunShellScript`. Para cada instância grava em `auditoria_remota_resultados_DDMMAAAA/`:

- `usuarios_e_permissoes.txt`
- `tarefas_agendadas.txt`
- `discovery_web.txt` (sites Nginx/Apache e aplicações)

As instâncias precisam ter o agente SSM instalado e uma função (role) com permissão para o SSM. O script **executa comandos nas instâncias**, então use com cuidado.

## `fichas/ficha_tecnica.py`

Coleta os dados das instâncias EC2 e Lightsail e gera, em `inventario_por_instancia/`, uma ficha em texto por instância. No final junta todas em `inventario_consolidado_DDMMAAAA.txt`. Também usa o SSM para ler o histórico de comandos das instâncias.

## Requisitos

- Python 3
- Dependências:

```bash
pip install boto3 pandas openpyxl tabulate
```

- Credenciais da AWS configuradas, por exemplo com `aws configure` ou variáveis de ambiente (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`). **Nunca coloque credenciais no código nem no repositório.**
- Permissões de leitura nos serviços consultados: EC2, Lightsail, RDS, S3, IAM e STS. Para a auditoria remota e as fichas, também as permissões do SSM (`SendCommand` e `GetCommandInvocation`).

## Como usar

```bash
python inventario_aws.py        # inventário e relatórios
python auditoria_remota.py      # auditoria remota via SSM
python fichas/ficha_tecnica.py  # fichas técnicas por instância
```

Os scripts em Bash são para rodar direto no servidor Linux, como root:

```bash
sudo bash auditoria.sh
```

## Cuidados

Os arquivos gerados (CSV, Excel, logs e fichas) descrevem a conta e podem incluir dados sensíveis: regras de firewall, usuários IAM, nomes de recursos, usuários dos servidores, tarefas agendadas e histórico de comandos. Por isso o `.gitignore` do projeto já ignora `*.csv`, `*.xls*`, `*.log`, `*.txt` e as pastas de resultado. Mantenha assim e revise o que for compartilhado.

## Limitações

- Não há testes automatizados.
- A saída é pensada para leitura humana (Excel e texto); não há formato estruturado como JSON.
- A coleta percorre todas as regiões, então a execução pode demorar em contas grandes.
