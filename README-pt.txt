RedRecon

RedRecon é uma ferramenta de orquestração de segurança rápida e flexível construída em Go. Ele automatiza fluxos de trabalho de reconhecimento e varredura de segurança, orquestrando uma sequência de ferramentas populares de código aberto para descobrir e analisar ativos digitais.

Funcionalidades
- Fluxo de Trabalho Unificado: Um único comando `run` para executar um fluxo completo de reconhecimento e varredura.
- Reconhecimento Abrangente: Descobre subdomínios, valida hosts ativos, coleta URLs e analisa arquivos JavaScript.
- Rastreamento de Aplicações Web: Baixa o conteúdo de sites (JS, CSS, Source Maps) para análise offline com controle de profundidade.
- Descoberta de Endpoints e Segredos: Extrai automaticamente potenciais endpoints de API de arquivos JavaScript.
- Busca Inteligente: Um poderoso comando `search` para procurar termos em arquivos de resultados com contexto, destaque e suporte a regex.
- Extensível: Projetado para se integrar com ferramentas de segurança externas populares (Subfinder, Nuclei, Nikto, Katana, etc.).
- Configurável: Usa um arquivo `config.yaml` para gerenciar configurações de ferramentas, wordlists e chaves de API.

Instalação

1. Instale o Go

O RedRecon requer o Go (versão 1.21 ou mais recente). Você pode baixá-lo no site oficial do Go.

2. Instale as Ferramentas Externas

O RedRecon orquestra várias ferramentas externas. Você deve instalá-las e garantir que estejam disponíveis no `PATH` do seu sistema. Esta ferramenta é otimizada para **Parrot OS** e **Kali Linux**, onde a maioria dessas ferramentas pode ser instalada via `apt`.


# Instale ferramentas do gerenciador de pacotes
sudo apt update && sudo apt install -y subfinder dnsutils nmap nuclei nikto whatweb gobuster

# Instale ferramentas baseadas em Go
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsvalidator/cmd/dnsvalidator@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/assetfinder@latest

# Instale o Feroxbuster (Recomendado)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh)"


3. Compile o RedRecon

Clone o repositório e compile o binário:

git clone https://github.com/SEU_USUARIO/redrecon.git
cd redrecon
go build -o redrecon ./cmd/redrecon


Você pode mover o binário `redrecon` para um diretório em seu `PATH` para fácil acesso, como /usr/local/bin/.

Configuração

1. Copie o arquivo de configuração de exemplo:
   cp config.example.yaml config.yaml

2. Edite `config.yaml` para adicionar suas chaves de API e personalizar caminhos para wordlists. Isso é crucial para que ferramentas como o `subfinder` funcionem de forma eficaz.

Uso

O RedRecon agora se concentra em um comando principal unificado: `run`.

Fluxo de Trabalho Completo (`run`)

Executa um fluxo de trabalho completo, começando com o reconhecimento para mapear os ativos e, em seguida, realizando uma varredura de vulnerabilidades nos ativos encontrados. Os resultados são salvos em `results/<alvo>/recon/` e `results/<alvo>/scan/`.

# Execute uma avaliação completa em um alvo
./redrecon run example.com

# Execute a avaliação, pulando a etapa de fuzzing no reconhecimento e a etapa do nikto na varredura
./redrecon run example.com --recon-skip fuzz --scan-skip nikto

# Execute a avaliação, mas na fase de varredura, rode apenas o nuclei e a busca por CVEs
./redrecon run example.com --scan-only nuclei,cvesearch

Busca (`search`)

Procure por termos em todos os arquivos de resultados gerados.

# Encontre todas as ocorrências de "password"
./redrecon search "senha"

# Encontre potenciais chaves de API usando regex, apenas nos resultados de example.com
./redrecon search -t example.com -r "[a-fA-F0-9]{32}"

# Liste apenas os arquivos que contêm o termo "admin"
./redrecon search -l "admin"

Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo LICENSE para mais detalhes.