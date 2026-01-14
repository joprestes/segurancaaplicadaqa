# Guia de Deploy no Fly.io

Este guia explica como fazer o deploy do projeto Jekyll no Fly.io.

## Pré-requisitos

1. Conta no Fly.io: https://fly.io/app/sign-up
2. Fly CLI instalado: https://fly.io/docs/getting-started/installing-flyctl/

```bash
# macOS (usando Homebrew)
brew install flyctl

# Ou usando o script de instalação
curl -L https://fly.io/install.sh | sh
```

3. Faça login no Fly.io:
```bash
fly auth login
```

## Passo a Passo

### 1. Configurar o app no Fly.io

No diretório do projeto (`crescidos-qualidade`):

```bash
cd crescidos-qualidade
fly launch
```

O comando `fly launch` vai:
- Detectar o Dockerfile automaticamente
- Perguntar o nome do app (ou usar o padrão do fly.toml)
- Perguntar a região (recomendado: `gru` para São Paulo)
- Perguntar se quer criar um banco de dados (responda **não** para este projeto)
- Criar o app no Fly.io

### 2. Verificar configuração

Verifique se o arquivo `fly.toml` está correto. O arquivo já foi configurado com:
- App name: `crescidos-qualidade` (você pode mudar durante o `fly launch`)
- Região: `gru` (São Paulo, Brasil)
- Memória: 256MB
- CPU: 1 compartilhado

### 3. Fazer o deploy

```bash
fly deploy
```

Este comando vai:
- Fazer build da imagem Docker
- Enviar para o Fly.io
- Fazer deploy da aplicação

### 4. Verificar o deploy

Após o deploy, você verá a URL do app. Para verificar:

```bash
# Ver status do app
fly status

# Ver logs
fly logs

# Abrir o app no navegador
fly open
```

## Configurações Importantes

### URL e BaseURL

O arquivo `_config.yml` tem configurações de URL que podem precisar ser ajustadas:

```yaml
url: "https://onosendae.github.io"
baseurl: "/seguranca-qa"
```

**Importante**: Se você quiser servir o site na raiz do domínio do Fly.io (ex: `https://seu-app.fly.dev`), você precisa ajustar:

```yaml
url: "https://seu-app.fly.dev"  # Substitua pelo seu domínio
baseurl: ""  # Vazio para servir na raiz
```

Você pode fazer isso:
1. Depois do deploy, verificar a URL do app com `fly status`
2. Ajustar o `_config.yml`
3. Fazer deploy novamente com `fly deploy`

Ou usar variáveis de ambiente no Fly.io (veja seção abaixo).

### Variáveis de Ambiente

Você pode configurar variáveis de ambiente no Fly.io:

```bash
# Definir variável de ambiente
fly secrets set JEKYLL_ENV=production

# Ver variáveis de ambiente
fly secrets list
```

### Escalando

Por padrão, o app está configurado para:
- Auto-stop quando não há tráfego (`auto_stop_machines = true`)
- Auto-start quando há requisições (`auto_start_machines = true`)
- Mínimo de máquinas rodando: 0 (`min_machines_running = 0`)

Isso ajuda a economizar recursos quando não há uso.

Para ajustar recursos:

```bash
# Ver configurações atuais
fly scale show

# Ajustar memória (ex: 512MB)
fly scale memory 512

# Ajustar CPU
fly scale vm shared-cpu-2x
```

## Comandos Úteis

```bash
# Ver status do app
fly status

# Ver logs em tempo real
fly logs

# SSH no container
fly ssh console

# Ver métricas
fly metrics

# Reiniciar o app
fly apps restart

# Ver informações do app
fly info
```

## Troubleshooting

### Problema: Build falha

- Verifique os logs: `fly logs`
- Tente fazer build localmente primeiro: `docker build -t test .`
- Verifique se o Gemfile.lock está commitado

### Problema: App não inicia

- Verifique os logs: `fly logs`
- Verifique se a porta está correta (Fly.io usa PORT dinamicamente)
- Tente acessar via SSH: `fly ssh console`

### Problema: Site não carrega corretamente

- Verifique o `baseurl` no `_config.yml`
- Verifique se a URL está correta
- Verifique os logs para erros de Jekyll

### Problema: Arquivos estáticos não carregam

- Verifique se o `baseurl` está correto
- Verifique se os assets estão no lugar certo
- Limpe o cache do Jekyll: `fly ssh console` e depois `rm -rf .jekyll-cache _site`

## Próximos Passos

1. Configurar domínio customizado (opcional)
2. Configurar SSL (já habilitado por padrão no Fly.io)
3. Configurar monitoramento e alertas
4. Ajustar recursos conforme necessário

## Links Úteis

- [Documentação do Fly.io](https://fly.io/docs/)
- [Documentação do Jekyll](https://jekyllrb.com/docs/)
- [Dashboard do Fly.io](https://fly.io/apps)