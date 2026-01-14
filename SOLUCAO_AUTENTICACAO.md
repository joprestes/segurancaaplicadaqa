# Solução: Erro de Autenticação Fly.io

## Erro
```
Error: failed to run query... You must be authenticated to view this.
unsuccessful command 'flyctl launch plan generate...'
```

## Causa
O `flyctl` não está autenticado ou a sessão expirou.

## Solução

### 1. Verificar se está autenticado

```bash
flyctl auth whoami
```

Se retornar erro ou "not logged in", você precisa fazer login.

### 2. Fazer Login no Fly.io

**Opção A: Login via navegador (recomendado)**

```bash
flyctl auth login
```

Isso vai:
- Abrir seu navegador
- Pedir para fazer login na sua conta Fly.io
- Autorizar o CLI

**Opção B: Login com token**

Se você tem um token de acesso:

```bash
flyctl auth login --token SEU_TOKEN_AQUI
```

### 3. Verificar autenticação

```bash
flyctl auth whoami
```

Deve mostrar seu email cadastrado no Fly.io.

### 4. Se ainda não funcionar

**Verificar se o flyctl está instalado:**

```bash
# macOS
which flyctl

# Ou verificar versão
flyctl version
```

**Se não estiver instalado:**

```bash
# macOS (Homebrew)
brew install flyctl

# Ou script de instalação
curl -L https://fly.io/install.sh | sh
```

**Reinstalar autenticação:**

```bash
# Logout
flyctl auth logout

# Login novamente
flyctl auth login
```

### 5. Verificar configuração do app

Depois de autenticado, verifique se o app existe:

```bash
flyctl apps list
```

Se o app `segurancaaplicadaqa-tnnq1a` não aparecer, você pode:

**Opção A: Criar o app**

```bash
cd crescidos-qualidade
flyctl launch
```

**Opção B: Se o app já existe, verificar permissões**

```bash
flyctl apps show segurancaaplicadaqa-tnnq1a
```

Se der erro de permissão, você precisa:
- Ter acesso à organização que criou o app
- Ou criar um novo app com seu nome

## Comandos Úteis

```bash
# Ver status da autenticação
flyctl auth whoami

# Ver apps disponíveis
flyctl apps list

# Ver informações do app
flyctl status -a segurancaaplicadaqa-tnnq1a

# Fazer deploy (depois de autenticado)
flyctl deploy -a segurancaaplicadaqa-tnnq1a
```

## Troubleshooting

### Problema: "command not found: flyctl"

**Solução:**
1. Instalar flyctl (veja passo 4 acima)
2. Adicionar ao PATH se necessário:
   ```bash
   export PATH="$HOME/.fly/bin:$PATH"
   ```

### Problema: "You must be authenticated"

**Solução:**
1. Fazer logout: `flyctl auth logout`
2. Fazer login novamente: `flyctl auth login`
3. Verificar: `flyctl auth whoami`

### Problema: "App not found"

**Solução:**
- O app pode ter sido criado em outra organização
- Ou o app não existe ainda
- Use `flyctl launch` para criar um novo app

## Próximos Passos

Depois de resolver a autenticação:

1. Verificar apps disponíveis:
   ```bash
   flyctl apps list
   ```

2. Se o app não existir, criar:
   ```bash
   cd crescidos-qualidade
   flyctl launch
   ```

3. Fazer deploy:
   ```bash
   flyctl deploy
   ```
