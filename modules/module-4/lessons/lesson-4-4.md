---
layout: lesson
title: "Aula 4.4: Secrets Management"
slug: secrets-management
module: module-4
lesson_id: lesson-4-4
duration: "90 minutos"
level: "Avançado"
prerequisites: ["lesson-4-3"]
exercises: []
image: "assets/module-4/images/podcasts/4.4-Secrets_Management.png"
permalink: /modules/seguranca-cicd-devsecops/lessons/secrets-management/
---

<!-- # Aula 4.4: Secrets Management -->

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- Entender por que secrets em código são críticos
- Identificar diferentes tipos de secrets e onde estão expostos
- Implementar secrets management adequado (Vault, AWS Secrets Manager, Azure Key Vault)
- Detectar secrets vazados em repositórios
- Configurar rotação automática de secrets
- Integrar secrets management em pipelines CI/CD

## 📚 Por que Secrets Management é Crítico?

### O Problema: Secrets em Código

**Estatísticas alarmantes**:

- 🔴 **4 milhões de secrets** foram expostos no GitHub em 2022 (GitGuardian)
- 💰 **90% das organizações** tiveram secrets expostos em repositórios públicos
- ⚠️ **Média de 2.8 segundos** para detectar e explorar secrets expostos por bots

**Casos Reais de Vazamento**:

1. **Tesla (2018)**: API keys expostas em GitHub → Acesso não autorizado à infraestrutura AWS
2. **Uber (2016)**: Hardcoded AWS credentials → Violação de 57 milhões de usuários
3. **Codecov (2021)**: Secret de token exposto → Ataque à cadeia de suprimentos

### Por que Secrets em Código são Perigosos?

#### 1. Versionamento Persistente

**Problema**: Secrets commitados permanecem no histórico Git, mesmo após remoção.

```bash
# ❌ RUIM: Secret commitado
git commit -m "Add API key"
git push

# Tentando remover depois
git rm config.json
git commit -m "Remove API key"
git push

# ⚠️ Secret ainda está no histórico!
git log --all --full-history -- config.json
```

**Solução**: Usar `git-secrets` ou `git-filter-repo` para limpar histórico.

#### 2. Acesso Amplo

**Problema**: Qualquer pessoa com acesso ao repositório vê o secret.

```javascript
// ❌ RUIM: Secret hardcoded
const API_KEY = "sk-1234567890abcdef";
```

**Impacto**:
- ✅ Desenvolvedores internos veem
- ✅ Ex-desenvolvedores (que ainda têm acesso) veem
- ✅ Colaboradores externos veem
- ✅ Atacantes (se repositório comprometido) veem

#### 3. Sem Rastreabilidade

**Problema**: Não há log de quem acessou qual secret.

**Com secret management adequado**:
- ✅ Audit log completo
- ✅ Rastreamento de acesso
- ✅ Alertas de acesso suspeito

#### 4. Rotação Difícil

**Problema**: Rotacionar secret exige commit e deploy.

**Com secret management**:
- ✅ Rotação automática
- ✅ Sem downtime
- ✅ Versões múltiplas (zero-downtime rotation)

---

## 🔍 Tipos de Secrets

### Secrets Comuns

| Tipo de Secret | Exemplos | Onde Encontrar |
|----------------|----------|----------------|
| **API Keys** | `sk-...`, `AIza...`, `AKIA...` | Config files, environment variables |
| **Passwords** | `password123`, `Admin@123` | Config files, code comments |
| **Database Credentials** | `postgres://user:pass@host` | Connection strings |
| **Tokens OAuth** | `Bearer eyJhbG...` | Headers, config files |
| **Private Keys** | `-----BEGIN PRIVATE KEY-----` | Files, code |
| **Certificates** | `-----BEGIN CERTIFICATE-----` | Files, configs |
| **AWS Credentials** | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Environment variables |
| **Docker Registry** | `docker login` credentials | Config files |
| **Cloud Provider** | Azure, GCP service account keys | JSON files |

### Onde Secrets são Encontrados?

#### 1. Código-Fonte

```javascript
// ❌ RUIM: Secret hardcoded
const API_KEY = "sk-1234567890abcdef";
const DB_PASSWORD = "admin123";
```

#### 2. Arquivos de Configuração

```yaml
# ❌ RUIM: config.yaml
database:
  host: localhost
  password: admin123

api:
  key: sk-1234567890abcdef
```

#### 3. Variáveis de Ambiente

```bash
# ❌ RUIM: .env commitado
export API_KEY="sk-1234567890abcdef"
export DB_PASSWORD="admin123"
```

#### 4. Histórico Git

```bash
# Secret removido, mas ainda no histórico
git log --all --full-history -- config.json
```

#### 5. Logs

```javascript
// ❌ RUIM: Secret em log
console.log("API Key:", API_KEY);
logger.info("Database connection:", { password: DB_PASSWORD });
```

---

## 🛡️ Secrets Management Solutions

### 1. HashiCorp Vault

**O que é**: Ferramenta open-source para gerenciar secrets e dados sensíveis.

#### Características

- ✅ Centralização de secrets
- ✅ Audit logging completo
- ✅ Rotação automática
- ✅ Encryptação em repouso e em trânsito
- ✅ Integração com cloud providers (AWS, Azure, GCP)
- ✅ Dynamic secrets (cria secrets sob demanda)

#### Exemplo: Usar Vault

```bash
# Instalar Vault
brew install vault  # macOS
# ou
apt-get install vault  # Linux

# Iniciar Vault (desenvolvimento)
vault server -dev

# Armazenar secret
export VAULT_ADDR='http://127.0.0.1:8200'
vault kv put secret/myapp api_key="sk-1234567890abcdef"

# Recuperar secret
vault kv get secret/myapp
```

#### Exemplo: Integração com Aplicação

```javascript
// ✅ BOM: Buscar secret do Vault
const vault = require('node-vault')({ endpoint: process.env.VAULT_ADDR });

async function getSecret() {
  const result = await vault.read('secret/myapp');
  return result.data.api_key;
}

// Usar secret
const apiKey = await getSecret();
```

#### Exemplo: CI/CD com Vault

{% raw %}
```yaml
- name: Get secrets from Vault
  uses: hashicorp/vault-action@v3
  with:
    url: https://vault.mycompany.com
    method: aws
    role: myapp-role
    secrets: |
      secret/myapp api_key | API_KEY
      secret/myapp db_password | DB_PASSWORD

- name: Use secrets
  run: |
    echo "API Key: ${{ env.API_KEY }}"
    npm run deploy
  env:
    API_KEY: ${{ env.API_KEY }}
    DB_PASSWORD: ${{ env.DB_PASSWORD }}
```
{% endraw %}

### 2. AWS Secrets Manager

**O que é**: Serviço gerenciado da AWS para armazenar e gerenciar secrets.

#### Características

- ✅ Rotação automática
- ✅ Integração nativa com AWS (RDS, Redshift, DocumentDB)
- ✅ Audit logging via CloudTrail
- ✅ Encryption (KMS)
- ✅ Versionamento de secrets

#### Exemplo: Usar AWS Secrets Manager

```python
import boto3
import json

secrets_client = boto3.client('secretsmanager', region_name='us-east-1')

# Criar secret
response = secrets_client.create_secret(
    Name='myapp/api-key',
    SecretString=json.dumps({'api_key': 'sk-1234567890abcdef'})
)

# Recuperar secret
response = secrets_client.get_secret_value(SecretId='myapp/api-key')
secret = json.loads(response['SecretString'])
api_key = secret['api_key']
```

#### Exemplo: Rotação Automática

```python
# Lambda function para rotação
def lambda_handler(event, context):
    secret_arn = event['SecretId']
    
    # Gerar novo secret
    new_api_key = generate_new_api_key()
    
    # Atualizar secret
    secrets_client.update_secret(
        SecretId=secret_arn,
        SecretString=json.dumps({'api_key': new_api_key})
    )
    
    # Validar que novo secret funciona
    validate_api_key(new_api_key)
```

### 3. Azure Key Vault

**O que é**: Serviço gerenciado da Azure para armazenar secrets, keys e certificates.

#### Exemplo: Usar Azure Key Vault

```python
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

# Autenticar
credential = DefaultAzureCredential()
vault_url = "https://my-vault.vault.azure.net/"
client = SecretClient(vault_url=vault_url, credential=credential)

# Criar secret
client.set_secret("api-key", "sk-1234567890abcdef")

# Recuperar secret
secret = client.get_secret("api-key")
api_key = secret.value
```

### 4. Google Cloud Secret Manager

**O que é**: Serviço gerenciado do GCP para armazenar secrets.

#### Exemplo: Usar GCP Secret Manager

```python
from google.cloud import secretmanager

client = secretmanager.SecretManagerServiceClient()
project_id = "my-project"

# Criar secret
parent = f"projects/{project_id}"
secret_id = "api-key"
secret = client.create_secret(
    request={
        "parent": parent,
        "secret_id": secret_id,
        "secret": {"replication": {"automatic": {}}},
    }
)

# Adicionar versão do secret
version = client.add_secret_version(
    request={"parent": secret.name, "payload": {"data": b"sk-1234567890abcdef"}}
)

# Recuperar secret
response = client.access_secret_version(request={"name": version.name})
secret_value = response.payload.data.decode("UTF-8")
```

---

## 🔎 Detecção de Secrets Vazados

### Por que Detectar?

**Problema**: Secrets podem ser commitados acidentalmente.

**Solução**: Detectar secrets antes de commit (pre-commit) ou após commit (CI/CD).

### Ferramentas de Detecção

#### 1. GitGuardian

**O que é**: Ferramenta de detecção de secrets em repositórios.

**Características**:
- ✅ Detecção em tempo real
- ✅ Integração com GitHub, GitLab, Bitbucket
- ✅ API para integração customizada
- ✅ Detecção de 350+ tipos de secrets

**Exemplo: GitHub Actions**

{% raw %}
```yaml
secret-scan:
  name: Secret Scanning with GitGuardian
  runs-on: ubuntu-latest
  steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0  # Full history for secret scanning
    
    - name: Run GitGuardian scan
      uses: GitGuardian/ggshield-action@master
      env:
        GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
      with:
        fail_on_secrets: true
        mode: scan-path
        paths: |
          .
          !node_modules
          !.git
```
{% endraw %}

#### 2. TruffleHog

**O que é**: Ferramenta open-source de detecção de secrets.

**Exemplo: Pre-commit Hook**

```bash
# Instalar TruffleHog
pip install truffleHog

# Executar scan
trufflehog --regex --entropy=False . --json > secrets.json

# Pre-commit hook
#!/bin/bash
trufflehog --regex --entropy=False . && git commit || exit 1
```

#### 3. GitLeaks

**O que é**: Ferramenta CLI rápida para detectar secrets.

**Exemplo: CI/CD**

```yaml
secret-scan:
  name: Secret Scanning with GitLeaks
  runs-on: ubuntu-latest
  steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Run GitLeaks
      uses: gitleaks/gitleaks-action@v2
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Pre-commit Hooks

**Objetivo**: Detectar secrets antes de commit.

**Exemplo: .git/hooks/pre-commit**

```bash
#!/bin/bash

# Verificar secrets
if ggshield scan pre-commit; then
  echo "✅ No secrets found"
  exit 0
else
  echo "❌ Secrets found! Commit blocked."
  exit 1
fi
```

---

## 🔄 Rotação Automática de Secrets

### Por que Rotacionar?

**Benefícios**:
- ✅ Limita impacto de comprometimento
- ✅ Compliance (requisitos regulatórios)
- ✅ Boas práticas de segurança

### Estratégias de Rotação

#### 1. Rotação Periódica

**Definição**: Rotacionar secrets em intervalos fixos (ex: a cada 90 dias).

**Exemplo: AWS Secrets Manager**

```python
import boto3

secrets_client = boto3.client('secretsmanager')

# Configurar rotação automática
secrets_client.rotate_secret(
    SecretId='myapp/api-key',
    RotationLambdaARN='arn:aws:lambda:...:function:rotate-secret',
    RotationRules={
        'AutomaticallyAfterDays': 90  # Rotacionar a cada 90 dias
    }
)
```

#### 2. Rotação sob Demanda

**Definição**: Rotacionar secret quando solicitado (ex: após incidente).

**Exemplo: Vault**

```bash
# Rotacionar secret manualmente
vault kv patch secret/myapp api_key="sk-new-key-here"
```

#### 3. Rotação Zero-Downtime

**Definição**: Rotacionar secret sem interrupção de serviço.

**Estratégia**:
1. Criar novo secret
2. Validar que novo secret funciona
3. Atualizar aplicações gradualmente
4. Desativar secret antigo após período de graça

---

## 💼 Exemplos Práticos CWI

### Caso 1: Secret Management em Pipeline Financeiro (PCI-DSS)

**Contexto**: Cliente financeiro com requisitos PCI-DSS rigorosos.

**Solução**:
```yaml
pci-secrets-pipeline:
  stages:
    - name: Secret Scanning (Pre-commit)
      steps:
        - ggshield scan pre-commit
    
    - name: Get Secrets from Vault
      steps:
        - vault read secret/payment-gateway
    
    - name: Deploy with Secrets
      steps:
        - kubectl create secret generic payment-secrets \
            --from-literal=api-key=$VAULT_API_KEY \
            --from-literal=merchant-id=$VAULT_MERCHANT_ID
    
    - name: Rotate Secrets (Monthly)
      schedule: "0 0 1 * *"  # Primeiro dia do mês
      steps:
        - vault kv patch secret/payment-gateway
        - kubectl rollout restart deployment/payment-service
```

### Caso 2: Detecção de Secrets em Repositório EdTech

**Contexto**: Time grande com muitos desenvolvedores, risco de secrets acidentais.

**Solução**:
```yaml
secret-prevention:
  stages:
    - name: Pre-commit Hook (Local)
      # GitGuardian pre-commit hook instalado
    
    - name: CI Secret Scan
      steps:
        - ggshield scan repo --recursive
    
    - name: Alert if Secrets Found
      steps:
        - if secrets found:
            - Notify security team
            - Block merge
            - Create incident ticket
```

---

## 📝 Resumo da Aula

### Principais Conceitos

1. **Secrets Management**: Armazenamento seguro de credenciais e dados sensíveis
2. **Problemas**: Secrets em código são persistentes, amplamente acessíveis e difíceis de rotacionar
3. **Soluções**: Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager
4. **Detecção**: GitGuardian, TruffleHog, GitLeaks para detectar secrets vazados
5. **Rotação**: Periódica, sob demanda, zero-downtime

### Próximos Passos

Na próxima aula (4.5), você aprenderá sobre:
- Monitoramento de segurança em produção
- SIEM e logs de segurança
- Alertas de segurança
- Resposta a incidentes

---

## 📚 Recursos Adicionais

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
- [GitGuardian Documentation](https://docs.gitguardian.com/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

---

**Duração da Aula**: 90 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Aula 4.3 (Container Security e Kubernetes), conhecimento básico de cloud providers
