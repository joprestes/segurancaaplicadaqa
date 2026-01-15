---
layout: exercise
title: "Exercício 2.1.2: Criar Regras Customizadas Semgrep"
slug: "semgrep-custom-rules"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-1-exercise-2-semgrep-custom-rules/
lesson_url: /modules/testes-seguranca-pratica/lessons/sast-testes-estaticos/
---

## Objetivo

Este exercício tem como objetivo **criar regras customizadas Semgrep** para detectar padrões inseguros específicos do seu projeto.

Ao completar este exercício, você será capaz de:

- Identificar padrões inseguros comuns no seu código
- Criar regras Semgrep em YAML para detectar esses padrões
- Testar regras em código existente
- Validar que regras funcionam corretamente
- Integrar regras customizadas no workflow de desenvolvimento

---

## Descrição

Você vai identificar padrões inseguros no seu código (ou código de exemplo), criar regras Semgrep personalizadas para detectá-los, e integrar essas regras no processo de desenvolvimento.

### Contexto

Regras customizadas permitem detectar padrões específicos do seu contexto que podem não estar nas regras padrão. Isso é especialmente útil para padrões de negócio, frameworks específicos, ou vulnerabilidades encontradas anteriormente.

### Tarefa Principal

1. Identificar padrão inseguro comum no código
2. Criar regra Semgrep para detectar esse padrão
3. Testar regra em código existente
4. Validar que regra funciona (detecta vulnerabilidades reais)
5. Documentar regra e adicionar ao repositório

---

## Requisitos

### Passo 1: Instalar Semgrep

**1.1. Instalar Semgrep**

```bash
# Opção A: Via pip
pip install semgrep

# Opção B: Via Homebrew (macOS)
brew install semgrep

# Opção C: Via Docker
docker pull returntocorp/semgrep

# Verificar instalação
semgrep --version
```

**1.2. Testar Semgrep**

```bash
# Testar com regras padrão
semgrep --config=auto --help
```

### Passo 2: Identificar Padrão Inseguro

**2.1. Analisar Código do Projeto**

Revise o código do seu projeto e identifique:

- Padrões inseguros repetidos
- Vulnerabilidades encontradas anteriormente
- Padrões específicos do seu framework/linguagem
- Violações de padrões de segurança internos

**Exemplos de Padrões Comuns**:

1. **Hardcoded Secrets**: Senhas, API keys, tokens no código
2. **SQL Injection**: Queries SQL concatenadas com variáveis
3. **XSS**: InnerHTML com dados do usuário sem sanitização
4. **Path Traversal**: Leitura de arquivos com caminhos não validados
5. **Insecure Deserialization**: Pickle.load() ou similar
6. **Command Injection**: Execução de comandos com input do usuário
7. **Weak Cryptography**: MD5, SHA1, ou algoritmos fracos
8. **Logging Sensitive Data**: Logs com dados pessoais/sensíveis

**2.2. Escolher Padrão para Detectar**

Escolha 1-2 padrões para começar. Exemplo:

- Padrão escolhido: "Hardcoded API Keys em variáveis"
- Contexto: Projeto Python com muitas API keys hardcoded
- Motivação: Encontrar todas as ocorrências para migrar para variáveis de ambiente

### Passo 3: Criar Regra Semgrep Básica

**3.1. Estrutura Básica de Regra Semgrep**

Criar arquivo `regras/hardcoded-api-keys.yaml`:

```yaml
# regras/hardcoded-api-keys.yaml
rules:
  - id: hardcoded-api-keys
    languages: [python]
    severity: ERROR
    message: "Hardcoded API key detected. Use environment variables or secrets management instead."
    patterns:
      - pattern: |
          $VAR = "...$SECRET..."
        where:
          - metavariable-regex:
              metavariable: $VAR
              regex: (api_key|API_KEY|apiKey|access_key|secret_key)
          - metavariable-regex:
              metavariable: $SECRET
              regex: (sk_live_|sk_test_|AKIA|AIza|ya29)
    metadata:
      cwe: "CWE-798: Use of Hard-coded Credentials"
      owasp: "A07:2021 – Identification and Authentication Failures"
      category: security
      technology:
        - python
```

**3.2. Estrutura Completa de Regra Semgrep**

```yaml
rules:
  - id: <id-único-da-regra>
    languages: [<linguagens-suportadas>]
    severity: ERROR | WARNING | INFO
    message: "<mensagem-descritiva>"
    patterns:
      # Pattern matching simples
      - pattern: <padrão>
      
      # OU múltiplos padrões (qualquer um)
      - pattern-either:
          - pattern: <padrão-1>
          - pattern: <padrão-2>
      
      # OU padrão com condições
      - pattern: <padrão>
        where:
          - <condição-1>
          - <condição-2>
    
    # Exceções (não flagar nesses casos)
    exceptions:
      - pattern: <exceção>
    
    # Metadados
    metadata:
      cwe: "<CWE-XXX>"
      owasp: "<AXX:2021 – Nome>"
      category: security
      technology: [<tecnologias>]
```

### Passo 4: Testar Regra

**4.1. Criar Arquivo de Teste**

Criar arquivo `test_code.py` com código vulnerável:

```python
# test_code.py (código vulnerável para teste)
import os

# ❌ Deve ser flagado pela regra
API_KEY = "sk_live_1234567890abcdef"
api_key = "AKIAIOSFODNN7EXAMPLE"
access_key = "ya29.a0AfH6SMBwF..."

# ✅ Não deve ser flagado (usa variável de ambiente)
api_key_env = os.getenv("API_KEY")

# ✅ Não deve ser flagado (não é API key)
database_url = "postgresql://user:pass@host/db"
```

**4.2. Executar Regra no Código de Teste**

```bash
# Executar regra customizada
semgrep --config=regras/hardcoded-api-keys.yaml test_code.py

# Saída esperada:
# test_code.py
#   hardcoded-api-keys
#     Line 4: API_KEY = "sk_live_..."
#     Message: Hardcoded API key detected...
```

**4.3. Refinar Regra**

Ajustar regra até que:
- ✅ Detecta todas as ocorrências problemáticas
- ✅ Não flagar código seguro (reduzir false positives)
- ✅ Mensagem é clara e útil

### Passo 5: Criar Regras Adicionais

**5.1. Exemplo: Regra para SQL Injection (Python)**

```yaml
# regras/sql-injection-python.yaml
rules:
  - id: sql-injection-string-format
    languages: [python]
    severity: ERROR
    message: "Potential SQL Injection. User input '$INPUT' is directly concatenated into SQL query. Use parameterized queries instead."
    patterns:
      - pattern-either:
          - pattern: f"SELECT ... $INPUT ..."
          - pattern: f"INSERT ... $INPUT ..."
          - pattern: f"UPDATE ... $INPUT ..."
          - pattern: f"DELETE ... $INPUT ..."
          - pattern: "...".format($INPUT)
          - pattern: "...".join([..., $INPUT, ...])
    exceptions:
      - pattern: cursor.execute($QUERY, ($INPUT,))  # Prepared statement
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 – Injection"
```

**5.2. Exemplo: Regra para Logging de Dados Sensíveis**

```yaml
# regras/sensitive-data-logging.yaml
rules:
  - id: sensitive-data-in-logs
    languages: [python, javascript, java]
    severity: WARNING
    message: "Potential sensitive data in log statement. Avoid logging personal information, passwords, tokens, or credit card numbers."
    patterns:
      - pattern: |
          logging.$LEVEL(..., $DATA, ...)
        where:
          - metavariable-regex:
              metavariable: $DATA
              regex: (password|token|cpf|rg|credit_card|cvv|api_key|secret)
    metadata:
      cwe: "CWE-532: Insertion of Sensitive Information into Log File"
      owasp: "A09:2021 – Security Logging and Monitoring Failures"
```

**5.3. Exemplo: Regra para Deserialização Insegura (Python)**

```yaml
# regras/insecure-deserialization.yaml
rules:
  - id: insecure-pickle-load
    languages: [python]
    severity: ERROR
    message: "Insecure deserialization detected. pickle.load() can execute arbitrary code. Risk of model poisoning or code injection. Use safe alternatives like JSON or ensure data source is trusted."
    patterns:
      - pattern-either:
          - pattern: pickle.load($FILE)
          - pattern: pickle.loads($DATA)
          - pattern: joblib.load($FILE)
    exceptions:
      - pattern-inside: |
          # Safe: Trusted source
          if verify_signature($FILE):
              pickle.load($FILE)
    metadata:
      cwe: "CWE-502: Deserialization of Untrusted Data"
      owasp: "A08:2021 – Software and Data Integrity Failures"
```

### Passo 6: Testar Regras em Projeto Real

**6.1. Executar Regras no Projeto**

```bash
# Executar todas as regras customizadas
semgrep --config=regras/ src/

# Executar regras customizadas + regras padrão
semgrep --config=auto --config=regras/ src/

# Executar com saída JSON
semgrep --config=regras/ --json --output=results.json src/
```

**6.2. Analisar Resultados**

- Verificar findings
- Validar se são True Positives ou False Positives
- Ajustar regras se necessário

### Passo 7: Documentar Regras

**7.1. Criar Documentação**

Criar arquivo `regras/README.md`:

```markdown
# Regras Semgrep Customizadas

Este diretório contém regras customizadas Semgrep para detectar padrões inseguros específicos do nosso contexto.

## Regras Disponíveis

### hardcoded-api-keys.yaml
- **Descrição**: Detecta API keys hardcoded no código
- **Severidade**: ERROR
- **Linguagens**: Python
- **Uso**: `semgrep --config=regras/hardcoded-api-keys.yaml src/`

### sql-injection-python.yaml
- **Descrição**: Detecta SQL Injection em queries Python
- **Severidade**: ERROR
- **Linguagens**: Python
- **Uso**: `semgrep --config=regras/sql-injection-python.yaml src/`

[... outras regras ...]

## Como Adicionar Novas Regras

1. Criar arquivo YAML no diretório `regras/`
2. Seguir estrutura padrão de regras Semgrep
3. Testar em código de exemplo
4. Validar em projeto real
5. Documentar nesta página
6. Commitar no repositório
```

**7.2. Adicionar Regras ao Repositório**

```bash
# Adicionar regras ao git
git add regras/
git commit -m "feat(security): adicionar regras Semgrep customizadas"
```

### Passo 8: Integrar Regras no Workflow

**8.1. Integrar em Pre-commit Hook**

Criar arquivo `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config=auto', '--config=regras/', '--error']
```

**8.2. Integrar no CI/CD**

```yaml
# .github/workflows/semgrep.yml
name: Semgrep Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            auto
            regras/
          generateSarif: "1"
```

---

## Dicas

1. **Comece simples**: Crie uma regra simples primeiro, depois refine
2. **Teste com exemplos**: Crie código de teste com e sem vulnerabilidade
3. **Documente exceções**: Se há casos legítimos, adicione exceções à regra
4. **Use metavariables**: Use `$VAR` para capturar variáveis genéricas
5. **Regex em metavariables**: Use `metavariable-regex` para padrões específicos
6. **Combine padrões**: Use `pattern-either` para múltiplas variações
7. **Consulte documentação**: https://semgrep.dev/docs/writing-rules/

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] Semgrep instalado e funcionando
- [ ] Padrão inseguro identificado no código
- [ ] Regra Semgrep criada em YAML
- [ ] Regra testada em código de exemplo
- [ ] Regra funciona corretamente (detecta vulnerabilidades reais)
- [ ] Regra testada em projeto real
- [ ] Regra documentada no README
- [ ] Regra adicionada ao repositório
- [ ] Regra integrada no workflow (pre-commit ou CI/CD)

---

## Exemplos de Regras por Contexto

### Contexto Financeiro (PCI-DSS)

```yaml
# regras/pci-dss-card-data.yaml
rules:
  - id: credit-card-in-code
    languages: [python, javascript, java]
    severity: CRITICAL
    message: "Credit card data detected in code. PCI-DSS violation. Never store card numbers in code."
    patterns:
      - pattern: |
          $VAR = "...$CARD..."
        where:
          - metavariable-regex:
              metavariable: $CARD
              regex: (\d{4}[-\s]?){3}\d{4}  # Padrão de cartão de crédito
```

### Contexto Educacional (LGPD - Dados de Menores)

```yaml
# regras/lgpd-minor-data.yaml
rules:
  - id: minor-data-in-logs
    languages: [python, javascript]
    severity: CRITICAL
    message: "Potential logging of minor personal data. LGPD requires special protection. Avoid logging CPF, RG, or other personal identifiers of minors."
    patterns:
      - pattern: |
          logging.$LEVEL(..., $DATA, ...)
        where:
          - metavariable-regex:
              metavariable: $DATA
              regex: (cpf|rg|cnh|birth_date|birthdate|age|idade)
```

### Contexto Ecommerce (Manipulação de Preços)

```yaml
# regras/price-manipulation.yaml
rules:
  - id: price-from-client
    languages: [javascript, python, java]
    severity: ERROR
    message: "Price comes from client input. Risk of price manipulation. Always calculate price server-side from product database."
    patterns:
      - pattern: |
          price = $REQUEST.$FIELD
        where:
          - metavariable-regex:
              metavariable: $FIELD
              regex: (price|amount|value|valor|preco)
```

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Exercício 2.1.3: Integrar SAST no CI/CD
- Criar mais regras customizadas para outros padrões
- Compartilhar regras com a equipe
- Contribuir regras para a comunidade Semgrep

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Regra Semgrep criada (arquivo YAML)
2. Exemplo de código que a regra detecta
3. Exemplo de código que a regra não flagar (exceções)
4. Resultados do teste em projeto real
5. Documentação da regra

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Aula 2.1 (SAST), Exercício 2.1.1 (opcional mas recomendado)
