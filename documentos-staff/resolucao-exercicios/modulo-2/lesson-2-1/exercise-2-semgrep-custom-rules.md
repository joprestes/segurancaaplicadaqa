---
exercise_id: lesson-2-1-exercise-2-semgrep-custom-rules
title: "Exercício 2.1.2: Criar Regras Customizadas Semgrep"
lesson_id: lesson-2-1
module: module-2
difficulty: "Intermediário"
last_updated: 2025-01-15
---

# Exercício 2.1.2: Criar Regras Customizadas Semgrep

## 📋 Enunciado Completo

Este exercício tem como objetivo **criar regras customizadas Semgrep** para detectar padrões inseguros específicos do seu projeto.

### Tarefa Principal

1. Identificar padrão inseguro comum no código
2. Criar regra Semgrep para detectar esse padrão
3. Testar regra em código existente
4. Validar que regra funciona (detecta vulnerabilidades reais)
5. Documentar regra e adicionar ao repositório

---

## ✅ Soluções Detalhadas

### Passo 1: Instalar Semgrep

**Solução Esperada:**
```bash
# Opção A: Via pip
pip install semgrep

# Verificar instalação
semgrep --version
```

**Verificações:**
- Semgrep instalado: `semgrep --version` mostra versão
- Teste básico: `semgrep --config=auto --help` funciona

**Problemas Comuns:**
- Comando não encontrado → Adicionar ao PATH ou usar `pip install --user semgrep`
- Versão incompatível → Atualizar: `pip install --upgrade semgrep`

### Passo 2: Identificar Padrão Inseguro

**Solução Esperada - Exemplo: Hardcoded API Keys**

**2.1. Padrão Identificado:**
- **Problema**: API keys hardcoded no código
- **Contexto**: Projeto Python com múltiplas integrações
- **Risco**: Exposição de credenciais se código é commitado

**2.2. Exemplos de Código Vulnerável Encontrado:**
```python
# Código vulnerável encontrado no projeto:
API_KEY = "sk_live_1234567890abcdef"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
GOOGLE_API_KEY = "ya29.a0AfH6SMBwF..."
```

**2.3. Motivação:**
- Encontrar todas as ocorrências para migrar para variáveis de ambiente
- Prevenir futuras exposições de credenciais
- Atender compliance (não hardcode secrets)

### Passo 3: Criar Regra Semgrep

**Solução Esperada:**

**3.1. Regra Básica (Exemplo: Hardcoded API Keys):**
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
              regex: (api_key|API_KEY|apiKey|access_key|secret_key|ACCESS_KEY|SECRET_KEY)
          - metavariable-regex:
              metavariable: $SECRET
              regex: (sk_live_|sk_test_|AKIA|AIza|ya29|ghp_|gho_)
    metadata:
      cwe: "CWE-798: Use of Hard-coded Credentials"
      owasp: "A07:2021 – Identification and Authentication Failures"
      category: security
      technology:
        - python
```

**3.2. Explicação da Regra:**
- `languages: [python]`: Aplica apenas em Python
- `severity: ERROR`: Severidade alta (bloqueia pipeline se configurado)
- `pattern: $VAR = "...$SECRET..."`: Padrão genérico (variável = string)
- `metavariable-regex $VAR`: Busca variáveis com nomes relacionados a secrets
- `metavariable-regex $SECRET`: Busca valores que parecem secrets (prefixos comuns)

**3.3. Regra Alternativa (SQL Injection - Python/Django):**
```yaml
# regras/sql-injection-django.yaml
rules:
  - id: sql-injection-django-raw
    languages: [python]
    severity: ERROR
    message: "Potential SQL Injection in Django .raw() or .extra(). User input '$INPUT' is directly used in SQL. Use parameterized queries instead."
    patterns:
      - pattern-either:
          - pattern: |
              $MODEL.objects.raw("...$INPUT...")
          - pattern: |
              $MODEL.objects.extra(where=["...$INPUT..."])
    exceptions:
      - pattern-inside: |
          # Safe: Parameterized query
          Model.objects.raw("SELECT * WHERE id = %s", [user_id])
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 – Injection"
```

### Passo 4: Testar Regra

**Solução Esperada:**

**4.1. Código de Teste:**
```python
# test_code.py
import os

# ❌ Deve ser flagado
API_KEY = "sk_live_1234567890abcdef"
aws_key = "AKIAIOSFODNN7EXAMPLE"
GOOGLE_API_KEY = "ya29.a0AfH6SMBwF..."

# ✅ Não deve ser flagado (usa variável de ambiente)
api_key_env = os.getenv("API_KEY")

# ✅ Não deve ser flagado (não é API key)
database_url = "postgresql://user:pass@host/db"
```

**4.2. Executar Regra:**
```bash
semgrep --config=regras/hardcoded-api-keys.yaml test_code.py
```

**4.3. Saída Esperada:**
```
test_code.py
  hardcoded-api-keys
    Line 4: API_KEY = "sk_live_1234567890abcdef"
    Message: Hardcoded API key detected. Use environment variables...
    Severity: ERROR
    CWE: CWE-798

    Line 5: aws_key = "AKIAIOSFODNN7EXAMPLE"
    Message: Hardcoded API key detected...
    Severity: ERROR

    Line 6: GOOGLE_API_KEY = "ya29.a0AfH6SMBwF..."
    Message: Hardcoded API key detected...
    Severity: ERROR
```

**4.4. Validar Resultados:**
- ✅ Flagga código vulnerável corretamente (3 findings)
- ✅ Não flagga código seguro (variável de ambiente, database_url)
- ✅ Mensagens são claras e acionáveis

**Problemas Comuns:**
- Regra não flagga nada → Verificar regex, padrões corretos
- Regra flagga código seguro → Adicionar exceções ou refinar regex
- Muitos false positives → Refinar condições `where`

### Passo 5: Regras Adicionais (Exemplos)

**5.1. Regra: Logging de Dados Sensíveis**
```yaml
# regras/sensitive-data-logging.yaml
rules:
  - id: sensitive-data-in-logs
    languages: [python, javascript]
    severity: WARNING
    message: "Potential sensitive data in log statement. Avoid logging personal information, passwords, tokens, or credit card numbers."
    patterns:
      - pattern: |
          logging.$LEVEL(..., $DATA, ...)
        where:
          - metavariable-regex:
              metavariable: $DATA
              regex: (password|token|cpf|rg|credit_card|cvv|api_key|secret|senha)
    metadata:
      cwe: "CWE-532: Insertion of Sensitive Information into Log File"
      owasp: "A09:2021 – Security Logging and Monitoring Failures"
```

**5.2. Regra: Insecure Deserialization (Python)**
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

### Passo 6: Integrar Regras no Workflow

**Solução Esperada:**

**6.1. Pre-commit Hook:**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config=auto', '--config=regras/', '--error']
```

**6.2. CI/CD (GitHub Actions):**
```yaml
# .github/workflows/semgrep.yml
name: Semgrep Security Scan

on:
  pull_request:
    branches: [main]
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
            p/security-audit
            regras/
          generateSarif: "1"
          fail_on_severity: error
```

**6.3. Documentação (README):**
```markdown
# Regras Semgrep Customizadas

## hardcoded-api-keys.yaml
- **Descrição**: Detecta API keys hardcoded no código
- **Severidade**: ERROR
- **Uso**: `semgrep --config=regras/hardcoded-api-keys.yaml src/`

## sql-injection-django.yaml
- **Descrição**: Detecta SQL Injection em queries Django
- **Severidade**: ERROR
- **Uso**: `semgrep --config=regras/sql-injection-django.yaml src/`
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (60 pontos)

**Identificação de Padrão:**
- [ ] Padrão inseguro identificado no código (10 pontos)
- [ ] Contexto e risco explicados (10 pontos)

**Criação de Regra:**
- [ ] Regra Semgrep criada em YAML (15 pontos)
- [ ] Regra segue estrutura correta (metavariables, patterns, metadata) (10 pontos)

**Teste e Validação:**
- [ ] Regra testada em código de exemplo (10 pontos)
- [ ] Regra funciona corretamente (flagga vulnerável, não flagga seguro) (5 pontos)

### ⭐ Importantes (25 pontos)

**Regra Funcional:**
- [ ] Regra detecta vulnerabilidades reais no projeto (10 pontos)
- [ ] Mensagens de erro são claras e acionáveis (5 pontos)

**Documentação:**
- [ ] Regra documentada no README (5 pontos)
- [ ] Regra adicionada ao repositório (5 pontos)

**Integração:**
- [ ] Regra integrada no workflow (pre-commit ou CI/CD) (10 pontos)

### 💡 Bônus (15 pontos)

**Regras Adicionais:**
- [ ] Cria 2-3 regras customizadas (5 pontos)
- [ ] Regras cobrem diferentes tipos de vulnerabilidades (5 pontos)

**Refinamento:**
- [ ] Regras têm exceções configuradas para evitar false positives (5 pontos)
- [ ] Regras testadas em projeto real e validadas (5 pontos)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Análise de Padrões**: Aluno identifica padrões inseguros no código?
2. **Criação de Regras**: Aluno cria regras Semgrep funcionais?
3. **Teste e Validação**: Aluno testa e valida regras corretamente?
4. **Integração**: Aluno integra regras no workflow de desenvolvimento?

### Erros Comuns

1. **Erro: Regra Não Flagga Nada**
   - **Situação**: Regra criada mas não detecta vulnerabilidades
   - **Feedback**: "Regra criada corretamente! Se não está flaggando, verifique: regex está correto? Padrões estão corretos? Linguagem especificada? Teste com `semgrep -X` (debug mode) para ver o que está sendo analisado."

2. **Erro: Regra Flagga Tudo (Muitos False Positives)**
   - **Situação**: Regra flagga código seguro também
   - **Feedback**: "Boa regra! Para reduzir false positives, adicione exceções ou refine as condições `where`. Por exemplo, se flagga teste, adicione exceção: `- pattern-inside: '# Test file'` ou refine regex para ser mais específico."

3. **Erro: Estrutura YAML Incorreta**
   - **Situação**: Regra não funciona por sintaxe YAML incorreta
   - **Feedback**: "Estrutura da regra está quase correta! Verifique indentação YAML (espaços, não tabs). Teste a sintaxe com `semgrep --validate` antes de executar."

4. **Erro: Regex Muito Genérico ou Específico**
   - **Situação**: Regex não captura casos ou captura demais
   - **Feedback**: "Boa tentativa! Regex precisa de ajuste: se não captura, torne mais genérico (use `.*`). Se captura demais, torne mais específico (use prefixos/sufixos conhecidos). Teste regex em https://regex101.com/ antes de usar."

### Dicas para Feedback

- ✅ **Reconheça**: Identificação de padrões reais, regras funcionais, integração bem feita
- ❌ **Corrija**: Sintaxe YAML incorreta, regex mal formado, falta de testes
- 💡 **Incentive**: Criar múltiplas regras, adicionar exceções, documentar bem

### Contexto Pedagógico

Este exercício é importante porque:

1. **Customização**: Regras customizadas são essenciais para contextos específicos
2. **Prevenção**: Detecta padrões inseguros antes de commit
3. **Automação**: Integra segurança no workflow de desenvolvimento
4. **Escalabilidade**: Regras podem ser compartilhadas com o time

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
