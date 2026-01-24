---
exercise_id: lesson-2-1-exercise-2-semgrep-custom-rules
title: "Exercício 2.1.2: Criar Regras Customizadas Semgrep"
lesson_id: lesson-2-1
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.1.2: Criar Regras Customizadas Semgrep

## 📋 Enunciado Completo

Este exercício tem como objetivo **criar regras customizadas Semgrep** para detectar padrões inseguros específicos do seu projeto.

### Tarefa

1. Identificar padrão inseguro comum no código
2. Criar regra Semgrep para detectar esse padrão
3. Testar regra em código existente
4. Validar que regra funciona corretamente
5. Documentar regra e adicionar ao repositório

---

## ✅ Soluções Detalhadas

### Solução Esperada: Regra Semgrep Funcional

**Exemplo de regra bem construída:**

```yaml
# regras/hardcoded-secrets.yaml
rules:
  - id: hardcoded-api-keys
    languages: [python]
    severity: ERROR
    message: "Hardcoded API key detected. Use environment variables instead."
    patterns:
      - pattern-either:
          - pattern: $VAR = "sk_live_..."
          - pattern: $VAR = "AKIA..."
          - pattern: $VAR = "ya29..."
    metadata:
      cwe: "CWE-798"
      owasp: "A07:2021"
      category: security
```

**Evidências de regra funcional:**
- Regra detecta padrões inseguros corretamente
- Teste com código vulnerável valida eficácia
- Falsos positivos são mínimos (< 20%)
- Documentação clara explica quando regra se aplica

**Teste esperado:**

```python
# test_code.py
API_KEY = "sk_live_abc123"  # ❌ DEVE flagar
api_key = os.getenv("API_KEY")  # ✅ NÃO deve flagar

# Executar:
# semgrep --config=regras/hardcoded-secrets.yaml test_code.py
# Resultado: 1 finding (linha 2)
```

---

### Padrões Comuns a Detectar

**Prioridade Alta (recomendado começar por aqui):**

1. **Hardcoded Secrets** (API keys, passwords, tokens)
2. **SQL Injection** (string concatenation em queries)
3. **Command Injection** (subprocess/exec com input usuário)
4. **Path Traversal** (leitura de arquivos com path dinâmico)

**Prioridade Média:**

5. **Weak Cryptography** (MD5, SHA1, DES)
6. **Insecure Deserialization** (pickle.load, yaml.load)
7. **XSS** (innerHTML com dados não sanitizados)
8. **Logging Sensitive Data** (log.info com PII)

---

## 📊 Critérios de Avaliação (Abordagem Qualitativa)

### ✅ Aspectos Essenciais

**Regra Funcional:**
- [ ] Regra criada em YAML válido
- [ ] Pattern detecta vulnerabilidades reais
- [ ] Testado com código vulnerável (positivo)
- [ ] Testado com código seguro (negativo)

**Documentação:**
- [ ] Message clara e acionável para devs
- [ ] Metadata com CWE e OWASP
- [ ] Exemplos de código vulnerável e seguro

### ⭐ Aspectos Importantes

**Qualidade da Regra:**
- [ ] Poucos false positives (< 20%)
- [ ] Detecta variações do padrão inseguro
- [ ] Exceções documentadas quando aplicável
- [ ] Testada em projeto real (não apenas código de exemplo)

**Integração:**
- [ ] Regra adicionada ao repositório (`regras/` ou `.semgrep/`)
- [ ] Documentação de como executar (README)
- [ ] CI/CD configurado para executar regra (diferencial)

### 💡 Aspectos Diferencial

**Profundidade Técnica:**
- [ ] Criou múltiplas regras (2-3) para diferentes padrões
- [ ] Regras consideram contexto (framework específico)
- [ ] Configurou severidade apropriada (ERROR vs WARNING)
- [ ] Testou com benchmarks (OWASP Benchmark, Juliet)

**Impacto Prático:**
- [ ] Regra encontrou vulnerabilidades reais no projeto
- [ ] Time de dev adotou regra no workflow
- [ ] Reduziu vulnerabilidades em sprints subsequentes

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Pattern Matching**: Compreende sintaxe de patterns do Semgrep?
2. **Teste de Regras**: Valida com código vulnerável E seguro?
3. **False Positives**: Minimiza FPs com patterns precisos?
4. **Documentação**: Message e metadata são claros?

### Erros Comuns

**Erro 1: "Regra muito genérica (muitos false positives)"**
```yaml
# ❌ Ruim: Flaga TUDO que é string
- pattern: $VAR = "..."

# ✅ Bom: Específico para API keys
- pattern: $VAR = "sk_live_..."
  where:
    - metavariable-regex:
        metavariable: $VAR
        regex: (api_key|API_KEY)
```
**Orientação**: "Sua regra está muito genérica. Adicione condições (where, metavariable-regex) para detectar apenas padrões inseguros. Teste com código real e ajuste até FP rate < 20%."

**Erro 2: "Não testou com código negativo"**
**Orientação**: "Você testou apenas código vulnerável. Teste também código SEGURO para garantir que regra NÃO flaga incorretamente. Exemplo: `api_key = os.getenv('API_KEY')` não deve ser flagado."

**Erro 3: "Message vaga ou não acionável"**
```yaml
# ❌ Ruim
message: "Security issue detected"

# ✅ Bom
message: "Hardcoded API key detected. Move to environment variable: os.getenv('API_KEY')"
```
**Orientação**: "Message deve ser acionável. Diga O QUE está errado e COMO corrigir. Dev deve entender sem consultar documentação."

**Erro 4: "Não documentou exceções"**
**Orientação**: "Algumas regras têm exceções válidas (ex: hardcoded password em testes). Documente quando regra NÃO se aplica e considere usar `pattern-not` para excluir esses casos."

### Dicas para Feedback Construtivo

**Para regra profissional:**
> "Excelente trabalho! Sua regra detecta vulnerabilidades reais com baixa taxa de FP. Message é clara e acionável. Metadata completo. Próximo nível: integre no CI/CD (Exercício 2.1.3) e monitore eficácia ao longo do tempo."

**Para regra funcional mas básica:**
> "Boa criação de regra! Ela funciona mas pode melhorar: 1) Adicione metavariable-regex para reduzir FPs, 2) Teste com código real do projeto (não apenas exemplos), 3) Documente exceções. Refine a regra com base em feedback do time."

**Para dificuldades:**
> "Vejo que você teve dificuldades. Comece simples: 1) Use Semgrep Playground (https://semgrep.dev/playground) para testar patterns, 2) Clone regras existentes (https://semgrep.dev/r) e adapte, 3) Teste incrementalmente (pattern básico → adicione condições). Agende monitoria se precisar."

### Contexto Pedagógico

**Por que este exercício é importante:**

1. **Personalização**: Detecta padrões específicos do seu contexto
2. **Proatividade**: Previne vulnerabilidades ANTES de chegarem a prod
3. **Educação**: Regra customizada educa time sobre padrões inseguros
4. **Escalabilidade**: Uma regra detecta N ocorrências automaticamente

**Conexão com o Curso:**
- **Pré-requisito**: Exercício 2.1.1 (SonarQube Setup)
- **Aplica conceitos**: Pattern matching, SAST customizado, CWE, OWASP
- **Prepara para**: Exercício 2.1.3 (SAST no CI/CD)

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Regra Profissional (Nível Avançado)

```yaml
# regras/insecure-deserialization.yaml
rules:
  - id: insecure-pickle-load
    languages: [python]
    severity: ERROR
    message: |
      Insecure deserialization detected using pickle.load().
      pickle.load() can execute arbitrary code if data is malicious.
      
      Recommendation:
      - If possible, use JSON (json.loads()) instead of pickle
      - If pickle is required, validate data source and use HMAC signature
      - Never unpickle data from untrusted sources
      
      Example secure alternative:
        import json
        data = json.loads(user_input)
    
    patterns:
      - pattern-either:
          - pattern: pickle.load($FILE)
          - pattern: pickle.loads($DATA)
      - pattern-not-inside: |
          # Exceção: testes são OK
          def test_$FUNC(...):
            ...
    
    metadata:
      cwe: "CWE-502: Deserialization of Untrusted Data"
      owasp: "A08:2021 – Software and Data Integrity Failures"
      category: security
      technology: [python]
      confidence: HIGH
      likelihood: MEDIUM
      impact: HIGH
      references:
        - https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data
        - https://docs.python.org/3/library/pickle.html#security
```

**Teste realizado:**

```python
# test_insecure_deserialization.py
import pickle

# ❌ DEVE flagar (código vulnerável)
def load_user_data(file_path):
    with open(file_path, 'rb') as f:
        return pickle.load(f)  # FLAGADO

# ✅ NÃO deve flagar (teste - exceção)
def test_pickle_serialization():
    data = {"key": "value"}
    serialized = pickle.dumps(data)
    deserialized = pickle.loads(serialized)  # NÃO FLAGADO (teste)

# ✅ Alternativa segura
import json

def load_user_data_safe(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)  # NÃO FLAGADO (seguro)
```

**Resultados:**

```bash
$ semgrep --config=regras/insecure-deserialization.yaml test_insecure_deserialization.py

test_insecure_deserialization.py
  insecure-pickle-load
    Line 5: pickle.load(f)
    Message: Insecure deserialization detected...
    
1 finding: 1 ERROR
```

**Impacto no projeto:**
- Encontrou 3 ocorrências de `pickle.load()` em produção
- 2 eram vulneráveis (dados de API externa)
- 1 era seguro (dados internos validados)
- Time corrigiu P0s em 48h

**Por que é exemplar:**
- ✅ Message detalhada com recomendações práticas
- ✅ Exceção para testes (pattern-not-inside)
- ✅ Metadata completo (CWE, OWASP, confidence, impact)
- ✅ Referências para aprofundamento
- ✅ Testado com código real e de teste
- ✅ Encontrou vulnerabilidades reais

---

### Exemplo 2: Regra Adequada (Nível Intermediário)

```yaml
# regras/sql-injection.yaml
rules:
  - id: sql-string-concat
    languages: [python]
    severity: ERROR
    message: "SQL injection risk: query uses string concatenation. Use parameterized queries instead."
    patterns:
      - pattern: cursor.execute($QUERY + $VAR)
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021"
```

**Teste:**

```python
# ❌ Detectado
cursor.execute("SELECT * FROM users WHERE id=" + user_id)

# ✅ Não detectado (mas deveria! - limitação da regra)
query = "SELECT * FROM users WHERE id=" + user_id
cursor.execute(query)
```

**Por que é adequado:**
- ✅ Regra funciona para padrão básico
- ✅ Message clara
- ✅ Metadata básico presente
- ⚠️ Limitação: não detecta todas as variações
- ⚠️ Falta: teste com código negativo
- ⚠️ Falta: referências

**Feedback sugerido:**
> "Boa criação de regra! Ela detecta o padrão básico. Para melhorar: 1) Adicione pattern-either para detectar variações (f-strings, format()), 2) Teste com código seguro (`cursor.execute(query, params)`), 3) Adicione exemplos no metadata. Sua regra está funcional, agora refine!"

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
