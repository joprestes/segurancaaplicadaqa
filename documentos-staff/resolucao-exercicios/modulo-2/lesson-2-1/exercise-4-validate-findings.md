---
exercise_id: lesson-2-1-exercise-4-validate-findings
title: "Exercício 2.1.4: Validar e Priorizar Findings SAST"
lesson_id: lesson-2-1
module: module-2
difficulty: "Avançado"
last_updated: 2025-01-15
---

# Exercício 2.1.4: Validar e Priorizar Findings SAST

## 📋 Enunciado Completo

Este exercício tem como objetivo **criar processo de triagem e validação de findings SAST**, diferenciar false positives de true positives, e priorizar vulnerabilidades por risco real.

### Tarefa Principal

1. Executar SAST em projeto real
2. Para cada finding Critical/High:
   - Validar se é True Positive ou False Positive
   - Analisar contexto e impacto
   - Priorizar por risco real
   - Documentar decisão
3. Criar dashboard de vulnerabilidades priorizadas
4. Criar processo de triagem documentado

---

## ✅ Soluções Detalhadas

### Passo 1: Executar SAST

**Solução Esperada:**

**1.1. Consolidar Resultados:**
```json
{
  "scan_date": "2024-01-15",
  "tool": "semgrep",
  "total_findings": 45,
  "by_severity": {
    "critical": 2,
    "high": 8,
    "medium": 15,
    "low": 20
  },
  "findings": [
    {
      "id": "finding-001",
      "tool": "semgrep",
      "rule_id": "sql-injection",
      "severity": "ERROR",
      "file": "src/auth.py",
      "line": 45,
      "message": "Potential SQL Injection...",
      "cwe": "CWE-89",
      "owasp": "A03:2021 – Injection"
    }
  ]
}
```

### Passo 2: Processo de Validação

**Solução Esperada - Template Preenchido:**

**Exemplo 1: True Positive - SQL Injection**
```markdown
## Finding: finding-001 - SQL Injection

### Metadados
- **Finding ID**: finding-001
- **Severidade SAST**: Critical 🔴
- **CWE**: CWE-89 (SQL Injection)
- **OWASP Top 10**: A03:2021 – Injection
- **Ferramenta**: Semgrep
- **Arquivo**: `src/auth.py`
- **Linha**: 45

### Código Flagado
```python
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ SQL Injection
    return db.execute(query)
```

### Análise de Contexto
- [x] **Dados são validados antes de usar?** ❌ Não
- [x] **Há sanitização?** ❌ Não (concatenação direta)
- [x] **Código está em produção?** ✅ Sim
- [x] **Acesso requer autenticação?** ✅ Sim
- [x] **Dados sensíveis afetados?** ✅ Sim (dados de usuários)

### Análise de Risco
**Exploitability**: ALTA ⚠️
- Pode ser explorado facilmente via API
- Exemplo: `GET /users/1 OR 1=1--`

**Impacto**: ALTO ⚠️
- Pode expor dados de todos os usuários
- Violação LGPD

**Contexto**: CRÍTICO ⚠️
- Código em produção
- Endpoint público
- Dados sensíveis

### Decisão
- [x] **True Positive - P1 (Corrigir IMEDIATAMENTE)**
- [ ] False Positive
- [ ] Aceitar Risco

### Correção Implementada
```python
def get_user(user_id):
    # ✅ Validação
    if not user_id.isdigit():
        raise ValueError("Invalid user ID")
    
    # ✅ Prepared statement
    query = "SELECT * FROM users WHERE id = %s"
    return db.execute(query, (user_id,))
```

### Validação Pós-Correção
- [x] SAST re-executado - Finding removido ✅
- [x] Testes adicionados ✅
- [x] Deploy realizado ✅
```

**Exemplo 2: False Positive - Hardcoded Password em Teste**
```markdown
## Finding: finding-002 - Hardcoded Password (False Positive)

### Metadados
- **Severidade SAST**: High 🟠
- **CWE**: CWE-798 (Hard-coded Credentials)
- **Arquivo**: `tests/test_auth.py`
- **Linha**: 23

### Código Flagado
```python
def test_default_password():
    password = "changeme123"  # ← Flagado
    assert_raises(Exception, lambda: auth_service.login("admin", password))
```

### Análise
- [x] **É código de teste?** ✅ Sim
- [x] **Password usado em produção?** ❌ Não
- [x] **Há validação que rejeita?** ✅ Sim (teste valida rejeição)

### Decisão
- [ ] True Positive
- [x] **False Positive - Marcar como resolvido**
  - Razão: Password hardcoded é esperado em teste que valida rejeição de senha padrão
  - Contexto: Código em `tests/`, não executado em produção

### Ação
- Marcar como "False Positive" no SonarQube
- Adicionar comentário: `# nosec B106` ou `@SuppressWarnings`
- Configurar exceção na regra SAST para arquivos de teste
```

### Passo 3: Priorização

**Solução Esperada - Matriz de Priorização:**

| Severidade SAST | Exploitability | Impacto | Produção | Prioridade | Prazo |
|----------------|----------------|---------|----------|------------|-------|
| Critical | Alta | Dados sensíveis | Sim | P1 - IMEDIATO | 24h |
| Critical | Alta | Dados sensíveis | Não | P2 - Este Sprint | 1 semana |
| High | Alta | Dados sensíveis | Sim | P2 - Este Sprint | 1 semana |
| High | Média | Dados sensíveis | Não | P3 - Próximo Sprint | 2 semanas |
| Medium | Alta | Dados sensíveis | Sim | P3 - Próximo Sprint | 2 semanas |

**Solução Esperada - Dashboard:**
```markdown
# Dashboard de Vulnerabilidades SAST

**Última atualização**: 2024-01-15  
**Total de Findings**: 45  
**True Positives**: 32  
**False Positives**: 13

## P1 - IMEDIATO (Corrigir em 24h)
| ID | Tipo | Arquivo | Responsável | Prazo | Status |
|----|------|---------|-------------|-------|--------|
| F-001 | SQL Injection | src/auth.py:45 | João Silva | 2024-01-16 | Em andamento |
| F-002 | Hardcoded Secret | src/config.py:12 | Maria Santos | 2024-01-16 | Aberto |

## P2 - Este Sprint (1 semana)
| ID | Tipo | Arquivo | Responsável | Prazo | Status |
|----|------|---------|-------------|-------|--------|
| F-003 | XSS | src/public.js:78 | Pedro Costa | 2024-01-22 | Aberto |

## Estatísticas
- **Por Severidade**: Critical: 2 (1 TP, 1 FP), High: 8 (6 TP, 2 FP)
- **Por Status**: Aberto: 15, Em andamento: 5, Resolvido: 12
- **Por Prioridade**: P1: 2, P2: 6, P3: 10, P4: 14
```

### Passo 4: Processo de Triagem

**Solução Esperada:**
```markdown
# Processo de Triagem de Findings SAST

## Objetivo
Validar findings SAST, diferenciar True Positives de False Positives, e priorizar por risco real.

## Processo

### 1. Execução de SAST
- SAST executado automaticamente em cada PR
- SAST executado diariamente (scheduled)

### 2. Triagem Inicial
- QA revisa findings Critical/High
- Preenche template de validação

### 3. Validação
- True Positive → Priorizar
- False Positive → Marcar como resolvido
- Dúvida → Discutir com dev

### 4. Priorização
- Usar matriz de priorização
- Atribuir P1/P2/P3/P4

### 5. Tracking
- Criar issue para True Positives P1/P2/P3
- Atribuir responsável e prazo

### 6. Validação Pós-Correção
- SAST re-executado
- Validar que finding foi removido
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (60 pontos)

**Validação de Findings:**
- [ ] SAST executado em projeto real (10 pontos)
- [ ] Template de validação preenchido para cada Critical/High (15 pontos)
- [ ] True Positives identificados corretamente (10 pontos)
- [ ] False Positives identificados e documentados (10 pontos)

**Priorização:**
- [ ] Priorização por risco real realizada (P1/P2/P3/P4) (15 pontos)

### ⭐ Importantes (25 pontos)

**Análise Detalhada:**
- [ ] Análise de contexto completa (exploitability, impacto) (10 pontos)
- [ ] Dashboard de vulnerabilidades criado (10 pontos)
- [ ] Processo de triagem documentado (5 pontos)

**Documentação:**
- [ ] Justificativas claras para cada decisão (5 pontos)
- [ ] Correções sugeridas quando True Positive (5 pontos)

### 💡 Bônus (15 pontos)

**Processo Completo:**
- [ ] Processo de triagem implementado e testado (5 pontos)
- [ ] Issues criadas para True Positives (5 pontos)
- [ ] Métricas de triagem documentadas (5 pontos)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Validação**: Aluno diferencia true/false positives?
2. **Análise**: Aluno analisa contexto e risco?
3. **Priorização**: Aluno prioriza por risco real?
4. **Processo**: Aluno cria processo documentado?

### Erros Comuns

1. **Erro: Assumir Tudo é True Positive**
   - **Situação**: Aluno marca tudo como vulnerabilidade real
   - **Feedback**: "Boa análise! Lembre-se de que SAST gera false positives (20-40%). Sempre valide manualmente, especialmente código de teste ou configurações específicas."

2. **Erro: Priorizar Apenas por Severidade SAST**
   - **Situação**: Aluno prioriza Critical primeiro sem considerar contexto
   - **Feedback**: "Excelente identificação! Considere também: código em produção? dados sensíveis? fácil explorar? Isso ajuda a priorizar por risco real, não apenas severidade técnica."

3. **Erro: Não Documentar False Positives**
   - **Situação**: Aluno marca false positive mas não documenta razão
   - **Feedback**: "Boa identificação do false positive! Documente sempre a razão para auditoria futura e para evitar re-discussão do mesmo finding."

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
