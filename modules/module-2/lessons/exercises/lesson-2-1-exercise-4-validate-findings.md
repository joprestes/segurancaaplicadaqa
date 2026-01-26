---
layout: exercise
title: "Exercício 2.1.4: Validar e Priorizar Findings SAST"
slug: "validate-findings"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Avançado"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-1-exercise-4-validate-findings/
lesson_url: /modules/testes-seguranca-pratica/lessons/sast-testes-estaticos/
---

## Objetivo

Este exercício tem como objetivo **criar processo de triagem e validação de findings SAST**, diferenciar false positives de true positives, e priorizar vulnerabilidades por risco real.

Ao completar este exercício, você será capaz de:

- Validar findings SAST como True Positive ou False Positive
- Analisar contexto e impacto de vulnerabilidades
- Priorizar vulnerabilidades por risco real (não apenas severidade SAST)
- Criar processo documentado de triagem
- Criar dashboard de vulnerabilidades priorizadas

---

## Descrição

Você vai executar SAST em um projeto real (ou projeto de exemplo), validar cada finding Critical/High, diferenciar false positives de true positives, analisar contexto e impacto, e criar processo documentado de priorização.

### Contexto

Nem tudo que SAST reporta é vulnerabilidade real. É fundamental validar findings, entender contexto, e priorizar por risco real para focar esforço onde realmente importa.

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

## Pré-requisitos

- Projeto de código-fonte para análise
- Ferramenta SAST configurada (Semgrep, SonarQube ou Bandit)
- Conhecimento básico de CVSS e priorização de risco

---

## Passo a Passo

### Passo 1: Executar SAST em Projeto Real

**1.1. Escolher Projeto**

- Projeto próprio (preferido)
- Ou projeto de exemplo (OWASP Juice Shop, WebGoat, etc.)

**1.2. Executar SAST**

```bash
# Executar Semgrep
semgrep --config=auto --json --output=semgrep-results.json .

# Ou executar SonarQube
sonar-scanner

# Ou executar Bandit (Python)
bandit -r . -f json -o bandit-results.json

# Exportar resultados consolidados
python3 scripts/export_sast_results.py
```

**1.3. Consolidar Resultados**

Criar arquivo `sast-findings.json` com todos os findings:

```json
{
  "scan_date": "2026-01-14",
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

**2.1. Criar Template de Validação**

Criar arquivo `templates/validation-template.md`:

```markdown
## Finding: [ID] - [Tipo de Vulnerabilidade]

### Metadados
- **Finding ID**: finding-001
- **Severidade SAST**: Critical 🔴
- **CWE**: CWE-89 (SQL Injection)
- **OWASP Top 10**: A03:2021 – Injection
- **Ferramenta**: Semgrep
- **Arquivo**: `src/auth.py`
- **Linha**: 45
- **Regra**: sql-injection

### Código Flagado
\`\`\`python
[código vulnerável aqui]
\`\`\`

### Contexto do Código
[Descrição do contexto: função, classe, propósito]

### Análise de Contexto
- [ ] **Dados são validados antes de usar?**
  - [ ] Sim - Como? ___________
  - [ ] Não
  
- [ ] **Há sanitização (prepared statements, escaping)?**
  - [ ] Sim - Como? ___________
  - [ ] Não
  
- [ ] **Código está em produção?**
  - [ ] Sim - Desde quando? ___________
  - [ ] Não - Em desenvolvimento
  
- [ ] **Acesso requer autenticação?**
  - [ ] Sim - Tipo? ___________
  - [ ] Não
  
- [ ] **Dados sensíveis afetados?**
  - [ ] Sim - Quais? ___________
  - [ ] Não
  
- [ ] **Endpoint/function é público?**
  - [ ] Sim
  - [ ] Não - Requer autenticação/autorização

### Análise de Risco

**Exploitability (Fácil explorar?)**: ALTA / MÉDIA / BAIXA

**Justificativa**: 
[Por que é fácil ou difícil explorar?]

**Impacto (Dados sensíveis afetados?)**: CRÍTICO / ALTO / MÉDIO / BAIXO

**Justificativa**:
[Qual o impacto se explorado?]

**Contexto do Negócio**:
- Código em produção: Sim / Não
- Volume de usuários afetados: ___________
- Área crítica do sistema: Sim / Não
- Compliance afetado: Sim / Não - Qual? ___________

### Decisão

- [ ] **True Positive - Vulnerabilidade Real**
  - [ ] Corrigir imediatamente (P1)
  - [ ] Corrigir neste Sprint (P2)
  - [ ] Corrigir no próximo Sprint (P3)
  - [ ] Backlog (P4)
  
- [ ] **False Positive - Não é vulnerabilidade**
  - Razão: ___________
  - [ ] Marcar como resolvido
  - [ ] Adicionar exceção na regra SAST
  
- [ ] **Risco Aceito - Não será corrigido**
  - Justificativa: ___________
  - Mitigações implementadas: ___________
  - Aprovação: ___________

### Ação Corretiva (se True Positive)

**Correção Implementada**:
\`\`\`python
[código corrigido aqui]
\`\`\`

**Validação**:
- [ ] SAST re-executado - Finding removido ✅
- [ ] Testes de segurança adicionados ✅
- [ ] Code review aprovado ✅
- [ ] Deploy em produção ✅

### Tracking
- **Issue**: SEC-XXX
- **Responsável**: ___________
- **Prazo**: ___________
- **Status**: Aberto / Em andamento / Resolvido
```

**2.2. Validar Cada Finding**

Para cada finding Critical/High:

1. Ler código ao redor (mínimo 20 linhas antes/depois)
2. Analisar contexto completo
3. Preencher template de validação
4. Decidir: True Positive, False Positive, ou Risco Aceito
5. Priorizar se True Positive

### Passo 3: Exemplos de Validação

**3.1. Exemplo 1: True Positive - SQL Injection**

```python
# Finding: SQL Injection em UserService.getUser()
# Arquivo: src/services/UserService.py:45

@GetMapping("/users/{id}")
public User getUser(@PathVariable String id) {
    // ❌ SAST detecta SQL Injection
    String query = "SELECT * FROM users WHERE id = " + id;
    return db.executeQuery(query);
}
```

**Análise**:
- Dados validados? ❌ Não
- Sanitização? ❌ Não (concatenação direta)
- Em produção? ✅ Sim
- Requer autenticação? ✅ Sim (endpoint autenticado)
- Dados sensíveis? ✅ Sim (dados de usuários)

**Decisão**: ✅ **True Positive - P1 (Corrigir IMEDIATAMENTE)**

**Razão**: SQL Injection em produção com dados sensíveis. Pode ser explorado facilmente.

**Correção**:
```java
@GetMapping("/users/{id}")
public User getUser(@PathVariable String id) {
    // ✅ Prepared Statement
    String query = "SELECT * FROM users WHERE id = ?";
    return db.executeQuery(query, id);  // Parâmetroizado
}
```

**3.2. Exemplo 2: False Positive - Hardcoded Password em Teste**

```python
# Finding: Hardcoded password em SecurityTest.testDefaultPassword()
# Arquivo: src/test/SecurityTest.py:23

def test_default_password():
    # SAST detecta: "Hardcoded password"
    password = "changeme123"  # ← Flagged
    
    # Mas na prática:
    assert_raises(Exception, lambda: auth_service.login("admin", password))
```

**Análise**:
- É código de teste? ✅ Sim (arquivo em `src/test/`)
- Password usado para autenticação real? ❌ Não
- Há validação que rejeita? ✅ Sim (teste valida rejeição)

**Decisão**: ✅ **False Positive - Marcar como resolvido**

**Razão**: Password hardcoded é esperado em teste que valida rejeição de senha padrão.

**Ação**:
- Marcar como "False Positive" no SonarQube
- Adicionar comentário no código explicando contexto
- Configurar exceção na regra SAST para arquivos de teste

**3.3. Exemplo 3: Risco Aceito - XSS Low em Área Interna**

```javascript
// Finding: XSS em admin panel (área interna)
// Arquivo: src/admin/notifications.js:12

function displayNotification(message) {
    // SAST detecta: "Potential XSS"
    document.getElementById('notification').innerHTML = message;  // ← Flagged
}
```

**Análise**:
- Requer autenticação admin? ✅ Sim
- Mensagens vêm de fonte confiável? ✅ Sim (sistema interno)
- Dados do usuário não confiável? ❌ Não (mensagens internas)
- Área pública? ❌ Não (área admin interna)

**Decisão**: ⚠️ **True Positive - P4 (Risco Aceito, Backlog)**

**Justificativa**: XSS existe tecnicamente, mas risco é baixo porque:
- Requer autenticação admin
- Mensagens vêm de fonte confiável
- Não está em área pública
- Impacto limitado

**Mitigação**: Adicionar sanitização quando possível, mas não é urgente.

### Passo 4: Priorização por Risco Real

**4.1. Criar Matriz de Priorização**

| Severidade SAST | Exploitability | Impacto | Código em Prod | Prioridade Final | Prazo |
|----------------|----------------|---------|----------------|------------------|-------|
| Critical | Alta | Dados sensíveis | Sim | P1 - IMEDIATO | 24h |
| Critical | Alta | Dados sensíveis | Não | P2 - Este Sprint | 1 semana |
| High | Alta | Dados sensíveis | Sim | P2 - Este Sprint | 1 semana |
| High | Média | Dados sensíveis | Não | P3 - Próximo Sprint | 2 semanas |
| Medium | Alta | Dados sensíveis | Sim | P3 - Próximo Sprint | 2 semanas |
| Medium | Baixa | Dados não sensíveis | Não | P4 - Backlog | Quando possível |

**4.2. Priorizar Findings**

Para cada finding validado como True Positive:

1. Classificar por severidade SAST
2. Avaliar exploitability (fácil explorar?)
3. Avaliar impacto (dados sensíveis?)
4. Considerar contexto (produção, volume de usuários)
5. Atribuir prioridade final (P1, P2, P3, P4)

### Passo 5: Criar Dashboard de Vulnerabilidades

**5.1. Criar Dashboard Simplificado**

Criar arquivo `dashboard/vulnerabilities.md`:

```markdown
# Dashboard de Vulnerabilidades SAST

**Última atualização**: 2026-01-14  
**Total de Findings**: 45  
**True Positives**: 32  
**False Positives**: 13

## Prioridades

### P1 - IMEDIATO (Corrigir em 24h)
| ID | Tipo | Arquivo | Linha | Responsável | Prazo | Status |
|----|------|---------|-------|-------------|-------|--------|
| F-001 | SQL Injection | src/auth.py | 45 | João Silva | 2026-01-16 | Em andamento |
| F-002 | Hardcoded Secret | src/config.py | 12 | Maria Santos | 2026-01-16 | Aberto |

### P2 - Este Sprint (Corrigir em 1 semana)
| ID | Tipo | Arquivo | Linha | Responsável | Prazo | Status |
|----|------|---------|-------|-------------|-------|--------|
| F-003 | XSS | src/public.js | 78 | Pedro Costa | 2026-01-22 | Aberto |

### P3 - Próximo Sprint (Corrigir em 2 semanas)
[...]

### P4 - Backlog
[...]

## Estatísticas

- **Por Severidade SAST**:
  - Critical: 2 findings (1 TP, 1 FP)
  - High: 8 findings (6 TP, 2 FP)
  - Medium: 15 findings (12 TP, 3 FP)
  - Low: 20 findings (13 TP, 7 FP)

- **Por Status**:
  - Aberto: 15
  - Em andamento: 5
  - Resolvido: 12

- **Por Prioridade**:
  - P1: 2 findings
  - P2: 6 findings
  - P3: 10 findings
  - P4: 14 findings
```

**5.2. Dashboard Automatizado (Opcional)**

Criar script Python para gerar dashboard automaticamente:

```python
#!/usr/bin/env python3
"""
Script para gerar dashboard de vulnerabilidades a partir de findings SAST.
"""

import json
from pathlib import Path
from datetime import datetime

def generate_dashboard(findings_file='sast-findings.json', validations_dir='validations/'):
    """Gera dashboard de vulnerabilidades."""
    
    with open(findings_file) as f:
        findings = json.load(f)
    
    # Agrupar por prioridade
    by_priority = {
        'P1': [],
        'P2': [],
        'P3': [],
        'P4': [],
        'False Positive': [],
        'Risco Aceito': []
    }
    
    # Processar validações
    for validation_file in Path(validations_dir).glob('*.md'):
        # Ler validação e extrair prioridade
        # (implementar parser de markdown)
        pass
    
    # Gerar HTML/Markdown do dashboard
    # (implementar geração)
    
    print("✅ Dashboard gerado: dashboard/vulnerabilities.html")

if __name__ == '__main__':
    generate_dashboard()
```

### Passo 6: Criar Processo de Triagem Documentado

**6.1. Documentar Processo**

Criar arquivo `docs/sast-triagem-processo.md`:

```markdown
# Processo de Triagem de Findings SAST

## Objetivo

Validar findings SAST, diferenciar True Positives de False Positives, e priorizar vulnerabilidades por risco real.

## Responsáveis

- **QA de Segurança**: Validação inicial e triagem
- **Desenvolvedor**: Análise técnica e correção
- **Tech Lead**: Aprovação de riscos aceitos

## Processo

### 1. Execução de SAST
- SAST executado automaticamente em cada PR
- SAST executado diariamente (scheduled)
- Resultados exportados para `sast-findings.json`

### 2. Triagem Inicial
- QA de Segurança revisa findings Critical/High
- Para cada finding:
  - Ler código ao redor
  - Analisar contexto
  - Preencher template de validação

### 3. Validação
- True Positive → Continuar para priorização
- False Positive → Marcar como resolvido, adicionar exceção
- Dúvida → Discutir com desenvolvedor

### 4. Priorização
- Usar matriz de priorização
- Considerar: Severidade, Exploitability, Impacto, Contexto
- Atribuir prioridade (P1, P2, P3, P4)

### 5. Tracking
- Criar issue para cada True Positive P1/P2/P3
- Atribuir responsável
- Definir prazo
- Acompanhar até resolução

### 6. Validação Pós-Correção
- SAST re-executado
- Validar que finding foi removido
- Testes de segurança adicionados

## Critérios de Priorização

### P1 - IMEDIATO (24h)
- Critical + Em produção + Dados sensíveis
- Critical + Alta exploitability + Impacto crítico

### P2 - Este Sprint (1 semana)
- Critical em desenvolvimento
- High + Em produção + Dados sensíveis
- High + Alta exploitability

### P3 - Próximo Sprint (2 semanas)
- High em desenvolvimento
- Medium + Em produção + Dados sensíveis

### P4 - Backlog
- Medium em desenvolvimento
- Low + Qualquer contexto
- Vulnerabilidades com baixo risco real

## Frequência

- **Triagem**: Semanal (todas as segundas-feiras)
- **Review de Prioridades**: Quinzenal
- **Dashboard**: Atualizado semanalmente
```

**6.2. Criar Checklist de Validação**

Criar arquivo `checklists/validation-checklist.md`:

```markdown
# Checklist de Validação de Findings SAST

## Para Cada Finding Critical/High:

### Contexto
- [ ] Li código ao redor (mínimo 20 linhas antes/depois)
- [ ] Entendi propósito da função/classe
- [ ] Verifiquei se código está ativo (não é código morto)

### Validação Técnica
- [ ] Dados são validados antes de usar?
- [ ] Há sanitização (prepared statements, escaping)?
- [ ] Código usa padrões seguros?
- [ ] Há controles de acesso (autenticação/autorização)?

### Análise de Risco
- [ ] Código está em produção?
- [ ] Requer autenticação para acessar?
- [ ] Dados sensíveis são afetados?
- [ ] Fácil explorar (alta exploitability)?
- [ ] Qual o impacto se explorado?

### Decisão
- [ ] Classificado como True Positive / False Positive / Risco Aceito
- [ ] Justificativa documentada
- [ ] Prioridade atribuída (P1/P2/P3/P4)
- [ ] Issue criada (se True Positive)
- [ ] Responsável atribuído
- [ ] Prazo definido
```

---

## Dicas

1. **Não confie apenas na severidade SAST**: Avalie risco real considerando contexto
2. **False positives são OK**: SAST sempre gera false positives, é normal
3. **Documente decisões**: Justificativas ajudam em auditorias
4. **Priorize por impacto real**: Nem toda Critical é P1 se risco real é baixo
5. **Reavalie periodicamente**: Prioridades podem mudar com contexto
6. **Comunique com time**: Compartilhe decisões e prioridades

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] SAST executado em projeto real
- [ ] Findings Critical/High validados (True Positive vs False Positive)
- [ ] Template de validação preenchido para cada finding
- [ ] Priorização por risco real realizada (P1/P2/P3/P4)
- [ ] Dashboard de vulnerabilidades criado
- [ ] Processo de triagem documentado
- [ ] Issues criadas para True Positives P1/P2/P3

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Exercício 2.1.5: Comparar Ferramentas SAST
- Implementar processo de triagem em projeto real
- Criar dashboard automatizado
- Integrar com ferramentas de tracking (Jira, GitHub Issues)

---

## 💼 Contexto CWI (Exemplo Hipotético)

**Cenário**: Projeto financeiro hipotético (Open Banking)

- **Critérios rigorosos**: Critical sempre P1, bloqueia deploy
- **Validação obrigatória**: Todos os Critical/High devem ser validados antes de merge
- **Compliance**: Findings devem ser corrigidos para atender PCI-DSS
- **Dashboard semanal**: Review todas as segundas-feiras

Aplique o processo de triagem com esses critérios mais rigorosos.

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Template de validação preenchido (exemplo de 3-5 findings)
2. Dashboard de vulnerabilidades priorizadas
3. Processo de triagem documentado
4. Estatísticas de validação (quantos TP vs FP)
5. Lições aprendidas

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Aula 2.1 (SAST), Exercício 2.1.1 (SonarQube) ou conhecimento de ferramentas SAST
