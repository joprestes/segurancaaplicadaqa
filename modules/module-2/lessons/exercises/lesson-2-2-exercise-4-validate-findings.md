---
layout: exercise
title: "Exercício 2.2.4: Validar e Priorizar Findings DAST"
slug: "validate-findings-dast"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Avançado"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-2-exercise-4-validate-findings/
lesson_url: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

## Objetivo

Este exercício tem como objetivo **criar processo de triagem e validação de findings DAST**, diferenciar false positives de true positives, e priorizar vulnerabilidades por risco real.

Ao completar este exercício, você será capaz de:

- Validar findings DAST como True Positive ou False Positive
- Analisar contexto e impacto de vulnerabilidades
- Priorizar vulnerabilidades por risco real (não apenas severidade DAST)
- Criar processo documentado de triagem
- Criar dashboard de vulnerabilidades priorizadas

---

## Descrição

Você vai executar DAST em uma aplicação real (ou aplicação de exemplo), validar cada finding Critical/High, diferenciar false positives de true positives, analisar contexto e impacto, e criar processo documentado de priorização.

### Contexto

Nem tudo que DAST reporta é vulnerabilidade real. É fundamental validar findings, entender contexto, e priorizar por risco real para focar esforço onde realmente importa.

### Tarefa Principal

1. Executar DAST em aplicação real
2. Para cada finding Critical/High:
   - Validar se é True Positive ou False Positive
   - Analisar contexto e impacto
   - Priorizar por risco real
   - Documentar decisão
3. Criar dashboard de vulnerabilidades priorizadas
4. Criar processo de triagem documentado

---

## Requisitos

### Passo 1: Executar DAST em Aplicação Real

**1.1. Escolher Aplicação**

- Aplicação própria (preferido)
- Ou aplicação de exemplo (OWASP Juice Shop, WebGoat, etc.)

**1.2. Executar DAST**

```bash
# Executar OWASP ZAP
docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -J zap-results.json \
  -r zap-results.html

# Ou usar Burp Suite e exportar resultados
```

**1.3. Consolidar Resultados**

Criar arquivo `dast-findings.json` com todos os findings:

```json
{
  "scan_date": "2026-01-14",
  "tool": "owasp-zap",
  "total_findings": 32,
  "by_severity": {
    "high": 3,
    "medium": 12,
    "low": 17
  },
  "findings": [
    {
      "id": "finding-001",
      "tool": "owasp-zap",
      "alert": "SQL Injection",
      "severity": "High",
      "url": "http://app.com/api/users?id=1",
      "parameter": "id",
      "evidence": "Response contains data from multiple users",
      "cwe": "CWE-89",
      "owasp": "A03:2021 – Injection"
    }
  ]
}
```

### Passo 2: Processo de Validação

**2.1. Criar Template de Validação**

Criar arquivo `templates/validation-template-dast.md`:

```markdown
## Finding: [ID] - [Tipo de Vulnerabilidade]

### Metadados
- **Finding ID**: finding-001
- **Severidade DAST**: High 🔴
- **CWE**: CWE-89 (SQL Injection)
- **OWASP Top 10**: A03:2021 – Injection
- **Ferramenta**: OWASP ZAP
- **URL**: `http://app.com/api/users?id=1`
- **Parâmetro**: `id`

### Requisição/Resposta
```http
GET /api/users?id=1' OR '1'='1 HTTP/1.1
Host: app.com

HTTP/1.1 200 OK
[
  {"id": 1, "name": "User 1"},
  {"id": 2, "name": "User 2"}
]
```

### Payload Usado
```
1' OR '1'='1
```

### Análise de Contexto
- [ ] **URL está em produção?**
  - [ ] Sim - Desde quando? ___________
  - [ ] Não - Em staging/QA
  
- [ ] **Endpoint requer autenticação?**
  - [ ] Sim - Tipo? ___________
  - [ ] Não
  
- [ ] **Dados sensíveis afetados?**
  - [ ] Sim - Quais? ___________
  - [ ] Não
  
- [ ] **Endpoint é público?**
  - [ ] Sim
  - [ ] Não - Requer autenticação/autorização
  
- [ ] **Vulnerabilidade é reproduzível?**
  - [ ] Sim - Testado manualmente
  - [ ] Não - Não consegui reproduzir

### Análise de Risco

**Exploitability (Fácil explorar?)**: ALTA / MÉDIA / BAIXA

**Justificativa**: 
[Por que é fácil ou difícil explorar?]

**Impacto (Dados sensíveis afetados?)**: CRÍTICO / ALTO / MÉDIO / BAIXO

**Justificativa**:
[Qual o impacto se explorado?]

**Contexto do Negócio**:
- Aplicação em produção: Sim / Não
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
  - [ ] Adicionar exceção na ferramenta DAST
  
- [ ] **Risco Aceito - Não será corrigido**
  - Justificativa: ___________
  - Mitigações implementadas: ___________
  - Aprovação: ___________

### Ação Corretiva (se True Positive)

**Correção Implementada**:
[Como foi corrigido?]

**Validação**:
- [ ] DAST re-executado - Finding removido ✅
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

1. Reproduzir manualmente o ataque
2. Analisar resposta da aplicação
3. Preencher template de validação
4. Decidir: True Positive, False Positive, ou Risco Aceito
5. Priorizar se True Positive

### Passo 3: Exemplos de Validação

**3.1. Exemplo 1: True Positive - SQL Injection**

```http
GET /api/users?id=1' OR '1'='1 HTTP/1.1

Response: 200 OK
[
  {"id": 1, "name": "User 1"},
  {"id": 2, "name": "User 2"},
  {"id": 3, "name": "User 3"}
]
```

**Análise**:
- Vulnerabilidade reproduzível? ✅ Sim
- Em produção? ✅ Sim
- Requer autenticação? ❌ Não (endpoint público)
- Dados sensíveis? ✅ Sim (dados de usuários)

**Decisão**: ✅ **True Positive - P1 (Corrigir IMEDIATAMENTE)**

**Razão**: SQL Injection em produção, endpoint público, dados sensíveis afetados.

**3.2. Exemplo 2: False Positive - Missing Security Headers**

```http
GET / HTTP/1.1

Response: 200 OK
(Headers não incluem X-Frame-Options)
```

**Análise**:
- Headers realmente ausentes? ✅ Sim
- Mas aplicação usa CSP (Content Security Policy) que é mais moderno
- X-Frame-Options é redundante quando CSP está presente

**Decisão**: ✅ **False Positive - Marcar como resolvido**

**Razão**: CSP já implementado, X-Frame-Options é redundante.

### Passo 4: Priorização por Risco Real

**4.1. Criar Matriz de Priorização**

| Severidade DAST | Exploitability | Impacto | App em Prod | Prioridade Final | Prazo |
|----------------|----------------|---------|-------------|------------------|-------|
| High | Alta | Dados sensíveis | Sim | P1 - IMEDIATO | 24h |
| High | Alta | Dados sensíveis | Não | P2 - Este Sprint | 1 semana |
| Medium | Alta | Dados sensíveis | Sim | P2 - Este Sprint | 1 semana |
| Medium | Média | Dados sensíveis | Não | P3 - Próximo Sprint | 2 semanas |
| Low | Alta | Dados sensíveis | Sim | P3 - Próximo Sprint | 2 semanas |
| Low | Baixa | Dados não sensíveis | Não | P4 - Backlog | Quando possível |

**4.2. Priorizar Findings**

Para cada finding validado como True Positive:

1. Classificar por severidade DAST
2. Avaliar exploitability (fácil explorar?)
3. Avaliar impacto (dados sensíveis?)
4. Considerar contexto (produção, volume de usuários)
5. Atribuir prioridade final (P1, P2, P3, P4)

### Passo 5: Criar Dashboard de Vulnerabilidades

**5.1. Criar Dashboard Simplificado**

Criar arquivo `dashboard/vulnerabilities-dast.md`:

```markdown
# Dashboard de Vulnerabilidades DAST

**Última atualização**: 2026-01-14  
**Total de Findings**: 32  
**True Positives**: 18  
**False Positives**: 14

## Prioridades

### P1 - IMEDIATO (Corrigir em 24h)
| ID | Tipo | URL | Parâmetro | Responsável | Prazo | Status |
|----|------|-----|-----------|-------------|-------|--------|
| F-001 | SQL Injection | /api/users | id | João Silva | 2026-01-16 | Em andamento |

### P2 - Este Sprint (Corrigir em 1 semana)
[...]

## Estatísticas

- **Por Severidade DAST**:
  - High: 3 findings (2 TP, 1 FP)
  - Medium: 12 findings (8 TP, 4 FP)
  - Low: 17 findings (8 TP, 9 FP)

- **Por Status**:
  - Aberto: 10
  - Em andamento: 3
  - Resolvido: 5
```

### Passo 6: Criar Processo de Triagem Documentado

**6.1. Documentar Processo**

Criar arquivo `docs/dast-triagem-processo.md`:

```markdown
# Processo de Triagem de Findings DAST

## Objetivo

Validar findings DAST, diferenciar True Positives de False Positives, e priorizar vulnerabilidades por risco real.

## Responsáveis

- **QA de Segurança**: Validação inicial e triagem
- **Desenvolvedor**: Análise técnica e correção
- **Tech Lead**: Aprovação de riscos aceitos

## Processo

### 1. Execução de DAST
- DAST executado automaticamente em cada deploy
- DAST executado semanalmente (scheduled)
- Resultados exportados para `dast-findings.json`

### 2. Triagem Inicial
- QA de Segurança revisa findings High/Critical
- Para cada finding:
  - Reproduzir manualmente
  - Analisar resposta
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

## Critérios de Priorização

### P1 - IMEDIATO (24h)
- High + Em produção + Dados sensíveis
- High + Alta exploitability + Impacto crítico

### P2 - Este Sprint (1 semana)
- High em staging
- Medium + Em produção + Dados sensíveis

### P3 - Próximo Sprint (2 semanas)
- Medium em staging
- Low + Em produção + Dados sensíveis

### P4 - Backlog
- Low em staging
- Vulnerabilidades com baixo risco real
```

---

## Dicas

1. **Não confie apenas na severidade DAST**: Avalie risco real considerando contexto
2. **False positives são OK**: DAST sempre gera false positives, é normal
3. **Documente decisões**: Justificativas ajudam em auditorias
4. **Priorize por impacto real**: Nem toda High é P1 se risco real é baixo
5. **Reavalie periodicamente**: Prioridades podem mudar com contexto
6. **Comunique com time**: Compartilhe decisões e prioridades

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] DAST executado em aplicação real
- [ ] Findings High/Critical validados (True Positive vs False Positive)
- [ ] Template de validação preenchido para cada finding
- [ ] Priorização por risco real realizada (P1/P2/P3/P4)
- [ ] Dashboard de vulnerabilidades criado
- [ ] Processo de triagem documentado
- [ ] Issues criadas para True Positives P1/P2/P3

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Exercício 2.2.5: Comparar Ferramentas DAST
- Implementar processo de triagem em projeto real
- Criar dashboard automatizado
- Integrar com ferramentas de tracking (Jira, GitHub Issues)

---

## 💼 Contexto CWI (Exemplo Hipotético)

**Cenário**: Projeto financeiro hipotético (Open Banking)

- **Critérios rigorosos**: High sempre P1, bloqueia deploy
- **Validação obrigatória**: Todos os High/Critical devem ser validados antes de merge
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
**Pré-requisitos**: Aula 2.2 (DAST), Exercício 2.2.1 (OWASP ZAP) ou conhecimento de ferramentas DAST
