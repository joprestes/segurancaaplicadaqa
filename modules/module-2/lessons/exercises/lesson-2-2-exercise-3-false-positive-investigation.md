---
layout: exercise
title: "Exercício 2.2.8: Investigação de False Positive em DAST"
slug: "false-positive-investigation"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-2-exercise-8-false-positive-investigation/
lesson_url: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

## Objetivo

OWASP ZAP reportou XSS Critical no endpoint `/api/search`. Sua missão: investigar se é vulnerabilidade real ou false positive, reproduzir manualmente, validar exploitability e documentar decisão justificada.

Ao completar este exercício, você será capaz de:

- Investigar findings de DAST critically (não aceitar cegamente)
- Reproduzir vulnerabilidades manualmente para validação
- Distinguir true positives de false positives
- Documentar investigações de segurança profissionalmente
- Tomar decisões sobre markár finding como FP ou escalar

---

## Descrição

**Cenário**: OWASP ZAP full scan executou overnight e reportou:
- **1 Critical**: XSS Reflected no endpoint `/api/search?q=<payload>`
- **Payload**: `<script>alert('XSS')</script>`
- **Response**: Payload aparece na resposta HTML

Dev Team alega: "É false positive, temos sanitização". Você precisa investigar.

### Contexto

**Aplicação**: SaaS de busca empresarial
**Endpoint**: `GET /api/search?q=<termo>`
**Frontend**: React SPA (CSR)
**Backend**: Node.js + Express

### Tarefa Principal

1. Analisar request/response do ZAP
2. Reproduzir manualmente com diferentes payloads
3. Testar bypasses de sanitização
4. Validar exploitability real
5. Decidir: True ou False Positive
6. Documentar investigação completa

---

## Requisitos

### Passo 1: Análise do Finding ZAP

**Report ZAP:**
```
Vulnerability: Cross-Site Scripting (Reflected)
Risk: High
Confidence: Medium
URL: https://app.example.com/api/search?q=<script>alert('XSS')</script>
Method: GET

Evidence:
Response contains unsanitized user input:
<div class="search-result">
  Buscando por: <script>alert('XSS')</script>
</div>

Attack: <script>alert('XSS')</script>
```

**Tarefa 1.1**: O que levanta suspeita de false positive?
- Confidence: Medium (não High)
- Payload básico (deveria ter sido sanitizado)
- React apps geralmente têm XSS protection default

### Passo 2: Reprodução Manual

**Tarefa 2.1**: Reproduza com Burp Suite/curl:

```bash
# Teste 1: Payload básico (mesmo do ZAP)
curl "https://app.example.com/api/search?q=<script>alert('XSS')</script>"

# Analise response:
# - Payload aparece na resposta?
# - Está HTML encoded (&lt;script&gt;)?
# - Está dentro de atributo ou tag?
```

**Tarefa 2.2**: Teste bypasses comuns:

```bash
# Teste 2: Bypass encoding
curl "https://app.example.com/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E"

# Teste 3: Event handlers
curl "https://app.example.com/api/search?q=<img+src=x+onerror=alert(1)>"

# Teste 4: SVG
curl "https://app.example.com/api/search?q=<svg/onload=alert(1)>"

# Teste 5: HTML entities
curl "https://app.example.com/api/search?q=&lt;script&gt;alert(1)&lt;/script&gt;"
```

### Passo 3: Análise de Contexto

**Tarefa 3.1**: Inspecione onde payload aparece no DOM:

```html
<!-- Cenário A: JSON response (SPA) -->
{
  "results": [],
  "query": "<script>alert(1)</script>",
  "total": 0
}
<!-- React renderiza isso como texto (safe por default) -->

<!-- Cenário B: HTML direto (SSR) -->
<div>Buscando por: <script>alert(1)</script></div>
<!-- Vulnerável se não sanitizado -->
```

**Pergunta**: Aplicação é SPA (React) ou SSR? Faz diferença?

### Passo 4: Validação de Exploitability

**Tarefa 4.1**: Tente exploração real no browser:

```javascript
// Via console do browser:
// 1. Acesse https://app.example.com/
// 2. Abra DevTools Console
// 3. Navegue para busca com payload

// Se alert() executar → True Positive
// Se alert() NÃO executar → False Positive (provável)
```

**Tarefa 4.2**: Verifique proteções do frontend:

```javascript
// React sanitiza automaticamente?
// Código React:
<div>Buscando por: {searchQuery}</div>
// React converte <script> para texto (não executa)

// Mas se usar dangerouslySetInnerHTML:
<div dangerouslySetInnerHTML={{__html: searchQuery}} />
// Aí sim é vulnerável!
```

### Passo 5: Decisão e Documentação

**Tarefa 5.1**: Preencha relatório de investigação:

```markdown
# Investigação de Security Finding

## Informações do Finding
- **ID**: ZAP-XSS-001
- **Vulnerabilidade**: XSS Reflected
- **Severidade Reportada**: Critical
- **Endpoint**: GET /api/search?q=<payload>
- **Ferramenta**: OWASP ZAP Full Scan

## Investigação Realizada

### 1. Reprodução Manual
- [ ] Payload básico: [EXECUTOU / NÃO EXECUTOU]
- [ ] Bypass encoding: [EXECUTOU / NÃO EXECUTOU]
- [ ] Event handlers: [EXECUTOU / NÃO EXECUTOU]
- [ ] Payloads avançados: [EXECUTOU / NÃO EXECUTOU]

### 2. Análise de Contexto
**Onde payload aparece**: [JSON response / HTML direto / Outro]
**Framework frontend**: [React / Vue / Angular / SSR]
**Sanitização detectada**: [Sim / Não / Parcial]

### 3. Validação no Browser
**Alert executou**: [Sim / Não]
**Cookies acessíveis**: [Sim / Não / HttpOnly]
**Exploitability real**: [Trivial / Complexo / Impossível]

## Decisão Final

**Classificação**: [TRUE POSITIVE / FALSE POSITIVE]

**Justificativa** (mínimo 3 razões):
1. [Razão 1]
2. [Razão 2]
3. [Razão 3]

**Evidências** (anexar screenshots):
- Request/Response original
- Tentativas de bypass
- Teste no browser
- Análise do código (se disponível)

## Ação Recomendada

**Se True Positive**:
- [ ] P0: Corrigir imediatamente (blocker)
- [ ] P1: Corrigir neste sprint
- [ ] P2: Backlog

**Correção Sugerida**:
```javascript
// [Código da correção]
```

**Se False Positive**:
- [ ] Marcar como FP no ZAP
- [ ] Documentar razão (para auditorias)
- [ ] Ajustar regras do scanner (evitar recorrência)
- [ ] Notificar time (explicar decisão)

## Lições Aprendidas
- [O que aprendi com esta investigação]
- [Como melhorar processo de DAST]
- [Configurações de ZAP a ajustar]
```

---

## Desafios Adicionais

### Desafio 1: Múltiplos Contextos

Teste payload em diferentes contextos:
- Query param vs POST body
- JSON response vs HTML response
- Dentro de `<input value="">` vs `<div>`

### Desafio 2: Blind XSS

E se payload não executar imediatamente, mas for armazenado e executar em painel admin?
Como testar?

### Desafio 3: False Negative

Se você marcou como FP, mas pentester depois explorou com bypass avançado?
Como evitar false negatives na investigação?

---

## Validação

- [ ] Reproduziu payload original do ZAP
- [ ] Testou pelo menos 5 bypasses diferentes
- [ ] Analisou contexto (SPA vs SSR)
- [ ] Tentou exploração real no browser
- [ ] Documentou decisão com justificativas
- [ ] Propôs correção (se TP) ou ajuste de scanner (se FP)

---

## 📤 Enviar Resposta

1. Relatório completo de investigação
2. Screenshots das tentativas de exploração
3. Decisão justificada (TP/FP)
4. Sugestão de correção ou ajuste de scanner

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 45-60 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Aula 2.2 (DAST), Burp Suite básico, conhecimento de XSS
