---
layout: exercise
title: "Exercício 2.1.6: Trade-off Segurança vs Entrega"
slug: "security-vs-delivery"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-1-exercise-6-security-vs-delivery/
lesson_url: /modules/testes-seguranca-pratica/lessons/sast-testes-estaticos/
---

## Objetivo

Este exercício simula um **dilema real** que todo QA de segurança enfrenta: release importante em 3 dias, mas SAST encontrou 15 vulnerabilidades High. Sua missão é analisar riscos, priorizar correções e tomar decisão justificada sob pressão.

Ao completar este exercício, você será capaz de:

- Analisar vulnerabilidades por contexto de negócio (não apenas severidade CVSS)
- Priorizar correções por risco real e exploitability
- Tomar decisões justificadas em situações de trade-off
- Comunicar riscos técnicos para stakeholders não-técnicos
- Propor mitigações temporárias quando patch não é viável

---

## Descrição

**Cenário**: Terça-feira, 15:00. Release da funcionalidade "Checkout com PIX" está agendada para Sexta-feira 18:00 (72 horas). Marketing já divulgou, parceiros foram notificados, CEO prometeu para clientes.

SAST (SonarQube) acabou de finalizar scan e encontrou:
- **15 vulnerabilidades High**
- **47 vulnerabilidades Medium**
- **103 vulnerabilidades Low**

Product Owner te procura: "Podemos liberar essa release? Não podemos atrasar, temos compromissos comerciais."

### Contexto

**Projeto**: E-commerce (B2C)
**Tecnologia**: Node.js + Express + PostgreSQL
**Usuários**: 500k ativos/mês
**Receita**: R$ 2M/mês
**Dados sensíveis**: PII, dados de pagamento (tokenizados via gateway)

**Stakeholders pressionando:**
- CEO: "Prometemos para parceiros, não podemos atrasar"
- Marketing: "Campanha já está rodando, CPA alto se não entregarmos"
- Comercial: "3 clientes grandes aguardando essa feature"
- Dev: "Não dá tempo de corrigir 15 Highs em 3 dias"

### Tarefa Principal

**Você precisa:**
1. Analisar todas as 15 vulnerabilidades High
2. Identificar quais são true positives vs false positives
3. Priorizar por risco REAL (contexto + exploitability)
4. Decidir: Libera release, adia ou release parcial
5. Justificar decisão com dados técnicos e de negócio

---

## Pré-requisitos

- Conhecimento básico de CVSS e priorização de risco
- Familiaridade com SAST e triagem de findings

---

## Passo a Passo

### Passo 1: Análise das Vulnerabilidades High

**Vulnerabilidades Encontradas pelo SAST:**

```markdown
## Vulnerability #1: SQL Injection
- **Severidade**: High (CVSS 8.5)
- **Arquivo**: `src/controllers/checkout.controller.js`
- **Linha**: 127
- **CWE**: CWE-89 (SQL Injection)
- **OWASP**: A03:2021 – Injection

### Código Flagado:
```javascript
// checkout.controller.js:127
const query = `SELECT * FROM orders WHERE user_id = ${req.params.userId}`;
db.query(query, (err, results) => { ... });
```

### Análise Inicial:
- Input vem de `req.params.userId` (rota `/checkout/:userId`)
- Não há sanitização
- Concatenação direta em query SQL

---

## Vulnerability #2: Hardcoded Secret
- **Severidade**: High (CVSS 8.1)
- **Arquivo**: `src/config/pix.config.js`
- **Linha**: 12
- **CWE**: CWE-798 (Hardcoded Credentials)
- **OWASP**: A07:2021 – Identification and Authentication Failures

### Código Flagado:
```javascript
// pix.config.js:12
const PIX_API_KEY = "sk_live_1234567890abcdef";
const PIX_WEBHOOK_SECRET = "whsec_9876543210fedcba";
```

### Análise Inicial:
- API keys hardcoded no código-fonte
- Código está em repositório Git (histórico completo)
- Chaves são produção (sk_live_)

---

## Vulnerability #3: Path Traversal
- **Severidade**: High (CVSS 7.8)
- **Arquivo**: `src/controllers/invoice.controller.js`
- **Linha**: 45
- **CWE**: CWE-22 (Path Traversal)
- **OWASP**: A01:2021 – Broken Access Control

### Código Flagado:
```javascript
// invoice.controller.js:45
app.get('/invoice/:filename', (req, res) => {
  const file = `./invoices/${req.params.filename}`;
  res.sendFile(file);
});
```

### Análise Inicial:
- Input não sanitizado permite ../../../etc/passwd
- Acesso a arquivos fora do diretório invoices/
- Poderia expor .env, código-fonte, etc

---

## Vulnerability #4: Broken Access Control
- **Severidade**: High (CVSS 8.2)
- **Arquivo**: `src/controllers/order.controller.js`
- **Linha**: 78
- **CWE**: CWE-639 (IDOR - Insecure Direct Object Reference)
- **OWASP**: A01:2021 – Broken Access Control

### Código Flagado:
```javascript
// order.controller.js:78
app.get('/api/orders/:orderId', (req, res) => {
  const order = await Order.findById(req.params.orderId);
  res.json(order);
});
```

### Análise Inicial:
- Não verifica se usuário autenticado é dono da order
- Usuário A pode ver orders do usuário B apenas mudando ID
- Order contém PII (nome, endereço, valor)

---

## Vulnerability #5: Server-Side Request Forgery (SSRF)
- **Severidade**: High (CVSS 8.5)
- **Arquivo**: `src/services/webhook.service.js`
- **Linha**: 23
- **CWE**: CWE-918 (SSRF)
- **OWASP**: A10:2021 – Server-Side Request Forgery

### Código Flagado:
```javascript
// webhook.service.js:23
async function validateWebhook(callbackUrl) {
  const response = await axios.get(callbackUrl);
  return response.data;
}
```

### Análise Inicial:
- callbackUrl vem de input do usuário
- Não valida se URL é externa
- Poderia acessar http://localhost/admin ou http://169.254.169.254/metadata (AWS)

---

## Vulnerability #6-15: [Resumo das demais]

**#6**: Insecure Randomness (random() usado para tokens) - High  
**#7**: Missing Rate Limiting (endpoint /api/pix sem throttle) - High  
**#8**: Weak Cryptography (MD5 para hash de senha) - High  
**#9**: XML External Entity (XXE) em parser XML - High  
**#10**: Open Redirect (redirect não validado) - High  
**#11**: Sensitive Data Exposure (logs contêm PII) - High  
**#12**: Unvalidated Redirect (callback URL) - High  
**#13**: Missing CSRF Token (form de checkout) - High  
**#14**: Insufficient Logging (falhas não logadas) - High  
**#15**: Insecure Deserialization (JSON.parse sem validação) - High  
```

### Passo 2: Classificação True Positive vs False Positive

**Tarefa 2.1**: Para cada vulnerabilidade, classifique:

```markdown
| ID | Vulnerabilidade | True/False Positive | Justificativa |
|----|----------------|---------------------|---------------|
| #1 | SQL Injection | [TP/FP?] | [Por que?] |
| #2 | Hardcoded Secret | [TP/FP?] | [Por que?] |
| #3 | Path Traversal | [TP/FP?] | [Por que?] |
| #4 | IDOR | [TP/FP?] | [Por que?] |
| #5 | SSRF | [TP/FP?] | [Por que?] |
| ... | ... | ... | ... |
```

**Critérios de Validação:**
- É vulnerabilidade real ou false positive da ferramenta?
- Código está realmente em produção ou apenas teste?
- Input é controlado por usuário ou hardcoded?
- Existe mitigação não detectada pelo SAST (WAF, sanitização externa)?

### Passo 3: Priorização por Risco REAL

**Tarefa 3.1**: Use esta matriz de priorização:

```
Risco = (Exploitability × 3) + (Impacto × 2) + (Exposição × 1)

Exploitability (quão fácil explorar):
- 3: Trivial (payload público, sem autenticação)
- 2: Médio (requer autenticação ou conhecimento específico)
- 1: Difícil (requer condições específicas, race condition, etc)

Impacto (o que atacante consegue):
- 3: RCE, SQL Injection, acesso total DB
- 2: Acesso a dados sensíveis (PII, pagamentos)
- 1: Information disclosure menor

Exposição (onde está o código):
- 3: Internet-facing, endpoint público
- 2: Requer autenticação
- 1: Admin only ou interno
```

**Tarefa 3.2**: Calcule Risco Score para cada True Positive.

**Exemplo:**
```
Vulnerability #1 (SQL Injection):
- Exploitability: 3 (Trivial, payload público) × 3 = 9
- Impacto: 3 (Acesso total DB) × 2 = 6
- Exposição: 3 (Endpoint público /checkout/:userId) × 1 = 3
= Total: 18 pontos (CRÍTICO)

Vulnerability #14 (Insufficient Logging):
- Exploitability: 1 (Não é exploitável diretamente) × 3 = 3
- Impacto: 1 (Apenas visibilidade) × 2 = 2
- Exposição: 1 (Interno, afeta apenas investigação) × 1 = 1
= Total: 6 pontos (BAIXO)
```

**Tarefa 3.3**: Crie ranking final:

```markdown
| Rank | Vuln ID | Risco Score | Prioridade | Pode Release? |
|------|---------|-------------|------------|---------------|
| 1 | #1 (SQLi) | 18 | P0 | ❌ BLOCKER |
| 2 | #2 (Secret) | 16 | P0 | ❌ BLOCKER |
| 3 | #4 (IDOR) | 15 | P0 | ❌ BLOCKER |
| ... | ... | ... | ... | ... |
```

### Passo 4: Tomada de Decisão

**4.1. Cenário A: Corrigir Tudo (Ideal, mas inviável)**

**Tarefa 4.1**: Calcule esforço de correção:

```markdown
| Vuln ID | Esforço (dev hours) | Risco de Regressão | Testes Necessários |
|---------|---------------------|--------------------|--------------------|
| #1 (SQLi) | 2h | Baixo | Unit + Integration |
| #2 (Secret) | 1h | Médio (requer redeploy) | Manual |
| #4 (IDOR) | 4h | Alto (mudança em lógica) | Full regression |
| ... | ... | ... | ... |
| TOTAL | XXh | | |
```

**Resultado**: Se total > 72h (3 dias × 24h), inviável corrigir tudo.

**4.2. Cenário B: Corrigir Apenas Blockers (P0)**

**Tarefa 4.2**: Identifique vulnerabilidades P0 (Risco Score ≥ 15):

```markdown
## Blockers (MUST FIX antes de release):
1. #1 (SQL Injection) - 18 pontos
2. #2 (Hardcoded Secret) - 16 pontos
3. #4 (IDOR) - 15 pontos

Total Esforço: [X] horas
Timeline: [Viável em 72h? Sim/Não]
```

**4.3. Cenário C: Mitigações Temporárias**

**Tarefa 4.3**: Para vulnerabilidades P0, proponha mitigações temporárias:

```markdown
## Vulnerability #1 (SQL Injection) - Mitigação Temporária

### Opção 1: Sanitização Rápida
```javascript
// Correção rápida (30 min):
const userId = parseInt(req.params.userId, 10);
if (isNaN(userId)) return res.status(400).json({error: 'Invalid user ID'});
const query = `SELECT * FROM orders WHERE user_id = $1`;
db.query(query, [userId], (err, results) => { ... });
```
**Prós**: Resolve SQLi, baixo risco regressão  
**Contras**: Não é ideal (deveria usar ORM), mas funcional

### Opção 2: WAF Rule (Temporário)
```yaml
# Adicionar WAF rule para bloquear payloads SQLi
Block requests matching: (UNION|SELECT|DROP|INSERT|UPDATE|DELETE)
```
**Prós**: Instantâneo, zero downtime  
**Contras**: Bypassável, não resolve root cause

### Decisão: [Escolha uma opção e justifique]
```

**4.4. Decisão Final**

**Tarefa 4.4**: Preencha sua decisão final:

```markdown
# Decisão: [Liberar / Adiar / Release Parcial]

## Justificativa Técnica:
- Total de blockers: [N]
- Total de vulnerabilidades corrigíveis em 72h: [N]
- Vulnerabilidades com mitigação temporária: [N]
- Vulnerabilidades que ficarão para próximo sprint: [N]

## Justificativa de Negócio:
- Impacto de adiar: [R$ X em receita perdida, compromissos comerciais, etc]
- Risco de liberar vulnerável: [Potencial data breach, multas LGPD, reputação]
- Equilíbrio: [Como balancear os dois]

## Plano de Ação:
### Até Sexta-feira 18:00:
- [ ] Corrigir vulnerabilities #1, #2, #4 (P0)
- [ ] Aplicar mitigações temporárias em #5, #7
- [ ] Deixar #6, #8, #9, #10, #11, #12, #13, #14, #15 para Sprint+1

### Pós-Release (Sprint+1):
- [ ] Corrigir todas as vulnerabilidades restantes
- [ ] Remover mitigações temporárias (aplicar correções definitivas)
- [ ] Aumentar cobertura de testes de segurança

## Condições para Aprovar Release:
1. ✅ Blockers (P0) corrigidos E validados por QA
2. ✅ Testes de regressão passando (smoke + critical path)
3. ✅ Monitoramento ativo pós-deploy (logs, SIEM)
4. ✅ Rollback preparado (se exploração detectada)
5. ✅ Security Champion de plantão 24h após release
```

### Passo 5: Comunicação com Stakeholders

**Tarefa 5.1**: Escreva 3 versões da mesma mensagem para audiências diferentes:

**5.1.A. Para CEO (Executivo - não técnico):**
```markdown
Subject: Status Release Checkout PIX - [Decisão]

[Escreva em 3-5 frases]:
- Status atual (release vai acontecer ou não)
- Risco principal (sem jargões técnicos)
- Ações tomadas para mitigar
- O que esperamos do negócio (aprovar atraso, aceitar risco monitorado, etc)
```

**5.1.B. Para Product Owner (Semi-técnico):**
```markdown
Subject: Trade-off Segurança vs Entrega - Checkout PIX

[Escreva em 1 parágrafo]:
- Vulnerabilidades encontradas (quantidade e severidade)
- Quais são blockers e quais podem esperar
- Proposta de release (completa, parcial ou adiada)
- Impacto no backlog do próximo sprint
```

**5.1.C. Para Dev Team (Técnico):**
```markdown
Subject: Security Findings - Action Required

[Escreva detalhadamente]:
- Lista de vulnerabilidades P0 com links para código
- Correções esperadas (sugestões de implementação)
- Deadline para cada correção
- Como validar que correção funcionou
- Process de re-scan pós-correção
```

---

## Desafios Adicionais (Para QAs Plenos)

### Desafio 1: Análise de Custo-Benefício

**Tarefa**: Calcule ROI de adiar vs liberar com mitigações:

```
Cenário A: Adiar Release por 1 semana
- Custo: R$ 500k receita perdida + multa contratual R$ 100k
- Benefício: 100% vulnerabilidades corrigidas definitivamente
- ROI: [Calcule]

Cenário B: Liberar com Mitigações Temporárias
- Custo: Risco de exploração (10% probabilidade × R$ 2M data breach)
- Benefício: R$ 500k receita mantida + cumprimento de SLA
- ROI: [Calcule]

Decisão Justificada: [Qual escolher baseado em ROI?]
```

### Desafio 2: Vulnerabilidade Descoberta Pós-Release

**Cenário**: Você liberou release na Sexta. Segunda-feira, pentester externo encontra SQLi que SAST não detectou (false negative).

**Tarefa**:
- Como responder ao incidente?
- Rollback imediato ou hotfix?
- Como melhorar processo para prevenir false negatives?
- O que dizer para CEO que questionou sua decisão?

### Desafio 3: Pressão Política

**Cenário**: CEO ligou diretamente para você: "Libera essa release AGORA, assumo o risco".

**Tarefa**:
- Como responder sem queimar pontes?
- Documentar formalmente o risco assumido?
- Criar CYA (Cover Your Ass) trail?
- Ethical dilemma: Obedecer CEO ou escalar para CISO/Board?

---

## Dicas

1. **CVSS não é tudo**: Severidade High pode ser baixo risco real no seu contexto.
2. **False positives são comuns**: Sempre valide antes de priorizar.
3. **Mitigações temporárias são válidas**: Desde que haja plano de correção definitiva.
4. **Documente decisões**: CYA é importante quando há pressão política.
5. **Comunique trade-offs claramente**: Não-técnicos precisam entender riscos.
6. **Rollback preparado**: Sempre tenha plano B se vulnerabilidade for explorada.
7. **Monitoramento intenso**: Pós-release de mitigações, monitore 24h.
8. **Não ceda a pressão injustificada**: Se risco é real, defenda sua posição.

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] Classificou as 15 vulnerabilidades (True/False Positive)
- [ ] Calculou Risco Score para cada True Positive
- [ ] Identificou blockers (P0) que impedem release
- [ ] Propôs mitigações temporárias viáveis para P0s
- [ ] Tomou decisão justificada (Liberar/Adiar/Parcial)
- [ ] Escreveu comunicações para 3 audiências diferentes
- [ ] Considerou trade-offs de negócio e técnicos
- [ ] Criou plano de ação executável

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Tomar decisões difíceis sob pressão com dados
- Balancear segurança e velocidade de entrega
- Comunicar riscos técnicos para não-técnicos
- Priorizar vulnerabilidades por contexto real
- Propor mitigações criativas quando patch não é viável

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Tabela de classificação (TP/FP) das 15 vulnerabilidades
2. Ranking de priorização com Risco Score
3. Decisão final justificada (Liberar/Adiar/Parcial)
4. Plano de ação detalhado
5. Comunicações para CEO, PO e Dev Team

{% include exercise-submission-form.html %}

---

## 💼 Contexto CWI (Exemplo Real)

**Cenário Real**: Projeto de Open Banking em 2021 teve situação similar. SAST encontrou 23 Highs faltando 2 dias para go-live regulatório (deadline Bacen).

**Decisão Tomada:**
- Corrigidos 5 blockers P0 em 48h intensas
- Aplicadas mitigações temporárias em 8 vulnerabilidades
- Liberado release com monitoramento 24/7
- 10 vulnerabilidades restantes corrigidas em Sprint+1

**Resultado**: 
- Release cumprido no prazo (compliance mantido)
- Zero explorações detectadas
- Todas as vulnerabilidades corrigidas em 2 semanas

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Aula 2.1 (SAST), experiência com CVSS, conhecimento de priorização de riscos
