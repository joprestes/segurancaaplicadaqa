---
exercise_id: lesson-2-1-exercise-5-security-vs-delivery
title: "Exercício 2.1.5: Conflito Segurança vs Velocidade de Entrega"
lesson_id: lesson-2-1
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.1.5: Conflito Segurança vs Velocidade de Entrega

## 📋 Enunciado Completo

**Cenário Real**: Sprint de 2 semanas está 80% completo (sexta-feira, última dia). SAST encontrou **8 vulnerabilidades** (2 Critical, 3 High, 3 Medium). Product Owner quer lançar feature na sexta-feira (hoje!). Time de dev diz que corrigir TODAS leva 1 semana adicional (atraso de release).

**Seu papel**: QA Security precisa tomar decisão sobre **lançar COM mitigações** ou **bloquear lançamento** até correção completa.

### Tarefa

1. **Analisar cada vulnerabilidade** individualmente (não todas como bloco)
2. **Avaliar risco real** (não apenas CVSS - considerar contexto de negócio)
3. **Propor estratégia** que balanceia segurança com realidade de negócio
4. **Justificar decisão** tecnicamente (para devs) E para stakeholders (PO, CEO)
5. **Criar plano de ação** pós-lançamento (se aplicável)
6. **Documentar processo** para situações futuras similares

---

## ✅ Soluções Detalhadas

### Passo 1: Análise Individual das 8 Vulnerabilidades

```markdown
## Análise de Risco: Lançamento vs Segurança

### Vulnerabilidade #1: SQL Injection em /api/checkout (CRITICAL)

**Detalhes SAST:**
- **Arquivo**: `src/api/CheckoutController.java:156`
- **Severity**: CRITICAL (CVSS 9.8)
- **CWE**: CWE-89
- **Código**: `query = "SELECT * FROM orders WHERE user_id='" + userId + "'"`

**Análise de Contexto:**
- ✅ Endpoint em PRODUÇÃO (deployado há 3 meses)
- ✅ Endpoint PÚBLICO (sem autenticação prévia)
- ✅ Dados sensíveis: Cartões de crédito (últimos 4 dígitos), endereços, CPF
- ✅ Compliance: Viola PCI-DSS Requirement 6.5.1

**Risco Real:**
- **Exploitação**: Trivial (apenas modificar userId na URL)
- **Impacto**: Exposição de 50K+ pedidos com dados de pagamento
- **Probabilidade**: ALTA (atacantes targetam endpoints de pagamento)
- **Custo de incidente**: R$ 5M-20M (multa PCI-DSS + LGPD + reputação)

**Decisão**: **BLOQUEIA LANÇAMENTO** ❌

**Justificativa:**
1. Viola PCI-DSS (não-negociável em sistema de pagamento)
2. Exploração trivial + dados financeiros = risco inaceitável
3. Custo de incidente (R$ 5M-20M) >> custo de atraso (R$ 50K)

**Ação Imediata:**
- Hotfix URGENTE: Implementar prepared statements (ETA: 6-8h)
- Lançar APÓS correção (sábado/domingo, se necessário)

---

### Vulnerabilidade #2: Authentication Bypass em /admin/users (CRITICAL)

**Detalhes SAST:**
- **Arquivo**: `src/api/AdminController.java:45`
- **Severity**: CRITICAL (CVSS 9.1)
- **Código**: Falta validação de role (qualquer usuário autenticado acessa admin)

**Análise de Contexto:**
- ⚠️ Endpoint NÃO está na feature nova (legado)
- ⚠️ Endpoint em produção há 6 meses
- ⚠️ Zero exploração detectada nos últimos 6 meses (logs auditados)
- ✅ Facilmente mitigável com WAF (desabilitar endpoint temporariamente)

**Risco Real:**
- **Exploitação**: Fácil (usuário autenticado comum acessa /admin)
- **Impacto**: Acesso total ao painel admin (deletar users, alterar configs)
- **Probabilidade**: BAIXA (não foi explorado em 6 meses de produção)

**Decisão**: **MITIGAÇÃO TEMPORÁRIA** ⚠️

**Justificativa:**
1. Endpoint não é parte da nova feature (não introduz novo risco)
2. Mitigação viável: Desabilitar /admin/* via WAF por 1 semana
3. Correção definitiva: Sprint seguinte (prioridade P1)

**Ações:**
- **Sexta (hoje)**: Desabilitar /admin/* via Cloudflare WAF (15 minutos)
- **Comunicação**: Avisar admins que painel estará offline por 1 semana
- **Sprint seguinte**: Correção definitiva (role-based access control)

---

### Vulnerabilidade #3: XSS Reflected em /search (HIGH)

**Detalhes SAST:**
- **Arquivo**: `src/components/Search.jsx:89`
- **Severity**: HIGH (CVSS 7.5)
- **Código**: `<div>{searchQuery}</div>` (React sem sanitização)

**Análise de Contexto:**
- ✅ React JSX auto-escapes por padrão
- ✅ CSP header presente (`script-src 'self'`)
- ⚠️ SAST não detectou React auto-escape (FALSE POSITIVE provável)

**Validação Manual:**
```bash
curl "https://app.exemplo.com/search?q=<script>alert(1)</script>"
# Resultado: <div>&lt;script&gt;alert(1)&lt;/script&gt;</div>
# ✅ HTML entities codificados = NÃO VULNERÁVEL
```

**Decisão**: **FALSE POSITIVE - IGNORAR** ✅

**Justificativa:**
1. React JSX protege automaticamente
2. Validação manual confirmou: payload não executa
3. CSP como camada adicional de proteção

**Ação:**
- Marcar como FALSE POSITIVE no SonarQube
- Documentar no README: "React auto-escaping valida vulnerabilidades XSS em JSX"

---

### [Análises de #4-8 seguem mesmo formato...]
```

---

### Passo 2: Matriz de Decisão (Todas as 8 Vulnerabilidades)

```markdown
## Matriz de Decisão - 8 Vulnerabilidades

| # | Vulnerability | CVSS | Contexto | Exploitação | Impacto | **Decisão** | **Prazo** |
|---|---------------|------|----------|-------------|---------|-------------|-----------|
| 1 | SQLi (checkout) | 9.8 | 🔴 PCI-DSS | 🔴 Trivial | 🔴 Dados financeiros | **BLOQUEIA** | Hotfix 6-8h |
| 2 | Auth Bypass (admin) | 9.1 | 🟠 Legado | 🟠 Fácil | 🔴 Admin access | **MITIGA (WAF)** | 15 min + fix Sprint 16 |
| 3 | XSS Reflected (search) | 7.5 | 🟢 React protege | 🟢 Não vulnerável | 🟢 Zero | **FALSE POSITIVE** | N/A |
| 4 | CSRF (profile update) | 6.5 | 🟡 Requer eng. social | 🟡 Moderada | 🟡 Altera perfil | **ACEITA RISCO** | Sprint 16 |
| 5 | Path Traversal (logs) | 8.0 | 🟡 Apenas logs | 🟠 Fácil | 🟡 Config files | **MITIGA (Auth)** | Adicionar auth (2h) |
| 6 | Hardcoded API Key (test) | 7.5 | 🟢 Código de teste | 🟢 Não vai prod | 🟢 Zero | **FALSE POSITIVE** | N/A |
| 7 | Insecure Random (UUID) | 6.0 | 🟡 UUIDs previsíveis | 🟡 Difícil | 🟡 IDOR potencial | **ACEITA RISCO** | Sprint 16 |
| 8 | MD5 Hash (password) | 8.5 | 🟢 Código de teste | 🟢 Não vai prod | 🟢 Zero | **FALSE POSITIVE** | N/A |

**Resumo:**
- **BLOQUEADORES**: 1 (SQLi em checkout)
- **MITIGAÇÕES TEMPORÁRIAS**: 2 (Auth Bypass, Path Traversal)
- **FALSE POSITIVES**: 3 (XSS React, Hardcoded test key, MD5 test)
- **ACEITAR RISCO**: 2 (CSRF, Insecure Random)

**Decisão Final**: **LANÇAR NA SEXTA COM CORREÇÕES MÍNIMAS**
- Corrigir #1 (SQLi) - URGENTE (6-8h)
- Mitigar #2 (WAF) - 15 minutos
- Mitigar #5 (Adicionar auth) - 2h
- Ignorar #3, #6, #8 (FALSE POSITIVES)
- Aceitar risco #4, #7 (corrigir Sprint 16)

**Timeline:**
- **Sexta 10h**: Iniciar hotfix SQLi + Path Traversal auth
- **Sexta 15h**: Desabilitar /admin via WAF
- **Sexta 18h**: Deploy com correções (validado em staging)
- **Sábado-Domingo**: Monitoramento intensivo
- **Segunda-feira**: Retrospectiva + Sprint 16 planning
```

---

### Passo 3: Comunicação para Stakeholders

**Para Product Owner / CEO (Linguagem de Negócio):**

```
Assunto: Decisão de Lançamento - Feature X (Sexta 18h)

Prezados,

Análise de segurança identificou 8 vulnerabilidades. Após avaliação detalhada:

✅ **PODEMOS LANÇAR NA SEXTA** com correções mínimas

**O que vamos fazer:**
1. Corrigir 1 vulnerabilidade crítica (SQLi em checkout) - 6-8h ✅
2. Aplicar 2 mitigações temporárias (WAF + auth) - 2h ✅
3. Ignorar 3 falsos positivos (validados manualmente) ✅
4. Aceitar risco temporário em 2 vulnerabilidades menores (corrigir Sprint 16) ✅

**Risco Residual:** BAIXO
- Vulnerabilidade crítica (PCI-DSS) será corrigida ANTES do deploy
- Mitigações temporárias protegem adequadamente até correção definitiva
- Monitoramento 24/7 no fim de semana

**Custo vs Benefício:**
- Atraso de 1 semana = R$ 200K perda de revenue
- Risco residual com mitigações = R$ 5K (baixíssimo)
- **Decisão recomendada: Lançar na sexta**

**Comprometimento:**
- Sprint 16: Corrigir 4 vulnerabilidades restantes (2 sem, P1)
- Auditoria: Nenhuma vulnerabilidade Critical/High em produção pós-Sprint 16

Ficamos à disposição para esclarecimentos.

Att,
QA Security Team
```

---

**Para Time de Dev (Linguagem Técnica):**

```
Assunto: Hotfix URGENTE - SQLi + Mitigações (Deploy Sexta 18h)

Time,

Análise de segurança: 8 vulnerabilidades detectadas. Decisão: lançar com correções mínimas.

**BLOQUEADOR (P0 - HOJE):**

1. **SQLi em CheckoutController:156** (CVSS 9.8)
   - Corrigir: Prepared statements
   - Responsável: @backend-lead
   - ETA: 6h (terminar 16h)
   - Code review: @security-lead (obrigatório)
   - Teste: Validar que `' OR '1'='1' --` não funciona
   
   ```java
   // ANTES
   query = "SELECT * FROM orders WHERE user_id='" + userId + "'";
   
   // DEPOIS
   query = "SELECT * FROM orders WHERE user_id = ?";
   PreparedStatement pstmt = conn.prepareStatement(query);
   pstmt.setString(1, userId);
   ```

**MITIGAÇÕES TEMPORÁRIAS (P0 - HOJE):**

2. **Auth Bypass em /admin** (CVSS 9.1)
   - Mitigação: Desabilitar /admin/* via Cloudflare WAF
   - Responsável: @devops
   - ETA: 15 min
   - Correção definitiva: Sprint 16 (role-based access control)

3. **Path Traversal em /logs** (CVSS 8.0)
   - Mitigação: Adicionar authentication middleware
   - Responsável: @backend-dev2
   - ETA: 2h
   
**FALSE POSITIVES (IGNORAR):**
- #3 XSS (React auto-escape)
- #6 Hardcoded Key (código de teste)
- #8 MD5 Hash (código de teste)

**ACEITAR RISCO (Sprint 16):**
- #4 CSRF (profile update)
- #7 Insecure Random (UUID)

**Timeline:**
- 10h: Kickoff (War Room Slack)
- 16h: Code review + testes
- 17h: Deploy staging + validação
- 18h: Deploy produção
- 18h-22h: Monitoramento

**Validação Obrigatória:**
- [ ] SQLi payload bloqueado (teste manual)
- [ ] /admin retorna 403 (WAF)
- [ ] /logs requer auth (401 sem token)
- [ ] Funcionalidade normal funciona (smoke tests)

Qualquer bloqueio: ping @security-lead imediatamente.

Att,
Security
```

---

### Passo 4: Plano de Ação Pós-Lançamento

```markdown
## Plano de Ação Pós-Lançamento

### Monitoramento Intensivo (Sexta 18h - Domingo 23h59)

**Responsáveis On-Call:**
- Sexta 18h-22h: @dev-lead + @security-analyst
- Sábado 08h-18h: @sre-team
- Domingo 08h-18h: @sre-team

**Métricas Monitoradas:**
- WAF blocks em /admin (esperado: 0, alerta se > 5)
- SQL errors (esperado: < 10/hora, alerta se > 50)
- 401 em /logs (esperado: < 20/hora, alerta se > 100)
- Response time /checkout (esperado: < 500ms, alerta se > 2s)

**Alertas Configurados:**
- Slack #security-alerts
- PagerDuty (P1 se Critical)
- Dashboard: https://grafana.exemplo.com/security

### Sprint 16 (Segunda-Feira - 2 Semanas)

**Prioridade P1 (Corrigir 4 Vulnerabilidades Restantes):**

| # | Vulnerability | Responsável | ETA | Validação |
|---|---------------|-------------|-----|-----------|
| 2 | Auth Bypass (definitivo) | @backend-team | Semana 1 | Pentest manual |
| 4 | CSRF | @backend-team | Semana 1 | Burp Suite test |
| 5 | Path Traversal (definitivo) | @backend-team | Semana 1 | Whitelist validation |
| 7 | Insecure Random | @backend-team | Semana 2 | UUID v4 validation |

**Entregável Sprint 16:**
- 0 Critical vulnerabilities
- 0 High vulnerabilities
- Relatório de validação (pentest interno)

### Retrospectiva (Segunda-Feira 10h)

**Agenda:**
1. O que funcionou? (decisões acertadas)
2. O que não funcionou? (pontos de melhoria)
3. Como evitar situação similar? (processo preventivo)

**Ações Preventivas:**
1. SAST no CI/CD (bloquear Critical antes de merge) - @qa-lead
2. Security training para devs (Secure Coding 4h) - @security-team
3. Code review checklist (SQL injection, auth, etc) - @eng-lead
4. Revisão trimestral de vulnerabilidades legadas - @security-team
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios)

- [ ] Analisou CADA vulnerabilidade individualmente (não todas como bloco)
- [ ] Avaliou risco real (não apenas CVSS - considerou contexto)
- [ ] Tomou decisão fundamentada (lançar, bloquear, ou lançar com mitigações)
- [ ] Considerou stakeholders (PO, dev, security, CEO)

### ⭐ Importantes (Qualidade da Resposta)

- [ ] Propôs mitigações temporárias quando viáveis (WAF, disable feature, auth adicional)
- [ ] Criou plano de ação pós-lançamento (monitoramento, correção definitiva)
- [ ] Comunicação adaptada (técnico para devs, negócio para PO/CEO)
- [ ] Considerou compliance (LGPD, PCI-DSS, SOC2)

### 💡 Diferencial (Conhecimento Avançado)

- [ ] Propôs monitoramento adicional durante rollout (métricas, alertas)
- [ ] Configurou feature flag para rollback rápido (se mitigação falhar)
- [ ] Documentou lições aprendidas (processo para situações futuras)
- [ ] Criou processo preventivo (SAST no CI, training, code review checklist)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Análise Individual**: Avalia cada vulnerabilidade separadamente (não "todas são críticas")
2. **Risco Contextual**: Considera negócio, não apenas CVSS (PCI-DSS > CVSS genérico)
3. **Pragmatismo**: Balanceia segurança absoluta com realidade de entrega
4. **Mitigações Temporárias**: Sabe usar WAF, feature flags, autenticação adicional como ponte
5. **Comunicação Multi-Nível**: Adapta para técnicos (devs) vs negócio (PO/CEO)

### Erros Comuns

**Erro 1: "Bloqueou lançamento sem avaliar mitigações possíveis"**
- **Causa**: Pensamento binário (lançar OU bloquear), não considerou mitigações temporárias
- **Feedback**: "Decisão correta pode ser **lançar COM mitigações**. AVALIE: 1) Há mitigação temporária viável? (WAF, disable endpoint, auth adicional), 2) Risco residual é aceitável? (baixo com monitoramento), 3) Custo de atraso >> custo de risco mitigado? Exemplo: Auth Bypass em /admin legado → desabilitar via WAF (15min) → lançar → corrigir Sprint seguinte. Segurança absoluta vs pragmatismo inteligente. Refaça considerando mitigações."

**Erro 2: "Liberou lançamento ignorando Critical sem mitigação"**
- **Causa**: Priorizou velocidade de entrega sobre segurança
- **Feedback**: "Vulnerabilidade Critical em produção SEM MITIGAÇÃO = risco inaceitável (violação de compliance, incidente potencial). Se vai lançar, DEVE ter: 1) Mitigação técnica viável (WAF, disable feature, auth), 2) Monitoramento 24/7 (detectar exploração), 3) Plano de rollback (< 15min se explorado). EXEMPLO: SQLi em checkout (PCI-DSS) → NUNCA lançar sem correção (violação não-negociável). Justifique decisão com matriz de risco."

**Erro 3: "Não distinguiu FALSE POSITIVES (tratou todos como reais)"**
- **Causa**: Confiou cegamente no SAST, não validou manualmente
- **Feedback**: "SAST tem 20-40% FALSE POSITIVES. VALIDAÇÃO OBRIGATÓRIA: 1) XSS em React JSX? Teste manual (provavelmente FP - React auto-escape), 2) Hardcoded password em `src/test/`? FP (código de teste, não vai pra prod), 3) MD5 hash? Depende do contexto (senha = vulnerável, UUID de teste = FP). Validar FPs economiza tempo do dev (não corrigir o que não é vulnerável). Refaça validando manualmente pelo menos os Critical/High."

**Erro 4: "Não considerou contexto de negócio (apenas técnico)"**
- **Causa**: Decisão puramente técnica, ignorou impacto no roadmap/revenue
- **Feedback**: "Decisão técnica TEM IMPACTO NO NEGÓCIO. CONSIDERE: 1) Atraso de 1 semana = quanto de perda? (R$ 200K revenue, clientes esperando, competidor lança antes), 2) Risco de exploração vs custo de incidente (probabilidade x impacto), 3) Compliance crítico? (PCI-DSS não-negociável, CSRF pode esperar). EXEMPLO: SQLi em checkout (PCI-DSS) → bloquear (compliance). CSRF em profile → aceitar risco temporário (não é compliance-critical). Decisão balanceada = segurança + negócio."

**Erro 5: "Não criou plano de ação pós-lançamento"**
- **Causa**: Focou apenas em decisão de lançar/bloquear, não pensou no "depois"
- **Feedback**: "Lançar com mitigações EXIGE plano pós-lançamento: 1) Monitoramento 24/7 (WAF blocks, SQL errors, alertas), 2) Responsáveis on-call (quem acorda 3h da manhã se explorado?), 3) Correção definitiva agendada (Sprint 16 - P1), 4) Rollback plan (< 15min se necessário). Sem plano = mitigação não é confiável. Crie timeline: Sexta 18h deploy → Monitoramento fim de semana → Segunda Sprint planning."

**Erro 6: "Comunicação igual para devs e CEO"**
- **Causa**: Usou mesma linguagem técnica para todos os stakeholders
- **Feedback**: "ADAPTE COMUNICAÇÃO: 1) Para CEO: Impacto no negócio (custo de atraso R$ 200K vs risco mitigado R$ 5K), decisão recomendada, comprometimento de correção, 2) Para devs: Código vulnerável (linha exata), correção técnica (prepared statements), ETA (6h), validação (teste com payload), 3) Para PO: Features afetadas (checkout precisa hotfix 6h), timeline (lançar sexta 18h ao invés de 12h). Stakeholder diferente = mensagem diferente. Reescreva seções separadas."

### Dicas para Feedback Construtivo

**Para decisão madura:**
> "Excelente análise de trade-offs! Você demonstrou: 1) Análise individual de cada vulnerabilidade (não tratou como bloco), 2) Pragmatismo inteligente (lançar com mitigações viáveis - WAF, auth, hotfix), 3) Comunicação multi-nível (técnico para devs, negócio para CEO), 4) Plano pós-lançamento (monitoramento, correção Sprint 16). Essa é a habilidade de um Security Lead. Decisão balanceada entre segurança e realidade de negócio. Time pode confiar suas decisões críticas."

**Para decisão simplista:**
> "Sua decisão está no caminho certo. Para melhorar: 1) ANALISE cada vulnerabilidade individualmente (não todas como 'críticas' - algumas podem ser FPs ou ter mitigações), 2) PROPONHA mitigações temporárias quando possível (WAF, disable feature, auth), 3) CRIE plano pós-lançamento (monitoramento, correção definitiva, responsáveis), 4) ADAPTE comunicação (CEO ≠ devs). Decisão binária (sim/não) raramente é melhor resposta. Pragmatismo inteligente é a arte."

**Para dificuldades:**
> "Decisões de trade-off são as mais difíceis. Vamos simplificar: 1) LISTA: Escreva as 8 vulnerabilidades em planilha, 2) CONTEXTO: Para cada uma: a) Código em produção ou novo? b) Dados sensíveis? c) Compliance?, 3) DECISÃO: Para cada uma: Bloquear, Mitigar, Aceitar risco, ou FP?, 4) JUSTIFIQUE: 1 frase (por que essa decisão?). Use matriz do gabarito como template. Após tentar, agende monitoria para refinar. Não há resposta única correta - avaliamos raciocínio."

### Contexto Pedagógico

**Por que este exercício é crítico:**

1. **Realidade Profissional**: QAs enfrentam pressão de entrega vs segurança SEMANALMENTE (não é teórico)
2. **Tomada de Decisão**: Desenvolve capacidade de avaliar trade-offs complexos (múltiplas variáveis)
3. **Comunicação Estratégica**: Treina explicar decisões técnicas para não-técnicos (CEO, board)
4. **Pragmatismo Inteligente**: Segurança absoluta é INVIÁVEL; mitigação inteligente é a arte
5. **Liderança**: Security Lead/Manager toma essas decisões (responsabilidade crítica)

**Conexão com o curso:**
- **Pré-requisito**: Exercício 2.1.4 (Validar Findings), conhecimento de mitigações (WAF, auth)
- **Aplica conceitos**: Risk Assessment, Mitigation Strategies, Stakeholder Communication, Incident Response
- **Prepara para**: Cargo de Security Lead/Manager, decisões estratégicas em crises
- **Integra com**: Exercício 2.3.4 (Post-Mortem - aprendizado após incidentes)

**Habilidades desenvolvidas:**
- Análise de risco contextual (não apenas CVSS)
- Pensamento pragmático (balancear segurança vs negócio)
- Mitigações temporárias (WAF, feature flags, auth)
- Comunicação multi-nível (técnico, negócio, executivo)
- Gestão de crises (decisões sob pressão)
- Planejamento pós-lançamento (monitoramento, correção)
- Liderança técnica (defender decisões com stakeholders)

**Estatísticas da indústria:**
- 68% das releases têm vulnerabilidades conhecidas (Veracode, 2024)
- 42% dos Security Leads relatam pressão de entrega semanal (SANS, 2025)
- Empresas com processos de decisão claros têm 3x menos incidentes (Forrester, 2024)
- 85% dos CTOs valorizam QAs que entendem trade-offs de negócio (StackOverflow, 2025)

**Não há resposta única correta** - monitores devem avaliar:
1. Raciocínio (considerou contexto, mitigações, impacto?)
2. Justificativa (defendeu decisão tecnicamente?)
3. Plano de ação (pensou no pós-lançamento?)
4. Comunicação (adaptou para stakeholders?)

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]