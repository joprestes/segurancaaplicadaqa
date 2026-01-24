---
exercise_id: lesson-2-3-exercise-4-incident-postmortem
title: "Exercício 2.3.4: Post-Mortem de Incidente de Segurança"
lesson_id: lesson-2-3
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.3.4: Post-Mortem de Incidente de Segurança

## 📋 Enunciado Completo

**Cenário**: Hacker explorou SQL Injection em produção, acessou 50K registros de clientes. Criar post-mortem blameless.

### Tarefa
1. Timeline do incidente (descoberta, resposta, resolução)
2. Root cause analysis (como passou despercebido?)
3. Action items (preventivos e detectivos)
4. Lições aprendidas
5. Apresentação para liderança

---

## ✅ Soluções Detalhadas

### Solução Esperada

**Post-mortem blameless profissional:**

```markdown
## Post-Mortem: SQL Injection Incident - Janeiro 2026

### 📊 Resumo Executivo

**Incidente**: SQL Injection explorado em produção, acesso não autorizado a 50.000 registros de clientes.
**Impacto**: Exposição de dados PII (nome, email, CPF, telefone) - SEM exposição de senhas ou dados financeiros.
**Duração**: 57 minutos (alerta → patch deployado).
**Status**: Resolvido. Clientes notificados, ANPD notificada (LGPD Art. 48).

---

### ⏱️ Timeline Detalhado

**14:23 (T+0min)**: Alerta automático (Cloudflare WAF detectou padrão suspeito)
- Trigger: 15 requisições com payload `' OR '1'='1' --` em 2 minutos
- Source IP: 203.0.113.45 (VPN, localização: EUA)

**14:30 (T+7min)**: Security team confirmou exploit ativo
- Revisão de logs: 127 requisições maliciosas nas últimas 2 horas
- Primeira exploração: 12:15 (2h8min antes da detecção)

**14:35 (T+12min)**: Aplicação colocada em modo manutenção
- Deploy de página estática: "Manutenção programada"
- Traffic redirecionado para CDN

**14:45 (T+22min)**: Análise de impacto iniciada
- Query logs do banco: 50.412 registros acessados
- Tabelas afetadas: `customers` (PII), `addresses` (endereços)
- Tabelas NÃO afetadas: `payments`, `passwords` (isoladas)

**15:05 (T+42min)**: Patch deployado em staging
- Correção: Prepared statements implementados
- Code review: @security-lead aprovado
- Testes: 5 variações de SQLi bloqueadas ✅

**15:20 (T+57min)**: Patch deployado em produção
- Aplicação restaurada
- WAF rules atualizadas (bloqueio adicional)
- Monitoramento intensificado

**16:00 (T+97min)**: Auditoria completa
- Logs revisados: 50.412 registros confirmados
- Análise forense: Atacante tentou exfiltrar via SQL UNION
- Evidências preservadas para investigação

**18:00 (T+5h)**: Comunicação externa
- Email para 50.412 clientes afetados (transparência)
- Notificação ANPD (LGPD Art. 48 - dentro de 72h)
- FAQ publicada: www.exemplo.com/security-incident

---

### 🔍 Root Cause Analysis (5 Whys)

**Problema**: SQLi em endpoint `/api/search/customers`

**Why 1**: Por que SQLi foi possível?
→ Código usava string concatenation ao invés de prepared statements

**Why 2**: Por que código vulnerável foi deployado?
→ SonarQube não detectou (regra de SQLi estava desabilitada)

**Why 3**: Por que regra estava desabilitada?
→ Gerava "muitos false positives" (decisão de 6 meses atrás)

**Why 4**: Por que não revisaram false positives?
→ Falta de processo de revisão trimestral de regras SAST

**Why 5**: Por que faltava processo?
→ Security team sub-dimensionado (1 pessoa para 50 devs)

**Root Cause**: Processo de SAST inadequado + falta de revisão periódica de configurações de segurança.

---

### 📋 Action Items

#### 🛡️ Preventivos (Não deixar acontecer de novo)

1. **[P0] Re-ativar regras SQLi no SonarQube**
   - Responsável: @security-team
   - Prazo: Imediato (já feito)
   - Status: ✅ Completo

2. **[P0] Security checklist obrigatório em code review**
   - Responsável: @engineering-lead
   - Prazo: Esta semana
   - Template: Validar inputs, prepared statements, autenticação, etc.

3. **[P1] Testes de segurança automatizados**
   - Responsável: @qa-team
   - Prazo: 2 semanas
   - Tool: Semgrep no CI/CD (bloqueia PR se SQLi detectado)

4. **[P1] Treinamento Secure Coding**
   - Responsável: @security-team
   - Prazo: Próximo mês
   - Duração: 4h (presencial)
   - Público: Todos os devs

5. **[P2] Revisão trimestral de regras SAST**
   - Responsável: @security-team
   - Prazo: Processo permanente (Q1, Q2, Q3, Q4)
   - Objetivo: Avaliar FPs, ajustar regras, manter eficácia

6. **[P2] Contratar Security Engineer**
   - Responsável: @hr-team
   - Prazo: 3 meses
   - Justificativa: Ratio atual (1:50) é insustentável

#### 🔍 Detectivos (Detectar mais rápido)

1. **[P0] WAF rules para SQL injection patterns**
   - Responsável: @infra-team
   - Prazo: Imediato (já feito)
   - Status: ✅ Completo (Cloudflare WAF)

2. **[P1] Alertas em tempo real**
   - Responsável: @sre-team
   - Prazo: Esta semana
   - Tool: Slack webhook para padrões suspeitos

3. **[P1] Monitoramento de anomalias**
   - Responsável: @sre-team
   - Prazo: 2 semanas
   - Tool: DataDog APM (detectar queries anômalas)

4. **[P2] Rate limiting agressivo**
   - Responsável: @backend-team
   - Prazo: 1 mês
   - Config: 10 req/s por IP em endpoints de busca

---

### 📚 Lições Aprendidas

#### ✅ O que funcionou

1. **Defesa em camadas salvou o dia**
   - WAF detectou exploit mesmo com código vulnerável
   - Tabelas críticas (`payments`, `passwords`) isoladas → impacto reduzido

2. **Resposta rápida (57min)**
   - Runbook de incident response funcionou
   - Comunicação clara (Slack war room)
   - Time empoderado para decisões rápidas (modo manutenção)

3. **Transparência com clientes**
   - Email honesto em 5h (não escondemos)
   - FAQ publicada
   - Zero reclamações públicas (Twitter, Reclame Aqui)

#### ⚠️ O que NÃO funcionou

1. **Detecção tardia (2h8min)**
   - Exploit começou 12:15, detectado 14:23
   - WAF alertou, mas não bloqueou automaticamente
   - → Action item: WAF em modo bloqueio (não apenas alerta)

2. **Regra SAST desabilitada**
   - SonarQube teria detectado na semana passada (PR #1234)
   - Decisão de desabilitar foi tomada sem revisão de segurança
   - → Action item: Mudanças em config de segurança exigem aprovação

3. **Code review não pegou**
   - Reviewer focou em funcionalidade, não em segurança
   - Security checklist não existia
   - → Action item: Checklist obrigatório + treinamento

#### 🎯 Principais Takeaways

1. **Automação > Humanos**: Ferramentas (SAST, WAF) detectam 24/7, humanos não
2. **Defense in Depth**: WAF salvou (mesmo com código vulnerável)
3. **Velocidade importa**: 57min do alerta ao patch é excelente
4. **Transparência constrói confiança**: Clientes apreciaram honestidade
5. **Processo > Pessoas**: Não culpar dev, mas processo que falhou

---

### 📊 Métricas

| Métrica | Valor | Meta |
|---------|-------|------|
| **Tempo de detecção** | 2h 8min | < 30min |
| **Tempo de resposta** | 57min | < 2h |
| **Registros afetados** | 50.412 | 0 (ideal) |
| **Downtime** | 45min | < 1h |
| **Custo estimado** | R$ 180K | N/A |

**Custo breakdown**:
- Horas-engenharia (20 pessoas x 4h): R$ 80K
- Notificação clientes (email, suporte): R$ 50K
- Consultoria jurídica (LGPD): R$ 30K
- Pentest emergencial (validação): R$ 20K

---

### 🎤 Comunicação

#### Para Board/CEO

> **Incidente de Segurança - Resolução e Ações**
>
> Sexta-feira, 14:30, detectamos exploração de vulnerabilidade em produção. Time de segurança respondeu imediatamente:
>
> - **Impacto**: 50K registros PII expostos (sem senhas/financeiro)
> - **Resolução**: 57 minutos (alerta → patch)
> - **Comunicação**: Clientes notificados, ANPD notificada (LGPD)
> - **Custo**: ~R$ 180K (eng + legal + notificação)
>
> **Ações em andamento**:
> 1. Segurança reforçada (WAF, testes automatizados)
> 2. Treinamento de time (Secure Coding)
> 3. Contratação Security Engineer (aprovação solicitada)
>
> **Transparência**: Publicamos FAQ, zero reclamações públicas. Evento demonstrou maturidade de resposta do time.

#### Para Time Técnico

> **Post-Mortem: SQLi Incident 24/Jan**
>
> Relatório completo: [link]
>
> **TL;DR**: SQLi em `/api/search/customers`, 50K registros acessados, resolvido em 57min.
>
> **Root cause**: Regra SAST desabilitada + falta de security checklist.
>
> **O que muda pra vocês**:
> 1. ✅ Security checklist obrigatório em PR (template no Confluence)
> 2. ✅ Semgrep no CI/CD (bloqueia SQLi, XSS, etc)
> 3. ✅ Treinamento Secure Coding (4h) - obrigatório
>
> **Importante**: Post-mortem é BLAMELESS. Foco em processo, não pessoas. Todos cometemos erros; o que importa é aprender.

---

### 🔄 Follow-up

**Revisão em 30 dias**:
- [ ] Action items P0 e P1 completados?
- [ ] Métricas melhoraram (tempo de detecção < 30min)?
- [ ] Treinamento realizado (100% participação)?
- [ ] Processo de revisão trimestral estabelecido?

**Auditoria trimestral**:
- [ ] Nenhum incidente similar nos últimos 90 dias?
- [ ] Testes de penetração passaram?
- [ ] Regras SAST revisadas?

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Timeline preciso do incidente
- [ ] Root cause identificado (5 Whys)
- [ ] Action items definidos (preventivo + detectivo)
- [ ] Blameless (foca em processo, não pessoas)

### ⭐ Importantes
- [ ] Análise profunda (não superficial)
- [ ] Comunicação para múltiplas audiências
- [ ] Métricas quantificadas
- [ ] Follow-up planejado

### 💡 Diferencial
- [ ] Custo estimado do incidente
- [ ] Lições aprendidas documentadas
- [ ] Apresentação executiva preparada
- [ ] Processo de revisão estabelecido

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Blameless Culture**: Post-mortem culpa PROCESSO, não PESSOAS
2. **Root Cause Analysis**: Identifica causa raiz (5 Whys), não apenas sintoma
3. **Ações Preventivas vs Detectivas**: Entende diferença e importância de ambas
4. **Comunicação Multi-Nível**: Adapta para Board vs Time Técnico

### Erros Comuns

**Erro 1: "Culpou desenvolvedor que escreveu código"**
- **Problema**: Post-mortem não é blameless, focou em pessoa
- **Feedback**: "Post-mortem é BLAMELESS. Foque em PROCESSO que falhou, não pessoa que errou. Perguntas certas: 'Por que nosso processo permitiu isso?' não 'Quem errou?'. Reescreva sem mencionar nomes de devs. Culpar pessoas destrói confiança; melhorar processos previne futuros incidentes."

**Erro 2: "Root cause superficial"**
- **Situação**: "Root cause: Dev esqueceu prepared statements"
- **Feedback**: "Isso é sintoma, não causa raiz. Use técnica 5 Whys: Por que dev esqueceu? → Não sabia. Por que não sabia? → Falta treinamento. Por que falta? → Sem orçamento. Continue até chegar na causa SISTÊMICA. Root cause verdadeira está no processo/organização."

**Erro 3: "Action items vagos"**
- **Situação**: "Melhorar segurança", "Treinar time"
- **Feedback**: "Action item específico: 'Implementar Semgrep no CI/CD (responsável: @qa-team, prazo: 15/Fev)' > 'Melhorar segurança'. Acionável significa: O QUÊ fazer, QUEM faz, QUANDO entrega. Reescreva action items com especificidade."

**Erro 4: "Apenas action items preventivos"**
- **Situação**: Aluno listou apenas correções, sem detecção
- **Feedback**: "Preventivo evita incidente; Detectivo reduz impacto QUANDO acontecer. Você precisa de AMBOS: Preventivo (SAST, code review) E Detectivo (WAF, monitoring). Adicione controles detectivos que alertam rapidamente se prevenção falhar."

**Erro 5: "Não quantificou impacto"**
- **Situação**: "Muitos clientes afetados", "Ficamos offline"
- **Feedback**: "Quantifique: 'Muitos' = quantos? '50.412 registros'. 'Offline' = quanto tempo? '45 minutos'. Stakeholders precisam de NÚMEROS para tomar decisões (orçamento, priorização). Adicione métricas."

**Erro 6: "Comunicação igual para CEO e devs"**
- **Situação**: Usou mesma linguagem técnica para todos
- **Feedback**: "CEO precisa entender IMPACTO NO NEGÓCIO (custo, risco legal, reputação). Devs precisam entender O QUE FAZER DIFERENTE (checklist, ferramentas). Adapte comunicação: CEO = negócio, Devs = técnico. Reescreva seções separadas."

### Dicas para Feedback Construtivo

**Para post-mortem maduro:**
> "Post-mortem exemplar! Você demonstrou: 1) Blameless culture (focou em processo), 2) Root cause profunda (5 Whys), 3) Action items acionáveis (preventivo + detectivo), 4) Comunicação adaptada (CEO vs devs). Esse é o padrão de post-mortems de empresas como Google, Netflix. Seu time pode aprender muito com esse documento. Próximo nível: apresente para liderança e facilite discussão de lições aprendidas."

**Para post-mortem básico:**
> "Bom post-mortem! Você documentou timeline e action items. Para elevar: 1) Aprofunde root cause (use 5 Whys até causa sistêmica), 2) Adicione controles detectivos (não apenas preventivos), 3) Quantifique impacto (números, não 'muitos'), 4) Prepare comunicação diferenciada para stakeholders. Sua estrutura está correta, agora profundidade e contexto."

**Para dificuldades:**
> "Post-mortem é desafiador, especialmente ser blameless. Vamos simplificar: 1) Timeline: O QUE aconteceu, QUANDO (hora exata), 2) Root cause: Por que aconteceu? (5 Whys), 3) Action items: O que vamos FAZER DIFERENTE? Foque nesses 3 pilares. Revise post-mortems de referência: https://github.com/danluu/post-mortems. Pratique com incidente fictício antes."

### Contexto Pedagógico

**Por que este exercício é crítico:**

1. **Realidade Profissional**: Incidentes acontecem; post-mortem transforma crise em aprendizado
2. **Blameless Culture**: Ensina a NÃO culpar pessoas (fundamental em DevOps/SRE)
3. **Root Cause Analysis**: Desenvolve pensamento sistêmico (problema → causa → ação)
4. **Melhoria Contínua**: Post-mortem bem feito previne futuros incidentes
5. **Comunicação em Crise**: Treina clareza sob pressão (stakeholders nervosos)

**Conexão com o Curso:**
- **Pré-requisito**: Exercício 2.3.1 (Interpretar Relatório), Aula 2.4 (Automação)
- **Aplica conceitos**: Incident Response, Root Cause Analysis, SAST/DAST, Monitoring
- **Prepara para**: Carreira em Security Engineering, SRE, ou liderança técnica
- **Diferencial**: Habilidade rara - poucos QAs sabem fazer post-mortem profissional

**Referências inspiradoras:**
- Google SRE Book (Capítulo 15: Postmortem Culture)
- Etsy's Debriefing Facilitation Guide
- PagerDuty Incident Response Documentation

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
