---
exercise_id: lesson-2-3-exercise-1-interpretar-relatorio
title: "Exercício 2.3.1: Interpretar Relatório de Pentest"
lesson_id: lesson-2-3
module: module-2
difficulty: "Básico"
last_updated: 2026-01-24
---

# Exercício 2.3.1: Interpretar Relatório de Pentest

## 📋 Enunciado Completo

Ler relatório profissional de pentest com 23 findings e criar plano de ação prático para QA.

### Tarefa
1. Ler Executive Summary e Technical Details
2. Priorizar findings por contexto de negócio
3. Criar plano de remediação (quem, quando, como)
4. Comunicar para stakeholders (CEO vs Devs)

---

## ✅ Soluções Detalhadas

### Solução Esperada

**Análise matura:**
- Leu relatório completo (não apenas summary)
- Re-priorizou por contexto (não apenas CVSS)
- Criou action items com responsáveis e prazos
- Comunicação adaptada para audiência (técnica vs negócio)

**Exemplo:**
```markdown
## Priorização por Contexto

| Finding | CVSS | Prioridade QA | Justificativa |
|---------|------|---------------|---------------|
| SQLi em /checkout | 9.8 | P0 | Exposição de 5M registros PII → LGPD |
| Auth Bypass /admin | 9.1 | P0 | Acesso total sistema |
| IDOR em /orders | 8.2 | P1 | Vazamento dados pedidos |
| XSS em /search | 6.1 | P2 | Requer engenharia social |

## Comunicação

**Para CEO:**
> "Pentest identificou 2 críticas que podem expor dados de clientes. Priorizando correção urgente (5 dias). Risco está sendo mitigado."

**Para Devs:**
> "Relatório anexado. Prioridade: SQLi no /checkout (usar prepared statements) e Auth Bypass no /admin (validar roles server-side). Tickets criados com POCs."
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Leu relatório completo
- [ ] Priorizou por contexto
- [ ] Criou plano de ação
- [ ] Comunicação clara

### ⭐ Importantes
- [ ] Re-priorizou diferente do CVSS (justificado)
- [ ] Definiu responsáveis e prazos
- [ ] Adaptou comunicação para audiências

### 💡 Diferencial
- [ ] Criou estratégia de validação pós-correção
- [ ] Propôs controles preventivos
- [ ] Documentou lições aprendidas

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Leitura Técnica**: Consegue ler e compreender relatório profissional de pentest?
2. **Priorização Contextual**: Prioriza por risco real ou apenas por CVSS Score?
3. **Coordenação**: Cria plano de ação acionável (quem, quando, como)?
4. **Comunicação Multi-Audiência**: Adapta linguagem para técnicos vs não-técnicos?

### Erros Comuns

**Erro 1: "Priorizou apenas por CVSS"**
- **Situação**: Aluno ordenou vulnerabilidades apenas por CVSS Score
- **Feedback**: "CVSS é referência, não verdade absoluta. CVSS 9.8 em endpoint de teste pode ser P3. CVSS 6.0 em checkout com dados de cartão pode ser P0. Re-priorize considerando: 1) Código em produção? 2) Dados sensíveis expostos? 3) Facilidade de exploração? 4) Impacto no negócio (LGPD, PCI-DSS). Use matriz de risco."

**Erro 2: "Não criou action items"**
- **Situação**: Aluno apenas listou vulnerabilidades sem plano de ação
- **Feedback**: "QA Security não apenas IDENTIFICA problemas, mas COORDENA correção. Transforme relatório em ACTION ITEMS: 1) Quem vai corrigir? (responsável), 2) Quando? (prazo realista), 3) Como QA vai validar? (critérios de aceitação). Isso transforma lista em PLANO EXECUTÁVEL."

**Erro 3: "Comunicação muito técnica para CEO"**
- **Situação**: Usou jargão técnico (CVSS, CWE, exploitation) com stakeholder não-técnico
- **Feedback**: "CEO não precisa saber o que é SQL Injection ou CWE-89. Precisa saber: 1) RISCO (quais dados podem ser expostos?), 2) IMPACTO (multa LGPD? Perda de clientes?), 3) PRAZO (quanto tempo para corrigir?). Reescreva em linguagem de NEGÓCIO. Use analogias se necessário."

**Erro 4: "Plano de remediação irrealista"**
- **Situação**: Aluno propôs corrigir 23 vulnerabilidades em 1 semana
- **Feedback**: "Plano de remediação deve ser REALISTA. Time de dev tem outras prioridades. Escalone: Sprint Atual (P0 apenas), Próxima Sprint (P1), Mês seguinte (P2), Backlog (P3). Comunique trade-offs para stakeholders. Pragmatismo > Perfeição."

**Erro 5: "Não diferenciou Executive Summary de Technical Details"**
- **Situação**: Aluno leu apenas Executive Summary ou apenas Technical Details
- **Feedback**: "Relatório profissional tem DUAS seções por motivo: Executive Summary (para gestão, contexto de negócio) e Technical Details (para devs, como corrigir). QA precisa ler AMBAS: entender contexto de negócio + detalhes técnicos. Releia relatório completo."

**Erro 6: "Criou tickets sem POCs"**
- **Situação**: Aluno criou tickets genéricos ("Corrigir SQLi")
- **Feedback**: "Ticket sem POC (Proof of Concept) = dev vai perder tempo entendendo. Copie POC do relatório de pentest, adicione screenshot, curl command. Dev deve poder REPRODUZIR vulnerabilidade antes de corrigir. Facilite o trabalho do time."

### Dicas para Feedback Construtivo

**Para alunos com domínio completo:**
> "Excelente análise de relatório de pentest! Você demonstrou maturidade profissional ao: 1) Re-priorizar por contexto de negócio (não apenas CVSS), 2) Criar plano de ação acionável com responsáveis e prazos, 3) Adaptar comunicação para diferentes audiências (CEO vs Devs). Essa é a competência de um QA Security pleno/sênior. Próximo desafio: lidere a validação das correções reproduzindo os exploits do pentester (Exercício 2.3.2)."

**Para alunos com dificuldades intermediárias:**
> "Boa leitura do relatório! Você identificou as vulnerabilidades principais. Para elevar o nível: 1) Adicione justificativa técnica para priorização (por que P0 vs P2?), 2) Crie action items específicos (quem, quando, como validar), 3) Escreva comunicação para CEO em linguagem de negócio (sem jargão técnico). Revise seção 'Papéis do QA no Pentest' da Aula 2.3. Sua análise está no caminho certo, agora profundidade."

**Para alunos que travaram:**
> "Vejo que você teve dificuldades com leitura de relatório técnico. Vamos simplificar: 1) Comece pelo Executive Summary (primeira página), 2) Identifique APENAS as 3 vulnerabilidades Critical/High, 3) Para cada uma, pergunte: 'Qual o risco?', 'Está em produção?', 'Como corrigir?'. Após dominar análise básica, expanda para relatório completo. Agende monitoria se precisar de suporte."

### Contexto Pedagógico

**Por que este exercício é fundamental:**

1. **Realidade Profissional**: QAs frequentemente recebem relatórios de pentest de consultores externos e precisam traduzir para action items
2. **Bridge Técnico-Negócio**: Desenvolve habilidade de comunicação multi-audiência (técnicos, gestores, executivos)
3. **Priorização Estratégica**: Ensina a priorizar por impacto no negócio, não apenas por métricas técnicas (CVSS)
4. **Coordenação de Remediação**: QA Security coordena correção, não apenas identifica problemas
5. **Pensamento Crítico**: Relatórios de pentest têm False Positives; QA precisa analisar criticamente

**Conexão com o Curso:**
- **Pré-requisito**: Aula 2.3 (Testes de Penetração Básico), Exercício 2.1.4 (Validar Findings)
- **Aplica conceitos**: CVSS, CWE, OWASP Top 10, Priorização por Risco, Comunicação
- **Prepara para**: Exercício 2.3.2 (Validar Correções de Pentest), Exercício 2.3.4 (Post-Mortem)
- **Integra com**: Todas as aulas do módulo (SAST, DAST, SCA) - pentest consolida todos os findings

**Diferença deste exercício:**
- QA **não executa** pentest (não é pentester)
- QA **interpreta** relatório e **coordena** remediação
- Foco em **gestão de vulnerabilidades**, não em exploitation

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Exemplar (Nível Avançado)

```markdown
## Análise de Relatório de Pentest - App Financeiro (Hipotético)

### 📊 Resumo Executivo (para CEO)

**Pentest identificou 23 vulnerabilidades**, sendo:
- **2 Críticas** (P0): SQL Injection e Authentication Bypass → Podem expor dados de 500K clientes
- **8 High** (P1-P2): XSS, IDOR, CSRF → Risco moderado, correção planejada
- **13 Medium/Low** (P3-P4): Configurações, headers → Backlog

**Ação Imediata**: Corrigindo 2 críticas nos próximos 5 dias úteis. APIs de pagamento estão sendo monitoradas 24/7 até correção. Risco de vazamento de dados está sendo mitigado.

**Impacto LGPD**: Vulnerabilidades críticas podem resultar em multa de até 2% do faturamento se exploradas. Correção prioritária alinhada com compliance.

---

### 🔍 Análise Técnica Detalhada (para Time de Dev)

#### Priorização por Contexto de Negócio

| # | Finding | CVSS | Prioridade | Justificativa Técnica |
|---|---------|------|------------|----------------------|
| 1 | SQL Injection em `/api/transactions/search` | 9.8 | **P0 - BLOCKER** | Endpoint público, permite dump de tabela `transactions` (500K registros PII), exploração trivial (apenas query string), código em PRODUÇÃO, viola PCI-DSS Req 6.5.1 |
| 2 | Authentication Bypass em `/admin/reports` | 9.1 | **P0 - BLOCKER** | Permite acesso total ao painel admin sem autenticação, manipulação de relatórios financeiros, código em PRODUÇÃO |
| 3 | IDOR em `/api/orders/:id` | 8.2 | **P1 - URGENTE** | Vazamento de dados de pedidos (nome, CPF, endereço), endpoint autenticado (mais difícil explorar), código em PRODUÇÃO |
| 4 | XSS Reflected em `/search` | 7.5 | **P2 - IMPORTANTE** | Requer engenharia social (enviar link malicioso), impacto limitado (sessão individual), mitigado por CSP parcial |
| 5 | CSRF em `/api/profile/update` | 6.8 | **P2 - IMPORTANTE** | Permite alteração de perfil, mas requer usuário autenticado + visitar site malicioso, impacto moderado |
| ... | ... | ... | ... | ... |

**Nota**: CVSS foi usado como REFERÊNCIA, mas priorização final considerou:
1. Código em produção vs staging
2. Endpoint público vs autenticado
3. Dados sensíveis expostos (PII, financeiros)
4. Facilidade de exploração
5. Compliance (PCI-DSS, LGPD)

---

#### Plano de Remediação (Action Items)

**🚨 Sprint Atual (Blocker - Prazo: 5 dias úteis)**

**Ticket #1: [P0] Corrigir SQL Injection em /api/transactions/search**
- **Responsável**: @backend-team (João Silva)
- **Prazo**: 3 dias úteis (até sexta-feira)
- **Como corrigir**: Implementar prepared statements com placeholders
- **POC para reproduzir**:
  ```bash
  curl "https://api.exemplo.com/transactions/search?query=1' OR '1'='1' --"
  # Retorna todas as transações (vulnerável)
  ```
- **Código vulnerável** (linha 156):
  ```javascript
  const query = `SELECT * FROM transactions WHERE user_id = '${userId}'`;
  ```
- **Código corrigido**:
  ```javascript
  const query = 'SELECT * FROM transactions WHERE user_id = $1';
  const result = await db.query(query, [userId]);
  ```
- **Validação QA**: 
  - Reproduzir POC após correção (deve falhar)
  - Testar 5 variações de SQLi (UNION, OR, time-based)
  - Code review (verificar uso de prepared statements)

**Ticket #2: [P0] Corrigir Authentication Bypass em /admin/reports**
- **Responsável**: @security-team (Maria Santos)
- **Prazo**: 2 dias úteis
- **Como corrigir**: Validar roles server-side, não apenas client-side
- **Validação QA**: Tentar acessar /admin sem cookie de autenticação (deve retornar 403)

---

**📅 Próxima Sprint (P1 - Prazo: 2 semanas)**

- Ticket #3: IDOR em /api/orders/:id
- Ticket #4: Implementar CSRF tokens em forms
- Ticket #5: Sanitizar inputs em /search (XSS)

**📋 Backlog (P2-P3 - Próximos 2 meses)**

- 8 vulnerabilidades Medium
- 3 vulnerabilidades Low
- Melhorias de hardening (headers de segurança)

---

### 📧 Comunicações

**Email para CEO/CTO:**

> **Assunto**: Ação Imediata - Resultados do Pentest Q1 2026
>
> **Resumo**: Pentest identificou 2 vulnerabilidades críticas que podem expor dados de 500K clientes (SQL Injection e falha de autenticação).
>
> **Ação em andamento**: Time técnico está corrigindo com prioridade máxima (prazo: 5 dias). APIs de pagamento estão sob monitoramento 24/7 até correção completa.
>
> **Risco residual**: Baixo. Nenhuma evidência de exploração até o momento (logs revisados). Compliance LGPD mantido com correção em prazo adequado.
>
> **Próximos passos**: Correção das 8 vulnerabilidades High nas próximas 2 semanas. Relatório completo anexado.

**Mensagem para Time de Dev (Slack):**

> **@backend-team @security-team** 
>
> 🚨 **ATENÇÃO: Vulnerabilidades P0 do Pentest**
>
> Relatório completo: [link]
> Tickets criados: #1234, #1235
>
> **Prioridade imediata**:
> 1. SQLi em /api/transactions/search (João) - Usar prepared statements
> 2. Auth bypass em /admin/reports (Maria) - Validar roles server-side
>
> Inclui POCs para reproduzir. Qualquer dúvida, me chamem. QA vai validar correções antes de aprovar PR.
>
> Code freeze temporário em `/api/transactions/*` até correção.

---

### 📈 Estratégia de Validação Pós-Correção

**Para cada vulnerabilidade corrigida:**
1. ✅ Reproduzir POC original (deve falhar)
2. ✅ Testar 3-5 variações (bypasses)
3. ✅ Code review da correção
4. ✅ Teste de regressão funcional
5. ✅ Atualizar documentação

**Critérios de Aceitação:**
- Exploit original não funciona mais
- Código usa padrão seguro (prepared statements, etc)
- Funcionalidade preservada (sem breaking changes)
- Testes automatizados adicionados

---

### 🔄 Controles Preventivos (Lições Aprendidas)

**Por que essas vulnerabilidades passaram?**
1. SQLi: SonarQube não detectou (regra desabilitada)
2. Auth Bypass: Code review focou em funcionalidade, não segurança

**Action items preventivos:**
- [ ] Re-ativar regras de SQLi no SonarQube
- [ ] Security checklist obrigatório em PRs
- [ ] Treinamento de Secure Coding para devs (2h)
- [ ] Pentest periódico (trimestral)
```

**Por que é exemplar:**
- ✅ Comunicação adaptada (CEO vs Devs)
- ✅ Priorização contextual (não apenas CVSS)
- ✅ Action items específicos (responsável, prazo, como validar)
- ✅ POCs incluídos para facilitar dev
- ✅ Plano de remediação realista (sprints)
- ✅ Estratégia de validação estruturada
- ✅ Controles preventivos (não apenas corretivos)
- ✅ Considerou compliance (LGPD, PCI-DSS)

---

### Exemplo 2: Resposta Adequada (Nível Intermediário)

```markdown
## Análise do Relatório de Pentest

### Resumo
Total: 23 vulnerabilidades (2 Critical, 8 High, 13 Medium/Low)

### Priorização

**Critical (P0):**
1. SQL Injection em /api/transactions
   - Severidade: 9.8
   - Recomendação: Usar prepared statements
   - Responsável: Backend team
   - Prazo: 3 dias

2. Authentication Bypass em /admin
   - Severidade: 9.1
   - Recomendação: Validar permissões server-side
   - Responsável: Security team
   - Prazo: 2 dias

**High (P1):**
3-5. IDOR, XSS, CSRF (próxima sprint)

**Medium/Low (P2-P3):**
Backlog (próximos 2 meses)

### Plano de Ação
- Sprint atual: Corrigir P0 (2 vulnerabilidades)
- Próxima sprint: Corrigir P1 (3 vulnerabilidades High)
- Mês seguinte: P2 e P3

### Comunicação
- CEO: Pentest encontrou 2 críticas, corrigindo em 5 dias
- Devs: Tickets criados, POCs anexados
```

**Por que é adequado:**
- ✅ Priorizou adequadamente
- ✅ Criou plano de ação básico
- ✅ Definiu responsáveis e prazos
- ⚠️ Falta: justificativa técnica da priorização
- ⚠️ Falta: comunicação detalhada (muito genérica)
- ⚠️ Falta: POCs e critérios de validação
- ⚠️ Falta: controles preventivos

**Feedback sugerido:**
> "Boa priorização e plano de ação! Você organizou as vulnerabilidades corretamente. Para elevar o nível: 1) Adicione JUSTIFICATIVA técnica para priorização (por que SQLi é P0? Contexto de negócio), 2) Inclua POCs nos tickets (facilita dev reproduzir), 3) Crie critérios de validação (como QA vai verificar correção?), 4) Expanda comunicação (CEO precisa entender RISCO e IMPACTO). Sua análise está funcional, agora profundidade!"

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
