---
layout: exercise
title: "Exercício 2.3.1: Interpretar Relatório de Pentest"
slug: "interpretar-relatorio-pentest"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Básico"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-3-exercise-1-interpretar-relatorio/
lesson_url: /modules/testes-seguranca-pratica/lessons/pentest-basico/
---

## Objetivo

Aprender a **interpretar relatórios de pentest** profissionalmente: entender estrutura, priorizar findings por contexto de negócio, e criar plano de ação para o time de desenvolvimento.

Ao completar este exercício, você será capaz de:

- Ler e entender relatórios de pentest (seções técnicas e executivas)
- Diferenciar findings críticos de informativos por contexto
- Criar plano de remediação priorizado
- Comunicar findings para stakeholders técnicos e não-técnicos

---

## Contexto

Você recebeu um relatório de pentest e precisa transformar achados técnicos em plano de ação claro para o time e para o negócio.

## Pré-requisitos

- Conhecimento básico de CVSS e risco
- Noções de priorização e comunicação com stakeholders

---

## Passo a Passo

**Cenário**: Pentester externo entregou relatório de 45 páginas com 23 findings. Você (QA Security) precisa interpretar, priorizar e criar plano de ação para o time.

**Relatório fornecido** (simulado):
```
RELATÓRIO DE PENTEST - APLICAÇÃO E-COMMERCE XYZ
Período: 15-19 Jan 2026
Tipo: Gray Box (acesso a credenciais de teste)
Escopo: app.xyz.com, api.xyz.com

SUMÁRIO EXECUTIVO:
- 23 vulnerabilidades encontradas
- 2 Critical, 8 High, 10 Medium, 3 Low
- Principais riscos: SQL Injection, IDOR, XSS

FINDINGS DETALHADOS:

[CRITICAL-01] SQL Injection em /api/products/search
CVSS: 9.8
CWE: CWE-89
Local: api.xyz.com/api/products/search?q=<payload>
Descrição: Parâmetro 'q' permite SQL Injection. 
Exploit: ' OR 1=1--
Impacto: Dump completo de database, incluindo senhas bcrypt
Recomendação: Usar prepared statements

[CRITICAL-02] Authentication Bypass em Admin Panel
CVSS: 9.1
CWE: CWE-287
Local: app.xyz.com/admin/
Descrição: Cookie manipulation permite bypass de autenticação
Exploit: Modificar cookie 'role' de 'user' para 'admin'
Impacto: Acesso total ao painel administrativo
Recomendação: Validar roles server-side, assinar cookies

[HIGH-01] IDOR em /api/orders/:id
CVSS: 8.2
CWE: CWE-639
Local: api.xyz.com/api/orders/123
Descrição: Qualquer usuário pode ver orders de outros modificando ID
Exploit: GET /api/orders/124 (order de outro usuário)
Impacto: Vazamento de PII (nome, endereço, itens comprados)
Recomendação: Validar ownership antes de retornar order

[... mais 20 findings ...]
```

### Tarefas

1. **Análise do Relatório** (30 min)
   - Leia relatório completo
   - Identifique seções: Executive Summary, Technical Findings, Recommendations
   - Liste todos os 23 findings em planilha

2. **Priorização por Contexto** (45 min)
   - Re-priorize findings considerando contexto e-commerce
   - Use matriz: Severidade CVSS × Exploitability × Exposição × Dados Sensíveis
   - Classifique: P0 (blocker), P1 (high), P2 (medium), P3 (low)

3. **Plano de Remediação** (30 min)
   - Crie plano de ação para top 10 findings
   - Defina responsáveis (Dev, DevOps, QA)
   - Estime esforço (horas) e prazo
   - Identifique dependências

4. **Comunicação para Stakeholders** (15 min)
   - Escreva summary executivo para CEO (5 frases)
   - Escreva briefing técnico para Dev Team (1 página)
   - Prepare apresentação para reunião de alinhamento

---

## Validação

- Findings organizados e priorizados por risco real
- Plano de remediação com responsáveis e prazos
- Comunicação adequada para público técnico e executivo

## Troubleshooting

- **Relatório muito extenso**: comece pelo executive summary e findings críticos
- **Dúvida de prioridade**: use matriz de risco e exposição

---

## 📤 Enviar Resposta

1. Planilha de priorização dos 23 findings
2. Plano de remediação (top 10)
3. Summary executivo para CEO
4. Briefing técnico para Dev Team

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 120 minutos  
**Nível**: Básico  
**Pré-requisitos**: Aula 2.3, conhecimento de CVSS
