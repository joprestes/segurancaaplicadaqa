---
layout: exercise
title: "Exercício 2.3.3: Preparar Escopo de Pentest"
slug: "preparar-escopo-pentest"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-3-exercise-3-preparar-escopo/
lesson_url: /modules/testes-seguranca-pratica/lessons/pentest-basico/
---

## Objetivo

Preparar documentação completa de escopo para contratar pentester, economizando 50% do tempo de descoberta e focando esforços em áreas críticas.

---

## Descrição

**Cenário**: Empresa vai contratar pentest externo pela primeira vez. Você (QA Security) precisa preparar documentação de escopo detalhada para maximizar ROI.

### Tarefas

Crie documento de escopo com:

1. **Aplicações em Escopo**
   - URLs, ambientes, tecnologias
   - APIs (endpoints críticos)
   - Mobile apps (se houver)

2. **Credenciais de Teste**
   - User comum, Admin, diferentes roles
   - API keys de teste

3. **Áreas Críticas de Negócio**
   - Checkout/Pagamento
   - Autenticação
   - Admin Panel
   - APIs internas

4. **Out of Scope** (o que NÃO testar)
   - Produção (usar staging)
   - DoS/DDoS
   - Social Engineering
   - Physical Security

5. **Informações Técnicas**
   - Stack (React, Node.js, PostgreSQL)
   - Arquitetura (monolith vs microservices)
   - Integrações externas (gateways de pagamento)

6. **Objetivos e Expectativas**
   - O que esperamos descobrir
   - Formato de entrega (relatório + apresentação)
   - Prazo

---

## 📤 Enviar Resposta

1. Documento completo de escopo de pentest
2. Planilha de credenciais de teste
3. Diagrama de arquitetura (simplificado)

{% include exercise-submission-form.html %}

---

**Duração**: 60 minutos | **Nível**: Intermediário
