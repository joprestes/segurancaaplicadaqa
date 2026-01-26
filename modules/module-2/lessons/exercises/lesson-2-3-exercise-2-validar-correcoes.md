---
layout: exercise
title: "Exercício 2.3.2: Validar Correções de Pentest"
slug: "validar-correcoes-pentest"
lesson_id: "lesson-2-3"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-3-exercise-2-validar-correcoes/
lesson_url: /modules/testes-seguranca-pratica/lessons/pentest-basico/
---

## Objetivo

Validar que correções de vulnerabilidades de pentest foram implementadas corretamente, reproduzindo exploits do relatório e confirmando que não funcionam mais.

---

## Contexto

**Cenário**: Dev Team corrigiu 5 vulnerabilidades Critical/High do pentest. Você precisa validar ANTES de chamar pentester para re-test (economiza $2k de re-test).

**Vulnerabilidades Corrigidas:**
1. SQL Injection em `/api/products/search`
2. IDOR em `/api/orders/:id`
3. XSS Reflected em `/search`
4. Authentication Bypass no Admin Panel
5. Missing Rate Limiting em `/api/login`

## Pré-requisitos

- Acesso ao ambiente de teste
- Relatório de pentest com exploits originais
- Ferramentas de teste (curl ou Burp Suite)

---

## Passo a Passo

### Tarefas

Para cada vulnerabilidade:

1. **Reproduzir Exploit Original** (do relatório de pentest)
2. **Validar Correção** (exploit não funciona mais)
3. **Testar Bypasses** (tentar contornar a correção)
4. **Criar Teste de Regressão** (para CI/CD)
5. **Documentar Resultado** (Pass/Fail com evidências)

---

## Validação

- Exploits originais não funcionam mais
- Bypasses testados e documentados
- Testes de regressão adicionados

## Troubleshooting

- **Exploit ainda funciona**: reporte ao time e reabra a correção
- **Ambiente instável**: valide em staging antes de concluir

---

## 📤 Enviar Resposta

1. Relatório de validação (5 vulnerabilidades)
2. Screenshots de tentativas de exploit
3. Testes de regressão automatizados
4. Recomendação: Aprovar re-test ou corrigir novamente

{% include exercise-submission-form.html %}

---

**Duração**: 90 minutos | **Nível**: Intermediário
