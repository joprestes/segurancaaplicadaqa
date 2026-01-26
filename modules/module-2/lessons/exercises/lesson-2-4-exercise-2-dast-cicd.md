---
layout: exercise
title: "Exercício 2.4.2: Integrar DAST no Pipeline CI/CD"
slug: "dast-cicd-integration"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-4-exercise-2-dast-cicd/
lesson_url: /modules/testes-seguranca-pratica/lessons/automacao-testes-seguranca/
---

## Objetivo

Integrar OWASP ZAP no pipeline CI/CD para executar testes dinâmicos automaticamente após deploy em staging.

---

## Contexto

Seu time precisa garantir que endpoints expostos em staging sejam validados a cada PR. O objetivo é detectar falhas conhecidas sem impactar o tempo de entrega.

## Pré-requisitos

- Ambiente de staging acessível por URL
- Permissão para editar pipeline CI/CD
- OWASP ZAP disponível via container ou ação oficial

## Passo a Passo

1. **Adicionar etapa de DAST no pipeline**
   - Inclua o OWASP ZAP Baseline após o deploy em staging.
   - Configure a URL alvo e o nome do relatório.

2. **Executar o scan em uma PR**
   - Abra uma PR para disparar o pipeline.
   - Aguarde o job do ZAP finalizar.

3. **Coletar relatório**
   - Salve o relatório HTML/JSON como artefato do pipeline.

## Validação

- O job de DAST executa após o deploy em staging.
- O relatório é gerado e anexado como artefato.
- Findings críticos são visíveis no relatório.

## Troubleshooting

- **Scan falha com timeout**: reduza profundidade do crawl ou use baseline.
- **URL inválida**: confirme se o staging está acessível pelo runner.
- **Sem resultados**: valide se o app tem endpoints públicos acessíveis.

---

## 📤 Enviar Resposta

1. Workflow CI/CD com DAST integrado
2. Relatório HTML do ZAP
3. Documentação do processo

{% include exercise-submission-form.html %}

---

**Duração**: 60 minutos | **Nível**: Intermediário
