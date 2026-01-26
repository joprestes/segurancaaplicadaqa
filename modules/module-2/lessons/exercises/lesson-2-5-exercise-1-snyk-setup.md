---
layout: exercise
title: "Exercício 2.5.1: Configurar Snyk em Projeto"
slug: "snyk-setup"
lesson_id: "lesson-2-5"
module: "module-2"
difficulty: "Básico"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-5-exercise-1-snyk-setup/
lesson_url: /modules/testes-seguranca-pratica/lessons/dependency-scanning-sca/
---

## Objetivo

Configurar o Snyk para monitorar dependências vulneráveis, executar o primeiro scan e habilitar alertas contínuos.

---

## Descrição

Neste exercício, você vai integrar o Snyk ao GitHub, rodar a análise inicial e preparar o fluxo de alertas para novas vulnerabilidades.

### Contexto
Sua equipe quer reduzir risco em dependências de terceiros e precisa de um fluxo simples para identificar e acompanhar vulnerabilidades desde o primeiro dia.

### Pré-requisitos
- Repositório com dependências (ex.: `package.json`, `pom.xml`, `requirements.txt`)
- Conta no Snyk (plano free é suficiente)
- Acesso para integrar apps no GitHub

### Passo a Passo
1. **Integrar Snyk ao GitHub**
   - No Snyk, vá em **Integrations → Source Control → GitHub**.
   - Autorize o acesso e selecione o repositório do exercício.

2. **Executar o scan inicial**
   - No Snyk, importe o repositório.
   - Aguarde o processamento e confirme a criação do projeto no dashboard.

3. **Configurar alertas**
   - No projeto importado, habilite notificações por e-mail.
   - Defina severidade mínima para alertas (ex.: High).

4. **Validar o fluxo**
   - Verifique o relatório de vulnerabilidades no dashboard.
   - Abra um item e confirme detalhes como CVE, severidade e recomendação.

### Validação
- O projeto aparece no dashboard do Snyk.
- O relatório lista vulnerabilidades com severidade e recomendações.
- Alertas estão configurados e ativos.

### Troubleshooting
- **Repositório não aparece**: confirme a autorização do GitHub e permissões do app.
- **Sem findings**: verifique se o projeto tem dependências vulneráveis conhecidas.
- **Alertas não chegam**: valide a configuração de e-mail e preferências do Snyk.

---

## 📤 Enviar Resposta

1. Print do dashboard Snyk
2. Relatório de vulnerabilidades encontradas
3. Configuração de alertas
4. Evidência do repositório integrado (print do projeto no Snyk)

{% include exercise-submission-form.html %}

---

**Duração**: 30 minutos | **Nível**: Básico
