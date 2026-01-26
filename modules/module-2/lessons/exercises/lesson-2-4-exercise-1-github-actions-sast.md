---
layout: exercise
title: "Exercício 2.4.1: Configurar SAST no GitHub Actions"
slug: "github-actions-sast"
lesson_id: "lesson-2-4"
module: "module-2"
difficulty: "Básico"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-4-exercise-1-github-actions-sast/
lesson_url: /modules/testes-seguranca-pratica/lessons/automacao-testes-seguranca/
---

## Objetivo

Configurar análise SAST automatizada usando GitHub Actions com CodeQL para detectar vulnerabilidades em cada push/PR e preparar o repositório para bloquear mudanças com findings críticos.

---

## Descrição

Neste exercício, você vai preparar um pipeline realista de SAST com CodeQL, integrar no fluxo de PR e garantir que resultados críticos possam bloquear a entrega via proteção de branch.

### Contexto
Você é responsável por garantir que uma aplicação em um repositório do GitHub não receba código com vulnerabilidades críticas. A equipe usa PRs e espera feedback automatizado de segurança.

### Pré-requisitos
- Repositório no GitHub com código em uma linguagem suportada pelo CodeQL
- Permissões para editar workflows e regras de proteção de branch
- Branch principal configurada (ex.: `main`)

### Passo a Passo
1. **Criar o workflow do CodeQL**
   - No repositório, crie o arquivo `.github/workflows/sast.yml`.
   - Use o template oficial do CodeQL Actions e configure a(s) linguagem(ns) do projeto.

   Exemplo mínimo:
   ```yaml
   name: "CodeQL"
   on:
     push:
       branches: [ "main" ]
     pull_request:
       branches: [ "main" ]
   jobs:
     analyze:
       name: Analyze
       runs-on: ubuntu-latest
       permissions:
         actions: read
         contents: read
         security-events: write
       steps:
         - name: Checkout repository
           uses: actions/checkout@v4
         - name: Initialize CodeQL
           uses: github/codeql-action/init@v3
           with:
             languages: <substitua_pela_linguagem>
         - name: Autobuild
           uses: github/codeql-action/autobuild@v3
         - name: Perform CodeQL Analysis
           uses: github/codeql-action/analyze@v3
   ```

2. **Executar o pipeline**
   - Faça um commit no repositório para disparar o workflow.
   - Aguarde a execução completar e verifique se o job “CodeQL” finalizou com sucesso.

3. **Habilitar bloqueio via proteção de branch**
   - No GitHub, vá em **Settings → Branches** e adicione uma regra para a branch `main`.
   - Marque a opção de **require status checks** e selecione o check do CodeQL.

4. **Validar o comportamento**
   - Crie um PR simples e verifique se o check do CodeQL aparece como requisito.
   - Confirme que o PR não pode ser mergeado até o check concluir.

### Validação
- O workflow do CodeQL aparece nas Actions e finaliza com sucesso.
- O **Security → Code scanning** mostra resultados da análise.
- A proteção de branch exige o check do CodeQL antes do merge.

### Troubleshooting
- **Job não inicia**: verifique a sintaxe do YAML e permissões do repositório.
- **Análise falha**: confirme a linguagem configurada e se o projeto compila no runner.
- **Check não aparece na proteção**: execute o workflow ao menos uma vez antes de configurar a regra.

---

## 📤 Enviar Resposta

1. Arquivo `.github/workflows/sast.yml`
2. Screenshot de análise executada
3. Print do Security tab com findings
4. Print da regra de proteção exigindo o check do CodeQL

{% include exercise-submission-form.html %}

---

**Duração**: 45 minutos | **Nível**: Básico
