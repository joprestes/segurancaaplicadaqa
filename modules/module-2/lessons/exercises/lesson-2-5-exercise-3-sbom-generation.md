---
layout: exercise
title: "Exercício 2.5.3: Gerar SBOM (Software Bill of Materials)"
slug: "sbom-generation"
lesson_id: "lesson-2-5"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-5-exercise-3-sbom-generation/
lesson_url: /modules/testes-seguranca-pratica/lessons/dependency-scanning-sca/
---

## Objetivo

Gerar SBOM completo da aplicação para rastreabilidade de dependências e conformidade.

---

## Contexto

O time precisa responder rápido a CVEs críticas. Um SBOM atualizado permite identificar impacto em minutos.

## Pré-requisitos

- Projeto com dependências gerenciadas (ex.: Node, Java, Python)
- Ferramenta de SBOM (CycloneDX ou SPDX)

## Passo a Passo

1. **Gerar SBOM**
   - Use CycloneDX ou SPDX para gerar arquivo em JSON/XML.

2. **Incluir dependências transitivas**
   - Garanta que a ferramenta liste dependências diretas e transitivas.

3. **Documentar versões e licenças**
   - Confirme que versão e licença aparecem no SBOM.

4. **Automatizar no CI/CD**
   - Adicione etapa no pipeline para gerar e publicar o SBOM.

## Validação

- Arquivo SBOM gerado com dependências diretas e transitivas.
- Licenças e versões presentes.
- Pipeline gera SBOM automaticamente.

## Troubleshooting

- **SBOM incompleto**: ajuste flags da ferramenta para incluir transitivas.
- **Licenças ausentes**: verifique metadados dos pacotes.

---

## 📤 Enviar Resposta

1. Arquivo SBOM (JSON/XML)
2. Documentação do processo
3. Workflow CI/CD para geração automática

{% include exercise-submission-form.html %}

---

**Duração**: 60 minutos | **Nível**: Intermediário ⭐
