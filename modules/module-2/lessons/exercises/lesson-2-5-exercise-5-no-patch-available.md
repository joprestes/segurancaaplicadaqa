---
layout: exercise
title: "Exercício 2.5.10: Dependência Vulnerável Sem Patch Disponível"
slug: "no-patch-available"
lesson_id: "lesson-2-5"
module: "module-2"
difficulty: "Avançado ⭐⭐"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-5-exercise-10-no-patch-available/
lesson_url: /modules/testes-seguranca-pratica/lessons/dependency-scanning-sca/
---

## Objetivo

CVE Critical em dependência core, sem patch disponível. Avaliar exploitability, alternativas, mitigações, documentar decisão.

---

## Cenário

```yaml
Dependência: old-crypto-lib 2.3.1
CVE: CVE-2024-XXXXX
CVSS: 9.8 (Critical)
Tipo: Cryptographic weakness
Patch: Não disponível (lib abandonada)
Uso: Core da aplicação (autenticação)
```

**Opções**:
1. Substituir lib (refactor grande, 3 semanas)
2. Fork e patch internamente (risco de manutenção)
3. Mitigação via WAF (temporário)
4. Aceitar risco documentado (compliance?)

**Tarefa**: Decisão justificada com:
- Análise de exploitability
- Matriz de risco
- Plano de ação
- Comunicação para stakeholders

---

## 📤 Enviar Resposta

1. Análise completa de opções
2. Decisão recomendada
3. Plano de implementação

{% include exercise-submission-form.html %}

**Duração**: 90 minutos | **Nível**: Avançado ⭐⭐
