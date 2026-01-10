---
layout: exercise
title: "Exercício 1.4.5: Mitigação e Priorização de Ameaças"
slug: "mitigacao-priorizacao"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Avançado"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-4-exercise-5-mitigacao-priorizacao/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/threat-modeling/
---

## Objetivo

Este exercício tem como objetivo praticar **mitigação e priorização** de ameaças através da **criação de planos de ação** e **alocação de recursos**.

Ao completar este exercício, você será capaz de:

- Criar mitigações efetivas para ameaças
- Priorizar mitigações por risco e esforço
- Criar planos de implementação
- Validar que mitigações são efetivas

---

## Descrição

Você precisa criar mitigações para ameaças identificadas e priorizar sua implementação considerando risco e esforço.

### Contexto

Identificar ameaças é apenas o primeiro passo. Mitigar e priorizar é essencial para segurança efetiva.

---

## Requisitos

### Parte 1: Criar Mitigações

Para cada ameaça crítica/alta identificada, crie mitigações:

**Template de Mitigação**:
```markdown
## Mitigação para: [Nome da Ameaça]

### Ameaça
[Descrição da ameaça]

### Mitigação Proposta
[Descrição da mitigação]

### Tipo de Controle
- [ ] Preventivo (evita ameaça)
- [ ] Detectivo (detecta ameaça)
- [ ] Corretivo (corrige após ameaça)

### Esforço de Implementação
- [ ] Baixo (< 1 dia)
- [ ] Médio (1-3 dias)
- [ ] Alto (> 3 dias)

### Efetividade Esperada
- [ ] Alta (mitiga completamente)
- [ ] Média (mitiga parcialmente)
- [ ] Baixa (reduz risco)

### Validação
[Como validar que mitigação funciona]
```

---

### Parte 2: Priorizar Mitigações

Crie matriz de priorização considerando risco e esforço:

**Tarefas**:
- [ ] Calcular risco de cada ameaça (DREAD)
- [ ] Estimar esforço de cada mitigação
- [ ] Criar matriz risco vs esforço
- [ ] Priorizar implementação

**Matriz de Priorização**:
```
        Esforço Baixo    Esforço Médio   Esforço Alto
Risco    ─────────────    ────────────    ───────────
Alto     [FAZER PRIMEIRO] [FAZER DEPOIS]  [PLANEJAR]
Médio    [FAZER AGORA]   [FAZER DEPOIS]  [CONSIDERAR]
Baixo    [FAZER QUANDO]  [OPCIONAL]      [IGNORAR]
```

---

### Parte 3: Criar Plano de Implementação

Crie plano de implementação das mitigações:

**Tarefas**:
- [ ] Ordenar mitigações por prioridade
- [ ] Estimar tempo de implementação
- [ ] Definir responsáveis
- [ ] Criar cronograma

**Template de Plano**:
```markdown
# Plano de Implementação de Mitigações

## Fase 1: Mitigações Críticas (Semana 1-2)
1. [Mitigação 1] - Responsável: [Nome] - Prazo: [Data]
2. [Mitigação 2] - Responsável: [Nome] - Prazo: [Data]

## Fase 2: Mitigações Altas (Semana 3-4)
1. [Mitigação 3] - Responsável: [Nome] - Prazo: [Data]

## Validação
- [ ] Testes de segurança após cada mitigação
- [ ] Validação de que ameaça foi mitigada
- [ ] Documentação atualizada
```

---

## Contexto CWI

> **Nota**: O exemplo abaixo é um cenário hipotético criado para fins educacionais.

### Exemplo Hipotético: Priorização em Projeto

Em um projeto hipotético, priorizaríamos 30+ mitigações:

**Estratégia**:
- Mitigações críticas de baixo esforço: implementadas imediatamente
- Mitigações críticas de alto esforço: planejadas para sprint seguinte
- Mitigações médias: implementadas quando possível

**Resultado**:
- 80% das ameaças críticas mitigadas em 2 semanas
- Recursos alocados eficientemente
- Produto seguro desde o início

---

## Dicas

1. **Foque no impacto**: Mitigações de alto impacto primeiro
2. **Considere esforço**: Balance risco e esforço
3. **Valide sempre**: Teste que mitigação funciona
4. **Documente**: Facilita acompanhamento
5. **Revise**: Prioridades podem mudar

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Aplicar threat modeling em projetos reais
- Criar planos de mitigação
- Priorizar segurança efetivamente
- Aula 1.5: Compliance e Regulamentações

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Exercício 1.4.4 (Threat Model Completo)
