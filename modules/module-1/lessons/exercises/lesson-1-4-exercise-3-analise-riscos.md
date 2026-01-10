---
layout: exercise
title: "Exercício 1.4.3: Análise de Riscos com DREAD"
slug: "analise-riscos"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Intermediário"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-4-exercise-3-analise-riscos/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/threat-modeling/
---

## Objetivo

Este exercício tem como objetivo praticar **análise de riscos** usando **DREAD** para priorizar ameaças identificadas.

Ao completar este exercício, você será capaz de:

- Aplicar DREAD para calcular riscos
- Priorizar ameaças por risco calculado
- Justificar priorização de ameaças
- Criar matriz de riscos

---

## Descrição

Você precisa analisar riscos de ameaças identificadas usando DREAD e criar uma matriz de priorização.

### Contexto

Após identificar ameaças, é essencial priorizá-las. DREAD fornece uma metodologia quantitativa para isso.

---

## Requisitos

### Parte 1: Calcular Riscos com DREAD

Para cada ameaça abaixo, calcule risco usando DREAD:

#### Ameaça 1: SQL Injection em Busca

**Descrição**: Endpoint de busca vulnerável a SQL Injection.

**Tarefas**:
- [ ] Calcular Damage (0-10)
- [ ] Calcular Reproducibility (0-10)
- [ ] Calcular Exploitability (0-10)
- [ ] Calcular Affected Users (0-10)
- [ ] Calcular Discoverability (0-10)
- [ ] Calcular Risco Total
- [ ] Classificar risco (Crítico/Alto/Médio/Baixo)

**Template**:
```markdown
## Ameaça: SQL Injection em Busca

### DREAD Analysis

**D - Damage**: [0-10]
Justificativa: [Por que essa pontuação]

**R - Reproducibility**: [0-10]
Justificativa: [Por que essa pontuação]

**E - Exploitability**: [0-10]
Justificativa: [Por que essa pontuação]

**A - Affected Users**: [0-10]
Justificativa: [Por que essa pontuação]

**D - Discoverability**: [0-10]
Justificativa: [Por que essa pontuação]

**Risco Total**: (D+R+E+A+D) / 5 = [X.X]

**Classificação**: [Crítico/Alto/Médio/Baixo]
```

---

#### Ameaça 2: Broken Access Control em Perfil

**Descrição**: Usuários podem acessar perfis de outros usuários.

**Tarefas**:
- [ ] Aplicar DREAD completo
- [ ] Calcular risco
- [ ] Comparar com Ameaça 1

---

#### Ameaça 3: Senha Fraca Permitida

**Descrição**: Sistema aceita senhas muito simples.

**Tarefas**:
- [ ] Aplicar DREAD completo
- [ ] Calcular risco
- [ ] Comparar com outras ameaças

---

### Parte 2: Criar Matriz de Riscos

Crie matriz de priorização:

**Tarefas**:
- [ ] Listar todas as ameaças
- [ ] Ordenar por risco (maior para menor)
- [ ] Criar matriz visual
- [ ] Definir ações por nível de risco

**Template de Matriz**:
```markdown
# Matriz de Riscos

| Ameaça | DREAD Score | Classificação | Ação |
|--------|-------------|---------------|------|
| SQL Injection | 9.2 | Crítico | Corrigir imediatamente |
| Broken Access Control | 8.5 | Crítico | Corrigir imediatamente |
| Senha Fraca | 6.0 | Alto | Corrigir em breve |
```

---

### Parte 3: Justificar Priorização

Justifique a priorização:

**Tarefas**:
- [ ] Explicar por que ameaças críticas são prioritárias
- [ ] Considerar contexto (Financeiro, Educacional, Ecommerce)
- [ ] Documentar decisões de priorização

---

## Contexto CWI

### Caso Real: Priorização em Projeto

Em um projeto da CWI, usamos DREAD para priorizar 50+ ameaças:

**Resultado**:
- 10 ameaças críticas corrigidas primeiro
- 20 ameaças altas corrigidas depois
- Recursos alocados eficientemente
- Zero vulnerabilidades críticas em produção

---

## Dicas

1. **Seja consistente**: Use mesma escala para todas as ameaças
2. **Considere contexto**: Ameaça pode ser mais crítica em financeiro
3. **Documente justificativas**: Facilita revisão depois
4. **Revise regularmente**: Riscos mudam com o tempo

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.4.4: Threat Model Completo
- Exercício 1.4.5: Mitigação e Priorização
- Aplicar DREAD em projetos reais

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Exercício 1.4.2 (Identificar Ameaças)
