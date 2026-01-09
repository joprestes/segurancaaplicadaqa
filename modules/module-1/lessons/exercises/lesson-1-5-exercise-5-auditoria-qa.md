---
layout: exercise
title: "Exercício 1.5.5: Auditoria QA - Preparação e Execução"
slug: "auditoria-qa"
lesson_id: "lesson-1-5"
module: "module-1"
difficulty: "Avançado"
permalink: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-5-exercise-5-auditoria-qa/
lesson_url: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/compliance-regulamentacoes/
---

## Objetivo

Este exercício tem como objetivo **preparar e executar uma auditoria de compliance** do ponto de vista do QA, incluindo coleta de evidências, documentação e resposta a não conformidades.

Ao completar este exercício, você será capaz de:

- Preparar evidências para auditoria
- Executar auditoria interna de compliance
- Documentar não conformidades
- Criar planos de ação corretiva
- Responder a auditorias externas

---

## Descrição

Você precisa preparar e executar uma auditoria de compliance LGPD para uma aplicação, simulando o processo completo de auditoria.

### Contexto

Auditorias de compliance são processos formais que validam conformidade. Como QA, você precisa preparar evidências, executar auditorias internas e responder a auditorias externas.

---

## Requisitos

### Parte 1: Preparar Evidências

Colete evidências de compliance:

**Tipos de Evidências**:
- Documentação (políticas, procedimentos)
- Configurações (screenshots, logs)
- Testes (resultados, relatórios)
- Registros (logs de acesso, auditoria)

**Tarefas**:
- [ ] Listar evidências necessárias
- [ ] Coletar evidências existentes
- [ ] Criar evidências faltantes
- [ ] Organizar evidências por requisito
- [ ] Validar que evidências são suficientes

**Template de Evidências**:
```markdown
# Evidências de Compliance - [Requisito]

## Requisito: [Nome do Requisito]

### Evidências Documentais
- [ ] Política: [Nome do documento]
- [ ] Procedimento: [Nome do procedimento]
- [ ] Checklist: [Nome do checklist]

### Evidências Técnicas
- [ ] Screenshot: [Descrição]
- [ ] Log: [Data e hora]
- [ ] Configuração: [Descrição]

### Evidências de Teste
- [ ] Teste: [Nome do teste]
- [ ] Resultado: [Passou/Falhou]
- [ ] Data: [Data da execução]

### Validação
- [ ] Evidências são suficientes?
- [ ] Evidências são claras?
- [ ] Evidências são acessíveis?
```

---

### Parte 2: Executar Auditoria Interna

Execute auditoria interna simulada:

**Processo de Auditoria**:
1. Planejamento
2. Execução
3. Documentação
4. Relatório
5. Ação corretiva

**Tarefas**:
- [ ] Criar plano de auditoria
- [ ] Executar testes de compliance
- [ ] Documentar não conformidades
- [ ] Criar relatório de auditoria
- [ ] Propor ações corretivas

**Template de Auditoria**:
```markdown
# Relatório de Auditoria - [Aplicação]

## Informações Gerais
- **Data**: [Data]
- **Auditor**: [Nome]
- **Escopo**: [O que foi auditado]
- **Metodologia**: [Como foi auditado]

## Requisitos Auditados

### Requisito 1: [Nome]
- **Status**: ✅ Conforme / ❌ Não Conforme
- **Evidências**: [Lista de evidências]
- **Observações**: [Comentários]

### Requisito 2: [Nome]
- **Status**: ✅ Conforme / ❌ Não Conforme
- **Evidências**: [Lista de evidências]
- **Observações**: [Comentários]

## Não Conformidades Encontradas

### NC-001: [Título]
- **Requisito**: [Qual requisito]
- **Descrição**: [O que está errado]
- **Severidade**: [Alta/Média/Baixa]
- **Ação Corretiva**: [O que fazer]
- **Prazo**: [Quando corrigir]

## Conclusão
- **Conformidade Geral**: [%]
- **Recomendações**: [Recomendações gerais]
```

---

### Parte 3: Documentar Não Conformidades

Documente não conformidades encontradas:

**Tarefas**:
- [ ] Identificar não conformidades
- [ ] Classificar por severidade
- [ ] Documentar detalhadamente
- [ ] Propor ações corretivas
- [ ] Estimar prazos

**Template de Não Conformidade**:
```markdown
## Não Conformidade NC-XXX: [Título]

### Informações
- **ID**: NC-XXX
- **Requisito**: [Qual requisito não está sendo cumprido]
- **Severidade**: [Crítica/Alta/Média/Baixa]
- **Data de Identificação**: [Data]
- **Responsável**: [Quem vai corrigir]

### Descrição
[Descrição detalhada da não conformidade]

### Evidência
[Como foi identificada - logs, testes, etc.]

### Impacto
[Qual o impacto desta não conformidade]

### Causa Raiz
[Por que esta não conformidade existe]

### Ação Corretiva
[O que precisa ser feito para corrigir]

### Plano de Ação
1. [Passo 1]
2. [Passo 2]
3. [Passo 3]

### Prazo
[Quando deve ser corrigida]

### Validação
- [ ] Ação corretiva implementada
- [ ] Teste de validação executado
- [ ] Não conformidade resolvida
- [ ] Evidência de correção coletada
```

---

### Parte 4: Criar Plano de Ação Corretiva

Crie plano para corrigir não conformidades:

**Tarefas**:
- [ ] Priorizar não conformidades
- [ ] Criar planos de ação
- [ ] Definir responsáveis
- [ ] Estabelecer prazos
- [ ] Criar cronograma

**Template de Plano de Ação**:
```markdown
# Plano de Ação Corretiva - [Aplicação]

## Não Conformidades Críticas (Prazo: Imediato)
1. **NC-001**: [Título]
   - Responsável: [Nome]
   - Prazo: [Data]
   - Status: [Em andamento/Concluído]

2. **NC-002**: [Título]
   - Responsável: [Nome]
   - Prazo: [Data]
   - Status: [Em andamento/Concluído]

## Não Conformidades Altas (Prazo: 1 semana)
1. **NC-003**: [Título]
   - Responsável: [Nome]
   - Prazo: [Data]
   - Status: [Em andamento/Concluído]

## Não Conformidades Médias (Prazo: 1 mês)
1. **NC-004**: [Título]
   - Responsável: [Nome]
   - Prazo: [Data]
   - Status: [Em andamento/Concluído]

## Acompanhamento
- [ ] Revisão semanal
- [ ] Atualização de status
- [ ] Validação de correções
- [ ] Fechamento de não conformidades
```

---

### Parte 5: Responder a Auditoria Externa

Simule resposta a auditoria externa:

**Tarefas**:
- [ ] Preparar apresentação
- [ ] Organizar evidências
- [ ] Responder perguntas
- [ ] Documentar respostas
- [ ] Acompanhar ações corretivas

**Template de Resposta**:
```markdown
# Resposta a Auditoria Externa - [Data]

## Perguntas do Auditor

### Pergunta 1: [Pergunta]
**Resposta**: [Resposta detalhada]
**Evidência**: [Referência à evidência]

### Pergunta 2: [Pergunta]
**Resposta**: [Resposta detalhada]
**Evidência**: [Referência à evidência]

## Não Conformidades Identificadas

### NC-001: [Título]
**Plano de Ação**: [O que será feito]
**Prazo**: [Quando]
**Responsável**: [Quem]

## Compromissos
- [ ] Compromisso 1: [Descrição]
- [ ] Compromisso 2: [Descrição]
```

---

## Contexto CWI

### Caso Real: Auditoria LGPD em Projeto

Em um projeto da CWI, preparamos e executamos auditoria LGPD:

**Estratégia**:
- Evidências coletadas sistematicamente
- Auditoria interna antes da externa
- Não conformidades corrigidas proativamente
- Documentação completa

**Resultado**:
- Auditoria externa aprovada
- Não conformidades mínimas
- Processo de compliance estabelecido
- Confiança dos clientes aumentada

---

## Dicas

1. **Prepare-se antecipadamente**: Evidências devem estar prontas
2. **Seja organizado**: Facilita encontrar evidências
3. **Documente tudo**: Facilita resposta a perguntas
4. **Seja proativo**: Corrija não conformidades antes da auditoria
5. **Colabore**: Envolva toda a equipe

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Módulo 1 completo: Fundamentos de Segurança em QA
- Módulo 2: Testes de Segurança na Prática
- Aplicar auditorias de compliance em projetos reais

---

**Duração Estimada**: 120-180 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Exercício 1.5.4 (Compliance por Setor)
