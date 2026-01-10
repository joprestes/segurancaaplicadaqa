---
layout: exercise
title: "Exercício 1.3.4: Checklist Shift-Left Security"
slug: "shift-left-checklist"
lesson_id: "lesson-1-3"
module: "module-1"
difficulty: "Avançado"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-3-exercise-4-shift-left-checklist/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/shift-left-security/
---

## Objetivo

Este exercício tem como objetivo criar um **checklist completo de Shift-Left Security** para uso em projetos reais, garantindo que segurança seja integrada em todas as fases do SDLC.

Ao completar este exercício, você será capaz de:

- Criar checklist de Shift-Left Security por fase do SDLC
- Adaptar checklist para diferentes contextos (Financeiro, Educacional, Ecommerce)
- Aplicar checklist em projetos reais
- Medir efetividade de Shift-Left Security

---

## Descrição

Você precisa criar um checklist completo e prático de Shift-Left Security que possa ser usado em projetos reais para garantir que segurança seja integrada em todas as fases.

### Contexto

Um checklist sistemático é essencial para garantir que Shift-Left Security seja aplicado consistentemente em todos os projetos. Este exercício desenvolve essa capacidade criando um checklist reutilizável.

---

## Requisitos

### Parte 1: Checklist por Fase do SDLC

Crie um checklist detalhado para cada fase do SDLC:

#### Checklist: Fase de Requisitos

**Tarefas**:
- [ ] Criar checklist de security requirements
- [ ] Incluir validações específicas
- [ ] Adicionar itens de compliance
- [ ] Criar critérios de conclusão

**Template Sugerido**:
```markdown
## Checklist: Fase de Requisitos

### Security Requirements
- [ ] Security requirements definidos junto com requisitos funcionais
- [ ] Requisitos de compliance incluídos (LGPD, PCI-DSS, SOC2)
- [ ] Requisitos são específicos e mensuráveis
- [ ] Requisitos são testáveis
- [ ] Requisitos priorizados por criticidade

### Participação de QA
- [ ] QA participa de reuniões de requisitos
- [ ] QA questiona requisitos de segurança ausentes
- [ ] QA valida que requisitos são testáveis
- [ ] QA cria casos de teste baseados em security requirements

### Documentação
- [ ] Security requirements documentados
- [ ] Template padronizado usado
- [ ] Requisitos revisados e aprovados
- [ ] Rastreabilidade mantida
```

---

#### Checklist: Fase de Design

**Tarefas**:
- [ ] Criar checklist de threat modeling
- [ ] Incluir validações de arquitetura
- [ ] Adicionar itens de controles de segurança
- [ ] Criar critérios de conclusão

---

#### Checklist: Fase de Desenvolvimento

**Tarefas**:
- [ ] Criar checklist de secure coding
- [ ] Incluir validações de code review
- [ ] Adicionar itens de bibliotecas seguras
- [ ] Criar critérios de conclusão

---

#### Checklist: Fase de Testes

**Tarefas**:
- [ ] Criar checklist de security testing
- [ ] Incluir validações de testes automatizados
- [ ] Adicionar itens de validação de requisitos
- [ ] Criar critérios de conclusão

---

#### Checklist: Fase de Produção

**Tarefas**:
- [ ] Criar checklist de security monitoring
- [ ] Incluir validações de logs
- [ ] Adicionar itens de resposta a incidentes
- [ ] Criar critérios de conclusão

---

### Parte 2: Adaptar por Contexto

Adapte o checklist para diferentes contextos:

#### Checklist Financeiro

**Tarefas**:
- [ ] Priorizar itens críticos para financeiro
- [ ] Adicionar validações de PCI-DSS
- [ ] Incluir requisitos de Open Banking
- [ ] Adicionar testes de fraude

---

#### Checklist Educacional

**Tarefas**:
- [ ] Priorizar itens críticos para educacional
- [ ] Adicionar validações de LGPD (dados de menores)
- [ ] Incluir requisitos de privacidade
- [ ] Adicionar testes de isolamento de dados

---

#### Checklist Ecommerce

**Tarefas**:
- [ ] Priorizar itens críticos para ecommerce
- [ ] Adicionar validações de prevenção de fraude
- [ ] Incluir requisitos de integridade de preços
- [ ] Adicionar testes de transações

---

### Parte 3: Criar Métricas

Crie métricas para medir efetividade:

**Tarefas**:
- [ ] Definir métricas de Shift-Left Security
- [ ] Criar dashboard de métricas
- [ ] Estabelecer metas
- [ ] Criar processo de acompanhamento

**Métricas Sugeridas**:
- % de security requirements cobertos por testes
- Número de vulnerabilidades encontradas por fase
- Tempo médio de correção de vulnerabilidades
- % de code reviews focados em segurança

---

### Parte 4: Aplicar Checklist

Aplique o checklist em um projeto real ou de exemplo:

**Tarefas**:
- [ ] Escolher projeto para aplicar checklist
- [ ] Executar checklist completo
- [ ] Documentar resultados
- [ ] Identificar gaps
- [ ] Criar plano de melhoria

---

## Contexto CWI

> **Nota**: O exemplo abaixo é um cenário hipotético criado para fins educacionais.

### Exemplo Hipotético: Checklist em Múltiplos Projetos

Em projetos hipotéticos, implementaríamos checklist de Shift-Left Security:

**Resultados**:
- Redução de 70% em vulnerabilidades encontradas em produção
- Tempo de correção reduzido em 60%
- Maior satisfação do time
- Produtos mais seguros

**Lição Aprendida**:
- Checklist sistemático é essencial
- Adaptação por contexto aumenta efetividade
- Métricas ajudam a medir sucesso
- Revisão regular do checklist é importante

---

## Checklist Completo de Referência

### Fase de Requisitos
- [ ] Security requirements definidos
- [ ] Compliance incluído
- [ ] QA participa
- [ ] Requisitos testáveis

### Fase de Design
- [ ] Threat modeling realizado
- [ ] Arquitetura de segurança definida
- [ ] Controles no design
- [ ] QA participa

### Fase de Desenvolvimento
- [ ] Code reviews de segurança
- [ ] Secure coding practices
- [ ] Bibliotecas seguras
- [ ] QA realiza reviews

### Fase de Testes
- [ ] Testes de segurança incluídos
- [ ] Testes automatizados
- [ ] Validação de requisitos
- [ ] Documentação de vulnerabilidades

### Fase de Produção
- [ ] Monitoramento ativo
- [ ] Logs configurados
- [ ] Resposta a incidentes
- [ ] QA valida monitoramento

---

## Dicas

1. **Seja sistemático**: Siga checklist em ordem
2. **Adapte**: Ajuste para contexto específico
3. **Meça**: Use métricas para acompanhar
4. **Revise**: Atualize checklist regularmente
5. **Compartilhe**: Compartilhe conhecimento com time

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Aplicar checklist em projetos reais
- Adaptar checklist para novos contextos
- Medir efetividade de Shift-Left Security
- Aula 1.4: Threat Modeling (aprofundamento)

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Todos os exercícios anteriores (1.3.1 a 1.3.3)
