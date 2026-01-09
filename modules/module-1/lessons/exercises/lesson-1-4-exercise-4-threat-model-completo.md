---
layout: exercise
title: "Exercício 1.4.4: Criar Threat Model Completo"
slug: "threat-model-completo"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Avançado"
permalink: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-4-exercise-4-threat-model-completo/
lesson_url: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/threat-modeling/
---

## Objetivo

Este exercício tem como objetivo criar um **threat model completo** para uma aplicação real, aplicando todas as técnicas aprendidas.

Ao completar este exercício, você será capaz de:

- Criar threat model completo e profissional
- Aplicar metodologias STRIDE e DREAD
- Documentar ameaças e mitigações
- Criar plano de validação

---

## Descrição

Você precisa criar um threat model completo para uma aplicação de exemplo, aplicando todo o processo de threat modeling.

### Contexto

Threat models completos são documentos profissionais usados em projetos reais. Este exercício desenvolve a capacidade de criar documentos de qualidade profissional.

---

## Requisitos

### Parte 1: Escolher Aplicação

Escolha uma das seguintes aplicações:

**Opção A**: Sistema de Ecommerce
- Funcionalidades: Login, Catálogo, Carrinho, Checkout, Pagamento

**Opção B**: Plataforma Educacional
- Funcionalidades: Login, Área do Aluno, Notas, Atividades, Chat

**Opção C**: API Financeira
- Funcionalidades: Autenticação, Consulta de Saldo, Transferências, Extratos

**Tarefas**:
- [ ] Escolher aplicação
- [ ] Documentar arquitetura
- [ ] Identificar componentes
- [ ] Mapear fluxos de dados

---

### Parte 2: Criar Threat Model Completo

Siga o processo completo:

**Tarefas**:
- [ ] Identificar ativos
- [ ] Identificar pontos de entrada
- [ ] Aplicar STRIDE a todos os componentes
- [ ] Calcular riscos com DREAD
- [ ] Priorizar ameaças
- [ ] Propor mitigações
- [ ] Criar plano de validação

**Template Completo**:
```markdown
# Threat Model - [Nome da Aplicação]

## Informações Gerais
- Data: [Data]
- Versão: [Versão]
- Responsável: [Nome]
- Metodologia: STRIDE + DREAD

## Arquitetura
[Diagrama da arquitetura]

## Ativos
1. [Ativo 1]
2. [Ativo 2]

## Pontos de Entrada
1. [Ponto de entrada 1]
2. [Ponto de entrada 2]

## Ameaças Identificadas

### Críticas (DREAD > 8.0)
1. [Ameaça 1]
2. [Ameaça 2]

### Altas (DREAD 6.0-8.0)
1. [Ameaça 3]

### Médias (DREAD 4.0-6.0)
1. [Ameaça 4]

## Mitigações
- [Mitigação 1]
- [Mitigação 2]

## Plano de Validação
- [Teste 1]
- [Teste 2]
```

---

### Parte 3: Validar Threat Model

Valide o threat model criado:

**Tarefas**:
- [ ] Revisar completude
- [ ] Validar que todas as ameaças críticas têm mitigações
- [ ] Verificar que plano de validação está completo
- [ ] Garantir que documentação está clara

---

## Contexto CWI

### Caso Real: Threat Model em Projeto

Em um projeto da CWI, criamos threat model completo:

**Resultado**:
- 30+ ameaças identificadas
- 10 ameaças críticas mitigadas antes de produção
- Zero vulnerabilidades críticas em produção
- Documento usado como referência em outros projetos

---

## Dicas

1. **Seja completo**: Não pule etapas
2. **Documente tudo**: Mesmo ameaças que parecem óbvias
3. **Use templates**: Facilita organização
4. **Revise**: Peça para outra pessoa revisar
5. **Atualize**: Threat models devem ser atualizados regularmente

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.4.5: Mitigação e Priorização
- Aplicar threat modeling em projetos reais
- Criar threat models para diferentes contextos

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Exercício 1.4.3 (Análise de Riscos)
