---
layout: exercise
title: "Exercício 1.3.2: Threat Modeling na Fase de Design"
slug: "threat-modeling-early"
lesson_id: "lesson-1-3"
module: "module-1"
difficulty: "Intermediário"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-3-exercise-2-threat-modeling-early/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/shift-left-security/
---

## Objetivo

Este exercício tem como objetivo praticar **threat modeling** na fase de design através da **identificação de ameaças** antes do desenvolvimento.

Ao completar este exercício, você será capaz de:

- Realizar threat modeling básico usando STRIDE
- Identificar ameaças em arquiteturas de aplicação
- Priorizar ameaças por risco
- Documentar ameaças e mitigações

---

## Descrição

Você precisa realizar threat modeling para uma aplicação de exemplo, identificando ameaças na fase de design.

### Contexto

Threat modeling na fase de design é uma prática fundamental do Shift-Left Security. Identificar ameaças antes de desenvolver permite criar controles de segurança desde o início.

---

## Requisitos

### Parte 1: Entender a Aplicação

Analise a seguinte arquitetura de aplicação:

```
┌─────────────────────────────────────────────────────────┐
│  ARQUITETURA DA APLICAÇÃO                               │
│                                                         │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐     │
│  │  Cliente │──────│   API    │──────│  Banco   │     │
│  │  (Web)   │ HTTPS│  REST    │      │  Dados   │     │
│  └──────────┘      └──────────┘      └──────────┘     │
│       │                  │                  │          │
│       │                  │                  │          │
│       └──────────────────┴──────────────────┘          │
│                    Comunicação                          │
└─────────────────────────────────────────────────────────┘
```

**Funcionalidades**:
- Login de usuários
- Consulta de dados pessoais
- Atualização de perfil
- Upload de arquivos

**Tarefas**:
- [ ] Identificar componentes principais
- [ ] Identificar fluxos de dados
- [ ] Identificar pontos de entrada
- [ ] Identificar ativos sensíveis

---

### Parte 2: Aplicar STRIDE

Use a metodologia STRIDE para identificar ameaças:

**STRIDE**:
- **S**poofing (Falsificação)
- **T**ampering (Alteração)
- **R**epudiation (Repúdio)
- **I**nformation Disclosure (Divulgação de Informação)
- **D**enial of Service (Negação de Serviço)
- **E**levation of Privilege (Elevação de Privilégio)

**Tarefas**:
- [ ] Para cada componente, identificar ameaças STRIDE
- [ ] Documentar ameaças encontradas
- [ ] Priorizar ameaças por risco
- [ ] Propor mitigações

**Template de Threat**:
```markdown
## Threat T-XXX: [Nome da Ameaça]

**Componente**: [Componente afetado]

**Categoria STRIDE**: [S/T/R/I/D/E]

**Descrição**: [Descrição da ameaça]

**Impacto**: [Alto/Médio/Baixo]

**Probabilidade**: [Alta/Média/Baixa]

**Risco**: [Crítico/Alto/Médio/Baixo]

**Mitigação**: [Como mitigar]

**Validação**: [Como testar]
```

---

### Parte 3: Identificar Ameaças Específicas

Para cada funcionalidade, identifique ameaças específicas:

#### Funcionalidade: Login

**Tarefas**:
- [ ] Identificar ameaças de autenticação
- [ ] Considerar força bruta
- [ ] Considerar roubo de sessão
- [ ] Documentar ameaças e mitigações

**Exemplo**:
```markdown
## Threat T-001: Força Bruta em Login

**Componente**: API REST - Endpoint /api/login

**Categoria STRIDE**: Denial of Service (D)

**Descrição**: Atacante tenta múltiplas senhas para quebrar autenticação.

**Impacto**: Alto

**Probabilidade**: Alta

**Risco**: Alto

**Mitigação**: 
- Rate limiting: máximo 5 tentativas por minuto
- CAPTCHA após 3 tentativas
- Bloqueio temporário de conta após 10 tentativas

**Validação**: 
- Teste de rate limiting
- Teste de bloqueio de conta
```

---

#### Funcionalidade: Consulta de Dados

**Tarefas**:
- [ ] Identificar ameaças de acesso não autorizado
- [ ] Considerar IDOR (Insecure Direct Object Reference)
- [ ] Considerar divulgação de informação
- [ ] Documentar ameaças e mitigações

---

#### Funcionalidade: Upload de Arquivos

**Tarefas**:
- [ ] Identificar ameaças de upload
- [ ] Considerar path traversal
- [ ] Considerar upload de arquivos maliciosos
- [ ] Documentar ameaças e mitigações

---

### Parte 4: Priorizar e Documentar

Crie um documento de threat model completo:

**Tarefas**:
- [ ] Listar todas as ameaças identificadas
- [ ] Priorizar por risco (Crítico > Alto > Médio > Baixo)
- [ ] Documentar mitigações para cada ameaça
- [ ] Criar plano de validação

**Template de Threat Model**:
```markdown
# Threat Model - [Nome da Aplicação]

## Resumo Executivo
- Total de ameaças identificadas: [X]
- Críticas: [X]
- Altas: [X]
- Médias: [X]
- Baixas: [X]

## Ameaças por Prioridade

### Críticas
1. [Ameaça 1]
2. [Ameaça 2]

### Altas
1. [Ameaça 3]
2. [Ameaça 4]

## Mitigações
- [Mitigação 1]
- [Mitigação 2]

## Plano de Validação
- [Teste 1]
- [Teste 2]
```

---

## Contexto CWI

> **Nota**: O exemplo abaixo é um cenário hipotético criado para fins educacionais.

### Exemplo Hipotético: Threat Modeling em Projeto Financeiro

Em um projeto financeiro hipotético, realizaríamos threat modeling na fase de design:

**Ameaças Identificadas**:
1. Força bruta em login (Alta)
2. IDOR em consulta de extratos (Crítica)
3. Manipulação de transferências (Crítica)
4. Divulgação de dados de cartão (Crítica)

**Mitigações Implementadas**:
1. Rate limiting e MFA
2. Validação de propriedade
3. Validação de regras de negócio
4. Tokenização de dados de cartão

**Resultado**:
- Vulnerabilidades prevenidas antes do desenvolvimento
- Arquitetura segura desde o início
- Menos retrabalho

---

## Dicas

1. **Use STRIDE sistematicamente**: Passe por cada categoria
2. **Pense como atacante**: Como você atacaria essa aplicação?
3. **Priorize por risco**: Foque nas ameaças mais críticas
4. **Documente tudo**: Ameaças, mitigações, validações
5. **Colabore**: Threat modeling é melhor em equipe

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.3.3: Colaboração Dev/QA/Security
- Exercício 1.3.4: Shift-Left Checklist
- Aula 1.4: Threat Modeling (aprofundamento)

---


{% include exercise-submission-form.html %}

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Exercício 1.3.1 (Security Requirements)
