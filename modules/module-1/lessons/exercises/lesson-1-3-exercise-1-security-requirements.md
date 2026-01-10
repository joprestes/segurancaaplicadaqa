---
layout: exercise
title: "Exercício 1.3.1: Criar Security Requirements"
slug: "security-requirements"
lesson_id: "lesson-1-3"
module: "module-1"
difficulty: "Básico"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-3-exercise-1-security-requirements/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/shift-left-security/
---

## Objetivo

Este exercício tem como objetivo praticar **criação de security requirements** através da **definição de requisitos de segurança** para funcionalidades específicas.

Ao completar este exercício, você será capaz de:

- Identificar requisitos de segurança para funcionalidades
- Documentar security requirements de forma clara e testável
- Aplicar requisitos de compliance (LGPD, PCI-DSS)
- Validar que requisitos são implementáveis e testáveis

---

## Descrição

Você precisa criar security requirements para diferentes funcionalidades de uma aplicação, considerando contexto específico (Financeiro, Educacional, Ecommerce).

### Contexto

Security requirements são a base do Shift-Left Security. Como QA, você precisa saber identificar e documentar requisitos de segurança desde a fase de requisitos.

---

## Requisitos

### Parte 1: Análise de Funcionalidade

Para cada funcionalidade abaixo, identifique security requirements necessários:

#### Funcionalidade 1: Sistema de Login

**Descrição Funcional**:
"Sistema deve permitir que usuários façam login com email e senha."

**Tarefas**:
- [ ] Identificar security requirements necessários
- [ ] Considerar autenticação forte
- [ ] Incluir requisitos de rate limiting
- [ ] Considerar requisitos de sessão
- [ ] Documentar requisitos usando template

**Template de Security Requirement**:
```markdown
## Security Requirement SR-XXX: [Nome]

**Funcionalidade**: [Nome da funcionalidade]

**Descrição**: [Descrição do requisito de segurança]

**Criticidade**: [Alta/Média/Baixa]

**Requisitos Específicos**:
- Requisito 1
- Requisito 2
- Requisito 3

**Compliance**: [LGPD/PCI-DSS/SOC2/Nenhum]

**Validação**: [Como validar/testar]
```

---

#### Funcionalidade 2: Transferência Bancária

**Descrição Funcional**:
"Sistema deve permitir que usuários transfiram dinheiro entre contas."

**Contexto**: Aplicação Financeira (Fintech)

**Tarefas**:
- [ ] Identificar security requirements críticos
- [ ] Considerar validação de propriedade
- [ ] Incluir requisitos de auditoria
- [ ] Considerar limites e validações de negócio
- [ ] Incluir requisitos de compliance (PCI-DSS se aplicável)

---

#### Funcionalidade 3: Área do Aluno

**Descrição Funcional**:
"Sistema deve permitir que alunos visualizem suas notas e atividades."

**Contexto**: Plataforma Educacional (EdTech)

**Tarefas**:
- [ ] Identificar security requirements
- [ ] Considerar isolamento de dados (alunos não veem dados de outros)
- [ ] Incluir requisitos de LGPD (dados de menores)
- [ ] Considerar privacidade e consentimento

---

#### Funcionalidade 4: Checkout de Ecommerce

**Descrição Funcional**:
"Sistema deve permitir que clientes finalizem compras e insiram dados de pagamento."

**Contexto**: Ecommerce

**Tarefas**:
- [ ] Identificar security requirements críticos
- [ ] Considerar proteção de dados de cartão (PCI-DSS)
- [ ] Incluir requisitos de validação de transação
- [ ] Considerar prevenção de fraude

---

### Parte 2: Criar Security Requirements Completos

Escolha uma das funcionalidades acima e crie security requirements completos:

**Tarefas**:
- [ ] Criar pelo menos 5 security requirements
- [ ] Priorizar por criticidade
- [ ] Incluir requisitos de compliance quando aplicável
- [ ] Garantir que requisitos são testáveis
- [ ] Documentar como validar cada requisito

**Exemplo Completo**:
```markdown
## Security Requirement SR-001: Autenticação Forte

**Funcionalidade**: Sistema de Login

**Descrição**: Sistema deve implementar autenticação forte para prevenir acesso não autorizado.

**Criticidade**: Alta

**Requisitos Específicos**:
- Senhas devem ter mínimo de 12 caracteres
- Senhas devem conter: maiúsculas, minúsculas, números e caracteres especiais
- MFA obrigatório para operações sensíveis
- Rate limiting: máximo 5 tentativas de login por minuto por IP
- Sessões devem expirar após 30 minutos de inatividade
- Senhas devem ser armazenadas com hash bcrypt (nunca texto plano)

**Compliance**: LGPD, PCI-DSS (se aplicável)

**Validação**:
- Teste de política de senhas
- Teste de rate limiting
- Teste de expiração de sessão
- Verificação de hash de senhas no banco
```

---

### Parte 3: Validar Security Requirements

Valide os security requirements criados:

**Tarefas**:
- [ ] Verificar que requisitos são específicos e mensuráveis
- [ ] Validar que requisitos são testáveis
- [ ] Garantir que requisitos atendem compliance quando necessário
- [ ] Verificar que requisitos são implementáveis
- [ ] Priorizar requisitos por criticidade

**Checklist de Validação**:
- [ ] Requisito é específico (não vago)
- [ ] Requisito é mensurável (pode ser validado)
- [ ] Requisito é testável (pode criar testes)
- [ ] Requisito é implementável (tecnologicamente viável)
- [ ] Requisito atende compliance quando necessário

---

## Contexto CWI

> **Nota**: O exemplo abaixo é um cenário hipotético criado para fins educacionais.

### Exemplo Hipotético: Projeto Financeiro

Em um projeto financeiro hipotético, criaríamos security requirements detalhados para funcionalidade de transferência bancária:

**Security Requirements Criados**:
1. Validação de propriedade da conta origem
2. Limite de transferência por dia
3. Autenticação forte (MFA) para transferências acima de R$ 1.000
4. Logs de auditoria para todas as transferências
5. Validação de conta destino
6. Rate limiting para prevenir abusos

**Resultado**:
- Zero incidentes de segurança relacionados a transferências
- Compliance mantido
- Funcionalidade segura desde o início

---

## Dicas

1. **Pense como atacante**: Quais vulnerabilidades essa funcionalidade pode ter?
2. **Considere compliance**: LGPD, PCI-DSS, SOC2 quando aplicável
3. **Seja específico**: Evite requisitos vagos como "deve ser seguro"
4. **Testável**: Garanta que pode criar testes para validar
5. **Priorize**: Foque primeiro nas vulnerabilidades mais críticas

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.3.2: Threat Modeling Early
- Exercício 1.3.3: Colaboração Dev/QA/Security
- Aplicar security requirements em projetos reais

---

**Duração Estimada**: 45-60 minutos  
**Nível**: Básico  
**Pré-requisitos**: Aula 1.3 (Shift-Left Security)
