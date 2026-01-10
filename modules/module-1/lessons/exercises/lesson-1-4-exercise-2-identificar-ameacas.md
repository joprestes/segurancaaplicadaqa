---
layout: exercise
title: "Exercício 1.4.2: Identificar Ameaças em Arquitetura Complexa"
slug: "identificar-ameacas"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Intermediário"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-4-exercise-2-identificar-ameacas/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/threat-modeling/
---

## Objetivo

Este exercício tem como objetivo praticar **identificação de ameaças** em arquiteturas mais complexas através da **análise detalhada** de componentes e fluxos.

Ao completar este exercício, você será capaz de:

- Identificar ameaças em arquiteturas complexas
- Analisar fluxos de dados para encontrar ameaças
- Identificar ameaças em integrações
- Documentar ameaças de forma completa

---

## Descrição

Você precisa identificar ameaças em uma arquitetura mais complexa com múltiplos componentes e integrações.

### Contexto

Aplicações reais têm arquiteturas complexas. Este exercício desenvolve a capacidade de identificar ameaças em sistemas mais elaborados.

---

## Requisitos

### Parte 1: Analisar Arquitetura

Analise a seguinte arquitetura:

```
┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐
│  Cliente │──────│   API    │──────│  Banco   │      │ Gateway  │
│   Web    │ HTTPS│  Gateway │      │  Dados   │      │Pagamento │
└──────────┘      └──────────┘      └──────────┘      └──────────┘
                        │                  │                  │
                        │                  │                  │
                        ▼                  ▼                  ▼
                   ┌──────────┐      ┌──────────┐      ┌──────────┐
                   │   API   │      │  Cache   │      │  Email   │
                   │  Users  │      │  Redis   │      │ Service  │
                   └──────────┘      └──────────┘      └──────────┘
```

**Funcionalidades**:
- Login e autenticação
- Consulta de dados de usuário
- Processamento de pagamentos
- Envio de emails

**Tarefas**:
- [ ] Identificar todos os componentes
- [ ] Mapear fluxos de dados
- [ ] Identificar pontos de entrada
- [ ] Identificar ativos sensíveis

---

### Parte 2: Identificar Ameaças por Componente

Para cada componente, identifique ameaças:

#### API Gateway

**Tarefas**:
- [ ] Aplicar STRIDE completo
- [ ] Considerar ameaças de roteamento
- [ ] Considerar ameaças de rate limiting
- [ ] Documentar ameaças encontradas

---

#### API de Usuários

**Tarefas**:
- [ ] Aplicar STRIDE completo
- [ ] Considerar ameaças de acesso
- [ ] Considerar ameaças de dados
- [ ] Documentar ameaças encontradas

---

#### Cache Redis

**Tarefas**:
- [ ] Aplicar STRIDE completo
- [ ] Considerar ameaças de cache poisoning
- [ ] Considerar ameaças de expiração
- [ ] Documentar ameaças encontradas

---

#### Gateway de Pagamento

**Tarefas**:
- [ ] Aplicar STRIDE completo
- [ ] Considerar ameaças de integração
- [ ] Considerar ameaças de dados de cartão
- [ ] Documentar ameaças encontradas

---

### Parte 3: Identificar Ameaças em Fluxos

Analise fluxos específicos:

#### Fluxo: Processamento de Pagamento

**Fluxo**:
1. Cliente envia dados de pagamento
2. API valida dados
3. API envia para Gateway de Pagamento
4. Gateway processa
5. API atualiza status
6. Email de confirmação enviado

**Tarefas**:
- [ ] Identificar ameaças em cada passo
- [ ] Considerar ameaças de integridade
- [ ] Considerar ameaças de confidencialidade
- [ ] Documentar ameaças encontradas

---

## Contexto CWI

### Caso Real: Threat Modeling em Projeto Financeiro

Em um projeto financeiro da CWI, realizamos threat modeling completo:

**Ameaças Identificadas**:
- 15 ameaças críticas
- 25 ameaças altas
- 30 ameaças médias

**Mitigações Implementadas**:
- Validação de propriedade
- Criptografia de dados sensíveis
- Logs de auditoria
- Rate limiting

**Resultado**:
- Zero vulnerabilidades críticas em produção
- Arquitetura segura desde o início

---

## Dicas

1. **Analise cada componente**: Não pule nenhum
2. **Considere integrações**: Pontos de integração são vulneráveis
3. **Analise fluxos**: Ameaças podem estar nos fluxos
4. **Documente tudo**: Mesmo ameaças que parecem óbvias

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.4.3: Análise de Riscos
- Exercício 1.4.4: Threat Model Completo
- Aplicar em projetos reais

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Exercício 1.4.1 (STRIDE Básico)
