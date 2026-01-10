---
layout: exercise
title: "Exercício 1.5.3: Controles SOC2"
slug: "soc2-controles"
lesson_id: "lesson-1-5"
module: "module-1"
difficulty: "Intermediário"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-5-exercise-3-soc2-controles/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/compliance-regulamentacoes/
---

## Objetivo

Este exercício tem como objetivo **implementar e validar controles SOC2** através da criação de testes para os Trust Service Criteria (Segurança, Disponibilidade, Integridade, Confidencialidade, Privacidade).

Ao completar este exercício, você será capaz de:

- Entender os Trust Service Criteria do SOC2
- Criar controles SOC2
- Validar que controles estão funcionando
- Preparar evidências para auditoria SOC2

---

## Descrição

Você precisa criar e validar controles SOC2 para uma aplicação SaaS que fornece serviços baseados em nuvem.

### Contexto

SOC2 é um padrão de auditoria para organizações que fornecem serviços baseados em nuvem. Como QA, você precisa validar que os controles estão implementados e funcionando.

---

## Requisitos

### Parte 1: Entender Trust Service Criteria

Revise os 5 Trust Service Criteria do SOC2:

**1. Segurança (Security)**:
- Controles de acesso
- Proteção contra ameaças
- Monitoramento de segurança

**2. Disponibilidade (Availability)**:
- Uptime e performance
- Monitoramento de sistema
- Plano de continuidade

**3. Processamento de Integridade (Processing Integrity)**:
- Dados são processados corretamente
- Validação de dados
- Controles de qualidade

**4. Confidencialidade (Confidentiality)**:
- Dados confidenciais protegidos
- Controles de acesso
- Criptografia

**5. Privacidade (Privacy)**:
- Coleta e uso de dados pessoais
- Direitos dos titulares
- Notificação de incidentes

---

### Parte 2: Criar Controles SOC2

Crie controles para cada critério:

**Template de Controle**:
```markdown
## Controle SOC2: [Nome do Controle]

### Critério: [Segurança/Disponibilidade/Integridade/Confidencialidade/Privacidade]

### Objetivo
[O que este controle protege]

### Descrição
[Como o controle funciona]

### Requisitos
- [ ] Requisito 1: [Descrição]
- [ ] Requisito 2: [Descrição]

### Evidências
- [ ] Evidência 1: [Como documentar]
- [ ] Evidência 2: [Como documentar]
```

---

### Parte 3: Validar Controles de Segurança

Foque nos controles de segurança:

**Controle: Autenticação e Autorização**

**Tarefas**:
- [ ] Validar que autenticação forte está implementada
- [ ] Validar que MFA está disponível
- [ ] Validar que controle de acesso está funcionando
- [ ] Validar que sessões expiram adequadamente

**Casos de Teste**:
- Teste: Login sem credenciais → Deve falhar
- Teste: Login com credenciais inválidas → Deve falhar
- Teste: Login com MFA → Deve solicitar segundo fator
- Teste: Acesso não autorizado → Deve ser negado
- Teste: Sessão expirada → Deve exigir novo login

---

**Controle: Monitoramento de Segurança**

**Tarefas**:
- [ ] Validar que logs de segurança estão sendo registrados
- [ ] Validar que alertas estão configurados
- [ ] Validar que incidentes são detectados
- [ ] Validar que resposta a incidentes está funcionando

**Casos de Teste**:
- Teste: Tentativa de login falhada → Log deve ser registrado
- Teste: Acesso não autorizado → Alerta deve ser gerado
- Teste: Múltiplas tentativas falhadas → Conta deve ser bloqueada
- Teste: Incidente detectado → Resposta deve ser acionada

---

### Parte 4: Validar Controles de Disponibilidade

**Controle: Uptime e Performance**

**Tarefas**:
- [ ] Validar que uptime está sendo monitorado
- [ ] Validar que performance está sendo monitorada
- [ ] Validar que alertas de downtime estão configurados
- [ ] Validar que plano de continuidade existe

**Casos de Teste**:
- Teste: Aplicação está disponível → Uptime deve ser > 99.9%
- Teste: Performance está adequada → Tempo de resposta deve ser < 2s
- Teste: Downtime detectado → Alerta deve ser gerado
- Teste: Plano de continuidade → Deve estar documentado e testado

---

### Parte 5: Validar Controles de Integridade

**Controle: Processamento de Dados**

**Tarefas**:
- [ ] Validar que dados são processados corretamente
- [ ] Validar que validação de dados está funcionando
- [ ] Validar que erros são detectados e corrigidos
- [ ] Validar que controles de qualidade estão ativos

**Casos de Teste**:
- Teste: Dados válidos → Devem ser processados corretamente
- Teste: Dados inválidos → Devem ser rejeitados
- Teste: Erro no processamento → Deve ser detectado e corrigido
- Teste: Qualidade de dados → Deve ser validada

---

### Parte 6: Criar Plano de Validação SOC2

Crie plano completo de validação:

**Tarefas**:
- [ ] Listar todos os controles SOC2
- [ ] Criar testes para cada controle
- [ ] Priorizar controles críticos
- [ ] Documentar evidências necessárias
- [ ] Criar cronograma de validação

**Template de Plano**:
```markdown
# Plano de Validação SOC2

## Critério: Segurança
- [ ] Autenticação e autorização
- [ ] Monitoramento de segurança
- [ ] Proteção contra ameaças
- [ ] Controles de acesso

## Critério: Disponibilidade
- [ ] Uptime e performance
- [ ] Monitoramento de sistema
- [ ] Plano de continuidade

## Critério: Integridade
- [ ] Processamento de dados
- [ ] Validação de dados
- [ ] Controles de qualidade

## Critério: Confidencialidade
- [ ] Proteção de dados confidenciais
- [ ] Controles de acesso
- [ ] Criptografia

## Critério: Privacidade
- [ ] Coleta e uso de dados
- [ ] Direitos dos titulares
- [ ] Notificação de incidentes

## Evidências
- [ ] Logs de segurança
- [ ] Métricas de disponibilidade
- [ ] Testes de integridade
- [ ] Documentação de controles
```

---

## Contexto CWI

> **Nota**: O exemplo abaixo é um cenário hipotético criado para fins educacionais.

### Exemplo Hipotético: Controles SOC2 em SaaS

Em um projeto SaaS hipotético, implementaríamos controles SOC2:

**Estratégia**:
- Controles por critério SOC2
- Testes automatizados quando possível
- Evidências coletadas sistematicamente
- Validação contínua

**Resultado**:
- Controles SOC2 implementados
- Evidências prontas para auditoria
- Certificação SOC2 Type II obtida
- Confiança dos clientes aumentada

---

## Dicas

1. **Foque nos critérios relevantes**: Nem todos os critérios são necessários
2. **Documente evidências**: Facilita auditoria
3. **Automatize quando possível**: Testes repetitivos
4. **Colabore**: Envolva time de segurança e operações
5. **Revise regularmente**: Controles devem evoluir

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.5.4: Compliance por Setor
- Exercício 1.5.5: Auditoria QA
- Implementar controles SOC2 em projetos reais

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Exercício 1.5.2 (Validação PCI-DSS)
