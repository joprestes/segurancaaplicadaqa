---
layout: exercise
title: "Exercício 1.5.4: Compliance por Setor"
slug: "compliance-por-setor"
lesson_id: "lesson-1-5"
module: "module-1"
difficulty: "Avançado"
permalink: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-5-exercise-4-compliance-por-setor/
lesson_url: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/compliance-regulamentacoes/
---

## Objetivo

Este exercício tem como objetivo **aplicar compliance específico por setor** através da criação de checklists e validação de requisitos específicos para Financeiro, Educacional e Ecommerce.

Ao completar este exercício, você será capaz de:

- Entender requisitos de compliance por setor
- Criar checklists específicos por setor
- Validar compliance multi-regulamentação
- Aplicar compliance em contextos CWI

---

## Descrição

Você precisa criar e validar compliance para três projetos diferentes, cada um em um setor específico: Financeiro, Educacional e Ecommerce.

### Contexto

Diferentes setores têm diferentes requisitos de compliance. Como QA, você precisa entender e validar compliance específico para cada setor.

---

## Requisitos

### Parte 1: Projeto Financeiro - Fintech

**Aplicação**: Plataforma de Pagamentos

**Regulamentações Aplicáveis**:
- PCI-DSS (pagamentos)
- LGPD (dados pessoais)
- Resolução BCB (Banco Central)
- Open Banking (compartilhamento de dados)

**Tarefas**:
- [ ] Criar checklist PCI-DSS
- [ ] Criar checklist LGPD
- [ ] Criar checklist Open Banking
- [ ] Validar compliance multi-regulamentação
- [ ] Criar plano de testes

**Checklist Financeiro**:
```markdown
# Checklist Compliance Financeiro

## PCI-DSS
- [ ] Dados de cartão tokenizados
- [ ] Criptografia end-to-end
- [ ] Autenticação forte (MFA)
- [ ] Logs de auditoria completos

## LGPD
- [ ] Consentimento explícito
- [ ] Direitos do titular respeitados
- [ ] Dados protegidos adequadamente
- [ ] Política de privacidade clara

## Open Banking
- [ ] Consentimento para compartilhamento
- [ ] APIs seguras
- [ ] Controle de acesso
- [ ] Logs de compartilhamento

## Resolução BCB
- [ ] Autenticação forte
- [ ] Controles de segurança
- [ ] Monitoramento de transações
- [ ] Prevenção de fraudes
```

---

### Parte 2: Projeto Educacional - EdTech

**Aplicação**: Plataforma de Ensino Online

**Regulamentações Aplicáveis**:
- LGPD (dados de menores têm proteção especial)
- ECA (Estatuto da Criança e do Adolescente)
- LDB (Lei de Diretrizes e Bases)

**Tarefas**:
- [ ] Criar checklist LGPD para menores
- [ ] Criar checklist ECA
- [ ] Validar proteção especial de dados de menores
- [ ] Validar consentimento dos pais
- [ ] Criar plano de testes

**Checklist Educacional**:
```markdown
# Checklist Compliance Educacional

## LGPD - Dados de Menores
- [ ] Consentimento dos pais/responsáveis
- [ ] Isolamento rigoroso de dados
- [ ] Transparência total
- [ ] Direitos dos menores respeitados

## ECA
- [ ] Proteção de dados de menores
- [ ] Não discriminação
- [ ] Direito à privacidade
- [ ] Direito à educação

## LDB
- [ ] Dados educacionais protegidos
- [ ] Histórico escolar seguro
- [ ] Certificados válidos
- [ ] Transparência de avaliações
```

---

### Parte 3: Projeto Ecommerce

**Aplicação**: Loja Online

**Regulamentações Aplicáveis**:
- PCI-DSS (pagamentos)
- LGPD (dados pessoais)
- Código de Defesa do Consumidor

**Tarefas**:
- [ ] Criar checklist PCI-DSS
- [ ] Criar checklist LGPD
- [ ] Criar checklist CDC
- [ ] Validar segurança de pagamentos
- [ ] Validar proteção de dados pessoais
- [ ] Criar plano de testes

**Checklist Ecommerce**:
```markdown
# Checklist Compliance Ecommerce

## PCI-DSS
- [ ] Dados de cartão protegidos
- [ ] Tokenização implementada
- [ ] Criptografia em trânsito
- [ ] Controles de acesso

## LGPD
- [ ] Consentimento para coleta
- [ ] Política de privacidade
- [ ] Direitos do consumidor
- [ ] Proteção de dados

## CDC
- [ ] Transparência de preços
- [ ] Informações claras
- [ ] Direito de arrependimento
- [ ] Proteção do consumidor
```

---

### Parte 4: Comparar Requisitos por Setor

Crie tabela comparativa:

**Tarefas**:
- [ ] Comparar requisitos entre setores
- [ ] Identificar requisitos comuns
- [ ] Identificar requisitos específicos
- [ ] Criar guia de compliance multi-setor

**Tabela Comparativa**:
```markdown
| Requisito | Financeiro | Educacional | Ecommerce |
|-----------|------------|-------------|-----------|
| PCI-DSS | ✅ Obrigatório | ❌ Não aplicável | ✅ Obrigatório |
| LGPD | ✅ Obrigatório | ✅ Obrigatório (especial) | ✅ Obrigatório |
| Autenticação Forte | ✅ Obrigatório | ⚠️ Recomendado | ⚠️ Recomendado |
| Dados de Menores | ⚠️ Quando aplicável | ✅ Obrigatório | ⚠️ Quando aplicável |
| Open Banking | ✅ Obrigatório | ❌ Não aplicável | ❌ Não aplicável |
```

---

### Parte 5: Criar Plano de Validação Multi-Setor

Crie plano de validação que considere múltiplos setores:

**Tarefas**:
- [ ] Identificar requisitos comuns
- [ ] Criar testes reutilizáveis
- [ ] Criar testes específicos por setor
- [ ] Priorizar validação
- [ ] Documentar evidências

**Template de Plano**:
```markdown
# Plano de Validação Compliance Multi-Setor

## Requisitos Comuns (Todos os Setores)
- LGPD: Consentimento, direitos do titular, proteção de dados
- Segurança: Criptografia, controle de acesso, logs

## Requisitos Específicos por Setor

### Financeiro
- PCI-DSS: Tokenização, criptografia end-to-end
- Open Banking: APIs seguras, consentimento

### Educacional
- LGPD Especial: Dados de menores, consentimento dos pais
- ECA: Proteção de menores

### Ecommerce
- PCI-DSS: Dados de cartão
- CDC: Transparência, direitos do consumidor

## Testes Reutilizáveis
- Teste de consentimento LGPD
- Teste de criptografia
- Teste de controle de acesso

## Testes Específicos
- Financeiro: Teste de tokenização PCI-DSS
- Educacional: Teste de consentimento dos pais
- Ecommerce: Teste de transparência CDC
```

---

## Contexto CWI

### Caso Real: Compliance Multi-Setor

A CWI trabalha com projetos em múltiplos setores:

**Estratégia**:
- Checklist base comum (LGPD, segurança)
- Checklists específicos por setor
- Testes reutilizáveis quando possível
- Validação contínua

**Resultado**:
- Compliance validado em todos os setores
- Eficiência na validação
- Conhecimento especializado por setor
- Projetos prontos para mercado

---

## Dicas

1. **Entenda o setor**: Cada setor tem suas particularidades
2. **Reutilize quando possível**: Requisitos comuns podem ser testados uma vez
3. **Seja específico**: Checklists devem refletir requisitos reais
4. **Colabore**: Envolva especialistas do setor
5. **Mantenha atualizado**: Regulamentações evoluem

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.5.5: Auditoria QA
- Módulo 2: Testes de Segurança na Prática
- Aplicar compliance em projetos reais por setor

---

**Duração Estimada**: 120-150 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Exercício 1.5.3 (Controles SOC2)
