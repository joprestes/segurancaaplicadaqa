---
layout: exercise
title: "Exercício 1.5.1: Checklist LGPD para Projeto"
slug: "lgpd-checklist"
lesson_id: "lesson-1-5"
module: "module-1"
difficulty: "Básico"
permalink: /modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-5-exercise-1-lgpd-checklist/
lesson_url: /modules/fundamentos-seguranca-qa/lessons/compliance-regulamentacoes/
---

## Objetivo

Este exercício tem como objetivo criar um **checklist completo de compliance LGPD** para um projeto real, aplicando os princípios e requisitos da LGPD.

Ao completar este exercício, você será capaz de:

- Aplicar princípios da LGPD em projetos
- Criar checklist de compliance LGPD
- Identificar requisitos técnicos necessários
- Validar conformidade com LGPD

---

## Descrição

Você precisa criar um checklist completo de compliance LGPD para uma aplicação web que coleta dados pessoais de usuários.

### Contexto

LGPD exige que organizações implementem controles técnicos e organizacionais para proteger dados pessoais. Como QA, você precisa validar que esses controles estão implementados.

---

## Requisitos

### Parte 1: Entender a Aplicação

Analise a seguinte aplicação:

**Aplicação**: Plataforma de E-learning

**Funcionalidades**:
- Cadastro de usuários (nome, email, CPF, data de nascimento)
- Cursos online
- Certificados digitais
- Área do aluno com dados pessoais
- Integração com pagamentos

**Dados Coletados**:
- Dados pessoais: nome, email, CPF, telefone
- Dados sensíveis: nenhum inicialmente
- Dados de navegação: cookies, logs

---

### Parte 2: Criar Checklist LGPD

Crie checklist completo seguindo os princípios da LGPD:

**Template de Checklist**:
```markdown
# Checklist LGPD - [Nome da Aplicação]

## 1. Princípio da Finalidade
- [ ] Finalidade do tratamento está clara?
- [ ] Dados são usados apenas para finalidade declarada?
- [ ] Não há uso secundário não autorizado?

## 2. Princípio da Adequação
- [ ] Dados coletados são adequados à finalidade?
- [ ] Não há coleta de dados desnecessários?
- [ ] Dados são relevantes?

## 3. Princípio da Necessidade
- [ ] Apenas dados necessários são coletados?
- [ ] Dados mínimos são solicitados?
- [ ] Não há coleta excessiva?

## 4. Princípio da Transparência
- [ ] Política de privacidade está acessível?
- [ ] Usuário é informado sobre uso de dados?
- [ ] Termos são claros e compreensíveis?

## 5. Princípio da Segurança
- [ ] Dados estão protegidos adequadamente?
- [ ] Criptografia está implementada?
- [ ] Controle de acesso está ativo?
- [ ] Logs de auditoria estão sendo registrados?

## 6. Princípio da Prevenção
- [ ] Medidas preventivas estão implementadas?
- [ ] Testes de segurança são realizados?
- [ ] Vulnerabilidades são corrigidas?

## 7. Princípio da Não Discriminação
- [ ] Dados não são usados para discriminar?
- [ ] Algoritmos são justos?
- [ ] Decisões automatizadas são transparentes?

## 8. Princípio da Responsabilização
- [ ] Controles estão documentados?
- [ ] Evidências de compliance existem?
- [ ] Responsáveis estão definidos?
```

---

### Parte 3: Requisitos Técnicos

Identifique requisitos técnicos necessários:

**Tarefas**:
- [ ] Listar controles técnicos necessários
- [ ] Identificar funcionalidades que precisam ser implementadas
- [ ] Criar plano de testes de compliance
- [ ] Documentar evidências necessárias

**Exemplos de Requisitos Técnicos**:
- Consentimento explícito antes de coletar dados
- Opção de revogar consentimento
- Endpoint para acesso aos dados (direito de acesso)
- Endpoint para correção de dados
- Endpoint para exclusão de dados
- Endpoint para portabilidade de dados
- Criptografia de dados sensíveis
- Logs de auditoria
- Controle de acesso

---

### Parte 4: Validar Conformidade

Crie plano de validação:

**Tarefas**:
- [ ] Criar casos de teste para cada princípio
- [ ] Validar que controles estão funcionando
- [ ] Verificar que evidências existem
- [ ] Documentar não conformidades

**Exemplos de Casos de Teste**:
- Teste: Usuário pode acessar política de privacidade antes de cadastrar
- Teste: Consentimento é obtido antes de coletar dados
- Teste: Usuário pode revogar consentimento
- Teste: Dados são criptografados em trânsito (HTTPS)
- Teste: Dados são criptografados em repouso
- Teste: Usuário pode acessar seus dados
- Teste: Usuário pode corrigir dados
- Teste: Usuário pode excluir dados
- Teste: Logs de acesso estão sendo registrados

---

## Contexto CWI

> **Nota**: O exemplo abaixo é um cenário hipotético criado para fins educacionais.

### Exemplo Hipotético: Checklist LGPD em Projeto

Em um projeto hipotético, criaríamos checklist LGPD com 50+ itens:

**Estratégia**:
- Checklist por princípio LGPD
- Requisitos técnicos identificados
- Casos de teste criados
- Validação contínua

**Resultado**:
- Compliance LGPD validado
- Evidências coletadas
- Não conformidades corrigidas
- Projeto pronto para auditoria

---

## Dicas

1. **Seja específico**: Checklist deve ser acionável
2. **Considere contexto**: Diferentes aplicações têm diferentes requisitos
3. **Documente evidências**: Facilita auditoria
4. **Revise regularmente**: LGPD evolui
5. **Colabore**: Envolva time jurídico e segurança

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.5.2: Validação PCI-DSS
- Exercício 1.5.3: Controles SOC2
- Aplicar checklist LGPD em projetos reais

---


{% include exercise-submission-form.html %}

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Básico  
**Pré-requisitos**: Aula 1.5 (Compliance e Regulamentações)
