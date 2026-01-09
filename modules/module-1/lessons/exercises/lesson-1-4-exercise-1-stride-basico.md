---
layout: exercise
title: "Exercício 1.4.1: Aplicar STRIDE Básico"
slug: "stride-basico"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Básico"
permalink: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-4-exercise-1-stride-basico/
lesson_url: /seguranca-qa/modules/fundamentos-seguranca-qa/lessons/threat-modeling/
---

## Objetivo

Este exercício tem como objetivo praticar **aplicação de STRIDE** através da **identificação de ameaças** usando a metodologia STRIDE.

Ao completar este exercício, você será capaz de:

- Aplicar STRIDE sistematicamente
- Identificar ameaças por categoria STRIDE
- Documentar ameaças encontradas
- Priorizar ameaças básicas

---

## Descrição

Você precisa aplicar STRIDE em uma aplicação simples, identificando ameaças para cada categoria.

### Contexto

STRIDE é uma metodologia fundamental de threat modeling. Este exercício desenvolve a capacidade de aplicá-la sistematicamente.

---

## Requisitos

### Parte 1: Entender a Aplicação

Analise a seguinte aplicação simples:

**Aplicação**: Sistema de Login e Perfil de Usuário

**Arquitetura**:
```
Cliente Web → API REST → Banco de Dados
```

**Funcionalidades**:
- Login de usuários
- Visualização de perfil próprio
- Atualização de perfil

**Componentes**:
- Frontend (Cliente Web)
- API REST (/api/login, /api/users/<id>)
- Banco de Dados (tabela users)

---

### Parte 2: Aplicar STRIDE

Para cada componente, identifique ameaças STRIDE:

#### Componente: API de Login

**Tarefas**:
- [ ] Identificar ameaça de **Spoofing**
- [ ] Identificar ameaça de **Tampering**
- [ ] Identificar ameaça de **Repudiation**
- [ ] Identificar ameaça de **Information Disclosure**
- [ ] Identificar ameaça de **Denial of Service**
- [ ] Identificar ameaça de **Elevation of Privilege**

**Template**:
```markdown
## Componente: API de Login

### S - Spoofing
- [ ] Ameaça: [Descrição]
- [ ] Impacto: [Alto/Médio/Baixo]
- [ ] Mitigação: [Como mitigar]

### T - Tampering
- [ ] Ameaça: [Descrição]
- [ ] Impacto: [Alto/Médio/Baixo]
- [ ] Mitigação: [Como mitigar]

[... repetir para R, I, D, E]
```

---

#### Componente: API de Perfil

**Tarefas**:
- [ ] Aplicar STRIDE completo
- [ ] Documentar todas as ameaças
- [ ] Priorizar por impacto

---

#### Componente: Banco de Dados

**Tarefas**:
- [ ] Aplicar STRIDE completo
- [ ] Considerar acesso direto ao banco
- [ ] Considerar backup e restauração

---

### Parte 3: Documentar Ameaças

Crie documento de threat model básico:

**Tarefas**:
- [ ] Listar todas as ameaças encontradas
- [ ] Categorizar por STRIDE
- [ ] Priorizar por impacto
- [ ] Documentar mitigações básicas

---

## Soluções Esperadas

### Exemplos de Ameaças STRIDE

**S - Spoofing**:
- Login sem credenciais válidas
- Falsificação de token de sessão

**T - Tampering**:
- Modificação de dados de perfil
- Alteração de senha sem autorização

**R - Repudiation**:
- Usuário nega ter feito login
- Usuário nega ter atualizado perfil

**I - Information Disclosure**:
- Vazamento de senhas
- Exposição de dados pessoais

**D - Denial of Service**:
- Força bruta bloqueia conta
- Sobrecarga de servidor

**E - Elevation of Privilege**:
- Usuário comum acessa dados de admin
- Bypass de autenticação

---

## Dicas

1. **Seja sistemático**: Passe por cada categoria STRIDE
2. **Pense como atacante**: Como você atacaria?
3. **Documente tudo**: Mesmo ameaças óbvias
4. **Priorize**: Foque nas mais críticas primeiro

---

## Próximos Passos

Após completar este exercício, você estará preparado para:
- Exercício 1.4.2: Identificar Ameaças Avançadas
- Exercício 1.4.3: Análise de Riscos
- Aplicar STRIDE em projetos reais

---

**Duração Estimada**: 45-60 minutos  
**Nível**: Básico  
**Pré-requisitos**: Aula 1.4 (Threat Modeling)
