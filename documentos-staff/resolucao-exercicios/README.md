# 📋 Gabaritos e Soluções de Exercícios

**Documentação para Instrutores e Monitores**

Este diretório contém os gabaritos completos e soluções detalhadas de todos os exercícios práticos do curso de Segurança em QA.

---

## 📁 Organização

Os gabaritos estão organizados por **Módulo** → **Lesson (Aula)** → **Exercise (Exercício)**:

```
resolucao-exercicios/
├── modulo-1/                    # Fundamentos de Segurança em QA
│   ├── lesson-1-1/              # Introdução à Segurança em QA
│   │   └── exercise-1-[nome].md
│   ├── lesson-1-2/              # OWASP Top 10
│   │   ├── exercise-1-identificar-vulnerabilidades.md
│   │   ├── exercise-2-sql-injection.md
│   │   ├── exercise-4-broken-access-control.md
│   │   └── exercise-5-owasp-checklist.md
│   ├── lesson-1-3/              # Shift-Left Security
│   ├── lesson-1-4/              # Threat Modeling
│   └── lesson-1-5/              # Compliance e Regulamentações
├── modulo-2/                    # Testes de Segurança na Prática (futuro)
├── modulo-3/                    # Segurança por Setor (futuro)
└── modulo-4/                    # DevSecOps e Automação (futuro)
```

---

## 📄 Estrutura Padrão dos Gabaritos

Cada arquivo de gabarito segue a seguinte estrutura:

### 1. Cabeçalho (Frontmatter)
```yaml
---
exercise_id: lesson-1-2-exercise-1-identificar-vulnerabilidades
title: "Exercício 1.2.1: Identificar Vulnerabilidades OWASP Top 10"
lesson_id: lesson-1-2
module: module-1
difficulty: "Básico"
last_updated: 2025-01-09
---
```

### 2. Enunciado Completo
Cópia do exercício como aparece para os alunos (para referência rápida).

### 3. Soluções Detalhadas
Respostas completas e explicadas, com:
- **Solução Esperada**: Resposta direta
- **Explicação Detalhada**: Por que essa é a resposta correta
- **Código de Exemplo** (quando aplicável): Código completo e comentado
- **Variações Aceitáveis**: Outras respostas válidas que podem ser aceitas

### 4. Critérios de Avaliação
Pontos a considerar na correção:
- ✅ **Essenciais**: O que é obrigatório na resposta
- ⭐ **Importantes**: O que agrega valor
- 💡 **Bônus**: O que demonstra conhecimento avançado

### 5. Pontos Importantes para Monitores
- **Erros Comuns**: O que os alunos costumam errar
- **Conceitos-Chave**: O que o exercício avalia
- **Dicas para Feedback**: Como dar feedback construtivo
- **Contexto Pedagógico**: Por que este exercício é importante

### 6. Exemplos de Boas Respostas
Referências de respostas exemplares para orientar correção.

---

## 🎯 Como Usar os Gabaritos

### Durante a Correção

1. **Abra o Gabarito Correspondente**
   - Navegue até `modulo-X/lesson-X-Y/exercise-[nome].md`
   - Leia o enunciado completo para contexto

2. **Compare com a Resposta do Aluno**
   - Use os critérios de avaliação como checklist
   - Verifique pontos essenciais vs. importantes vs. bônus

3. **Prepare Feedback**
   - Use os "Pontos Importantes" para orientar feedback
   - Consulte "Erros Comuns" se a resposta estiver incorreta
   - Referencie "Exemplos de Boas Respostas" se necessário

4. **Dê Feedback Construtivo**
   - ✅ Reconheça o que está correto
   - ❌ Aponte o que está incorreto de forma educativa
   - 💡 Sugira melhorias e próximos passos

---

## 📊 Critérios de Avaliação Padrão

Todos os exercícios são avaliados considerando:

### Básico (60-70 pontos)
- ✅ Identifica corretamente a vulnerabilidade/conceito principal
- ✅ Entende o problema básico
- ✅ Aplica conhecimento teórico da aula

### Intermediário (71-85 pontos)
- ✅ Explicação detalhada e clara
- ✅ Identifica múltiplas vulnerabilidades (quando aplicável)
- ✅ Propõe correções seguras
- ✅ Considera contexto prático

### Avançado (86-100 pontos)
- ✅ Análise profunda e completa
- ✅ Identifica vulnerabilidades não óbvias
- ✅ Proposta de correção bem estruturada e detalhada
- ✅ Considera múltiplos contextos (financeiro, educacional, etc.)
- ✅ Demonstra conhecimento além do conteúdo da aula

---

## ⚠️ Importante para Monitores

### ❌ Evite

- Dar a resposta direta sem que o aluno tente
- Criticar apenas sem orientar
- Ignorar tentativas válidas que usam abordagens diferentes
- Ser inflexível com formatação (avaliar conteúdo, não forma)

### ✅ Faça

- Incentive o pensamento crítico
- Reconheça esforço e progresso
- Dê feedback específico e acionável
- Oriente sobre onde encontrar informações
- Seja paciente e educador

---

## 📝 Template de Gabarito

Use este template ao criar novos gabaritos:

```markdown
---
exercise_id: lesson-X-Y-exercise-Z-[nome]
title: "Exercício X.Y.Z: [Título]"
lesson_id: lesson-X-Y
module: module-X
difficulty: "Básico|Intermediário|Avançado"
last_updated: YYYY-MM-DD
---

# [Título do Exercício]

## 📋 Enunciado Completo

[Cópia do enunciado do exercício público]

---

## ✅ Soluções Detalhadas

### Tarefa 1: [Nome da Tarefa]

**Solução Esperada:**
[Resposta direta]

**Explicação Detalhada:**
[Explicação completa e educativa]

**Código de Exemplo** (quando aplicável):
```linguagem
[Código completo e comentado]
```

**Variações Aceitáveis:**
- [Variação 1]: [Quando aceitar]
- [Variação 2]: [Quando aceitar]

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (60 pontos)
- [ ] [Critério essencial 1]
- [ ] [Critério essencial 2]

### ⭐ Importantes (25 pontos)
- [ ] [Critério importante 1]
- [ ] [Critério importante 2]

### 💡 Bônus (15 pontos)
- [ ] [Critério bônus 1]
- [ ] [Critério bônus 2]

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados
- [Conceito 1]
- [Conceito 2]

### Erros Comuns
1. **Erro Comum 1**: [Descrição] → **Feedback**: [Como orientar]
2. **Erro Comum 2**: [Descrição] → **Feedback**: [Como orientar]

### Dicas para Feedback
- ✅ Reconheça: [O que reconhecer]
- ❌ Corrija: [O que corrigir]
- 💡 Incentive: [O que incentivar]

### Contexto Pedagógico
[Por que este exercício é importante e como se conecta com o curso]

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (90-100 pontos)
[Exemplo de resposta exemplar]

### Exemplo 2: Resposta Boa (80-89 pontos)
[Exemplo de resposta boa]

---

**Última atualização**: YYYY-MM-DD  
**Criado por**: [Nome]  
**Revisado por**: [Nome]
```

---

## 📞 Dúvidas?

Para dúvidas sobre gabaritos ou correção:

- **Email**: [A definir]
- **Slack/Teams**: [A definir]
- **Revisão de Gabarito**: [Processo a definir]

---

**Última atualização**: 2025-01-09  
**Versão**: 1.0.0
