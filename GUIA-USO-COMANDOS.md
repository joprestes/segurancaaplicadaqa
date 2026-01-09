# 🚀 Guia de Uso dos Comandos para Popular Aulas

Este guia explica como usar os comandos `maker.lesson-detailed` e `tutor.course` para acelerar a criação de conteúdo do curso de Segurança em QA.

---

## 📚 Visão Geral dos Comandos

### 1. maker.lesson-detailed
**Propósito**: Enriquecer aulas básicas/esqueletos em conteúdo profundamente detalhado

**O que faz**:
- ✅ Adiciona analogias didáticas detalhadas
- ✅ Cria diagramas ASCII para visualização
- ✅ Gera tabelas comparativas (com outros frameworks quando relevante)
- ✅ Expande exemplos práticos com código comentado
- ✅ Adiciona boas práticas e anti-padrões
- ✅ Busca referências externas validadas
- ✅ Cria contexto histórico quando aplicável

### 2. tutor.course
**Propósito**: Criar material de apoio para alunos (questionários, exercícios personalizados)

**O que faz**:
- ✅ Analisa o contexto da aula
- ✅ Cria questionários de reforço
- ✅ Gera exercícios práticos personalizados
- ✅ Adiciona explicações alternativas
- ✅ Busca recursos adicionais

---

## 🎯 Workflow Recomendado

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│  1. Criar Aula Esqueleto                           │
│     ├─ Metadados (título, duração, etc)            │
│     ├─ Objetivos principais                        │
│     ├─ Tópicos em bullets                          │
│     └─ Conceitos básicos                           │
│                                                     │
│  2. Usar /maker.lesson-detailed                    │
│     └─ Transforma em aula completa com:            │
│        ├─ Analogias detalhadas                     │
│        ├─ Diagramas ASCII                          │
│        ├─ Tabelas comparativas                     │
│        ├─ Exemplos práticos completos              │
│        └─ Boas práticas e anti-padrões             │
│                                                     │
│  3. (Opcional) Usar /tutor.course                  │
│     └─ Cria material complementar:                 │
│        ├─ Questionários de reforço                 │
│        ├─ Exercícios práticos extras               │
│        └─ Recursos de aprofundamento               │
│                                                     │
│  4. Revisar e Ajustar                              │
│     └─ Adicionar contexto específico CWI           │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## 📝 Exemplo Prático: Aula 1.2 OWASP Top 10

### Passo 1: Aula Esqueleto (Já criada)

Criamos `lesson-1-2-esqueleto.md` com:
- ✅ Estrutura básica
- ✅ Lista das 10 vulnerabilidades
- ✅ Descrições curtas
- ✅ Sem analogias, sem diagramas, sem exemplos detalhados

### Passo 2: Usando o Comando maker.lesson-detailed

**Comando a executar**:

```
/maker.lesson-detailed 
  --file=modules/module-1/lessons/lesson-1-2-esqueleto.md 
  --theme="Segurança em QA"
  --level=profundo
  --comparisons=sim
  --search=sim
  --output=sobrescrever
```

**Parâmetros explicados**:
- `--file`: Caminho do arquivo esqueleto
- `--theme`: Tema principal (usado para contexto e buscas)
- `--level`: profundo (máximo detalhamento)
- `--comparisons`: sim (criar tabelas comparativas)
- `--search`: sim (buscar referências na internet)
- `--output`: sobrescrever (salva no mesmo arquivo)

### Passo 3: O que o Comando Vai Adicionar

#### 3.1 Analogias Detalhadas

Para **cada vulnerabilidade**, o comando criará analogias como:

**Exemplo: SQL Injection**
```markdown
#### 🎭 Analogia: A Biblioteca Enganada

Imagine uma biblioteca com um atendente que busca livros baseado no que você escreve num papel.

**Cenário Normal**:
Você escreve: "Livro de Python"
Atendente busca: "Livro de Python"
Resultado: Recebe o livro correto ✅

**Cenário de Ataque (SQL Injection)**:
Você escreve: "Livro de Python' OR '1'='1"
Atendente busca: "Livro de Python' OR '1'='1"
Resultado: Recebe TODOS os livros da biblioteca! ❌

O atendente (banco de dados) foi enganado porque não validou a entrada.
```

#### 3.2 Diagramas ASCII

**Exemplo: Fluxo de SQL Injection**
```
┌─────────────────────────────────────────────────────────┐
│  FLUXO DE SQL INJECTION                                 │
│                                                         │
│  Cliente                    Aplicação        Banco      │
│    │                            │              │        │
│    │─────"user' OR '1'='1"─────>│              │        │
│    │                            │              │        │
│    │                            │──SELECT * ──>│        │
│    │                            │   FROM users │        │
│    │                            │   WHERE name │        │
│    │                            │   = 'user'   │        │
│    │                            │   OR '1'='1' │        │
│    │                            │              │        │
│    │                            │<─TODOS USERS─┤        │
│    │                            │              │        │
│    │<───DADOS VAZADOS──────────│              │        │
│    │                                                    │
└─────────────────────────────────────────────────────────┘

SOLUÇÃO: Usar Prepared Statements / Parametrized Queries
```

#### 3.3 Tabelas Comparativas

**Exemplo: Comparação de Vulnerabilidades por Setor**
```markdown
| Vulnerabilidade | Financeiro | Educacional | Ecommerce | Criticidade |
|----------------|------------|-------------|-----------|-------------|
| Broken Access Control | CRÍTICA | CRÍTICA | ALTA | Acesso a contas |
| SQL Injection | CRÍTICA | ALTA | CRÍTICA | Vazamento de dados |
| XSS | ALTA | CRÍTICA | ALTA | Roubo de sessão |
| CSRF | CRÍTICA | MÉDIA | CRÍTICA | Transações não autorizadas |
```

#### 3.4 Exemplos Práticos Completos

**Exemplo: Código Vulnerável vs Seguro**
```markdown
### SQL Injection - Código Vulnerável ❌

```python
# VULNERÁVEL - Nunca faça isso!
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

# Ataque possível:
# username = "admin' OR '1'='1' --"
# Query executada: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'
# Resultado: Retorna TODOS os usuários!
```

### SQL Injection - Código Seguro ✅

```python
# SEGURO - Use prepared statements
def get_user(username):
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (username,))

# Mesmo com ataque:
# username = "admin' OR '1'='1' --"
# Query busca literalmente por um usuário com esse nome (que não existe)
# Resultado: Nenhum usuário retornado ✅
```

**Contexto CWI - Cliente Financeiro**:
Em um dos projetos financeiros da CWI, identificamos SQL Injection em endpoint de 
consulta de extratos. A correção usando prepared statements evitou exposição de 
dados bancários de 500k+ usuários.
```

#### 3.5 Boas Práticas e Anti-padrões

```markdown
## ✅ Boas Práticas

### Prevenção de SQL Injection

1. **SEMPRE use Prepared Statements**
   - Por quê: Separa código de dados
   - Quando: 100% das queries SQL
   - Benefício: Impossível injetar SQL malicioso

2. **Validação de Entrada**
   - Por quê: Defense in depth
   - Quando: Todo input do usuário
   - Benefício: Camada extra de proteção

3. **Princípio do Menor Privilégio**
   - Por quê: Limita impacto de exploits
   - Quando: Configuração do BD
   - Benefício: Mesmo com injection, dano limitado

## ❌ Anti-padrões Comuns

### 1. "Sanitização" Manual com Replace
```python
# ANTI-PADRÃO - Não funciona!
username = username.replace("'", "")  # ❌ Facilmente contornável
```

**Por que é problemático**:
- Atacantes podem usar encoding (hex, unicode)
- Não cobre todos os casos
- Falsa sensação de segurança

**Solução correta**: Prepared Statements sempre
```

#### 3.6 Referências Validadas

O comando buscará e validará:
- Documentação oficial OWASP
- Artigos técnicos recentes
- Ferramentas para testar cada vulnerabilidade
- Casos de estudo reais
- Laboratórios práticos (WebGoat, Juice Shop)

---

## 🎓 Exemplo Completo de Output

Após executar o comando, a aula ficará assim:

```markdown
# Aula 1.2: OWASP Top 10 e Principais Vulnerabilidades

## 🎯 Objetivos de Aprendizado
[Expandido com objetivos específicos e mensuráveis]

## 📚 Introdução
[Contexto histórico do OWASP Top 10, evolução das versões]

## 🔟 As 10 Vulnerabilidades Críticas

### 1. Broken Access Control

#### Definição Técnica Completa
[3-4 parágrafos detalhados]

#### 🎭 Analogia: O Porteiro Distraído
[Analogia detalhada mundo real → conceito técnico]

#### Diagrama de Ataque
[Diagrama ASCII mostrando o fluxo]

#### Exemplos Práticos
[Código vulnerável + código seguro + explicação linha por linha]

#### Contexto CWI
[Exemplo real de projeto financeiro/educacional/ecommerce]

#### Como Testar
[Casos de teste específicos]

#### Prevenção
[Checklist de boas práticas]

---
[Repetir estrutura para todas as 10 vulnerabilidades]
---

## 💼 Aplicação por Setor CWI

### Financeiro
[Priorização de vulnerabilidades, casos específicos]

### Educacional
[Vulnerabilidades críticas para dados de menores]

### Ecommerce
[Foco em transações e dados de pagamento]

## 🧪 Laboratório Prático

### Setup
[Como configurar ambiente de testes]

### Exercício 1: SQL Injection
[Passo a passo para explorar e corrigir]

### Exercício 2: XSS
[Passo a passo para explorar e corrigir]

[...]

## 📊 Tabela de Referência Rápida
[Resumo de todas as vulnerabilidades em tabela]

## 🔗 Referências Externas Validadas
[Lista organizada por categoria com descrições]

## 🎯 Próximos Passos
[Conexão com Aula 1.3]
```

---

## 🔄 Passo 4: Usando tutor.course (Opcional)

Após ter a aula completa, você pode criar material de apoio:

**Comando**:
```
/tutor.course 
  --lesson=modules/module-1/lessons/lesson-1-2.md
  --type=completo
  --level=intermediario
```

**Vai gerar**:
- 📝 Questionário de 10-15 questões (múltipla escolha + práticas)
- 💻 3-5 exercícios práticos adicionais
- 📚 Material complementar personalizado
- 🎯 Checklist de conceitos para revisar

---

## 📋 Checklist de Criação de Aula

Use este workflow para cada aula:

### ✅ Fase 1: Esqueleto (15-30 min)
- [ ] Criar arquivo .md com metadados
- [ ] Definir objetivos principais
- [ ] Listar tópicos/conceitos principais
- [ ] Adicionar descrições básicas (1-2 linhas cada)

### ✅ Fase 2: Enriquecimento (Automático com comando)
- [ ] Executar `/maker.lesson-detailed`
- [ ] Revisar conteúdo gerado
- [ ] Ajustar analogias se necessário
- [ ] Validar exemplos de código
- [ ] Adicionar contexto CWI específico

### ✅ Fase 3: Material de Apoio (Opcional)
- [ ] Executar `/tutor.course` se necessário
- [ ] Revisar questionários
- [ ] Validar exercícios

### ✅ Fase 4: Finalização (15-30 min)
- [ ] Adicionar casos específicos CWI
- [ ] Revisar links e referências
- [ ] Testar exemplos de código
- [ ] Criar exercícios no formato do curso

---

## 🚀 Produtividade Esperada

### Sem Comandos (Manual)
- ⏱️ Aula completa: **4-6 horas**
- 📝 24 aulas restantes: **96-144 horas** (12-18 dias úteis)

### Com Comandos
- ⏱️ Esqueleto: **15-30 min**
- 🤖 Comando enriquece: **5-10 min**
- ✏️ Revisão/ajustes: **30-45 min**
- **Total por aula: 50-85 min** (1-1.5h)
- 📝 24 aulas restantes: **24-36 horas** (3-4 dias úteis)

**Ganho de produtividade: 70-75% de redução de tempo** ⚡

---

## 💡 Dicas de Uso dos Comandos

### 1. Qualidade do Esqueleto
Quanto melhor o esqueleto, melhor o resultado:
- ✅ Liste todos os conceitos principais
- ✅ Indique quando quer analogias (`[analogia necessária]`)
- ✅ Marque onde quer diagramas (`[diagrama de fluxo]`)
- ✅ Sugira contextos CWI específicos

### 2. Iteração
Você pode executar o comando múltiplas vezes:
1. Primeira execução: enriquecimento geral
2. Segunda execução: focar em seção específica
3. Terceira execução: adicionar mais exemplos

### 3. Personalização
Após o comando gerar, adicione:
- 🏢 Casos reais específicos de projetos CWI
- 💼 Exemplos com nomes de clientes (anonimizados)
- 🎯 Lições aprendidas de experiências reais

### 4. Combinação de Comandos
```
Esqueleto → maker.lesson-detailed → tutor.course → Aula Completa + Material de Apoio
```

---

## 📊 Template de Esqueleto Rápido

Use este template para criar esqueletos rapidamente:

```markdown
---
layout: lesson
title: "Aula X.Y: [TÍTULO]"
slug: [slug-da-aula]
module: module-X
lesson_id: lesson-X-Y
duration: "[XX] minutos"
level: "[Básico|Intermediário|Avançado]"
prerequisites: ["lesson-X-Z"]
exercises: []
podcast:
  file: "assets/podcasts/X.Y-[Slug].m4a"
  image: "assets/images/podcasts/X.Y-[Slug].png"
  title: "[Título do Podcast]"
  description: "[Descrição]"
  duration: "XX-YY minutos"
permalink: /modules/[module-slug]/lessons/[lesson-slug]/
---

# Aula X.Y: [TÍTULO]

## 🎯 Objetivos
- Objetivo 1
- Objetivo 2
- Objetivo 3

## 📚 Conceitos Principais

### Conceito 1: [Nome]
Descrição breve do conceito.
[analogia necessária]
[diagrama de fluxo]

**Exemplo prático**:
[código básico ou exemplo]

### Conceito 2: [Nome]
Descrição breve do conceito.
[tabela comparativa com outros conceitos]

### Conceito 3: [Nome]
Descrição breve do conceito.

## 💼 Aplicação CWI
- Contexto em projetos financeiros
- Contexto em projetos educacionais
- Contexto em projetos ecommerce

## 🎯 Exercícios
1. Exercício conceitual
2. Exercício prático
3. Exercício de aplicação

## 📖 Referências
- [Link OWASP ou documentação oficial]
```

---

## ✨ Próximos Passos

1. **Criar esqueletos das 24 aulas restantes** usando o template
   - Foco em listar conceitos principais
   - Marcar onde quer analogias/diagramas
   
2. **Executar maker.lesson-detailed em lote**
   - Pode processar múltiplas aulas sequencialmente
   
3. **Revisar e personalizar**
   - Adicionar contexto CWI específico
   - Validar exemplos
   
4. **(Opcional) Gerar material de apoio**
   - Usar tutor.course para questionários e exercícios extras

---

## 🎓 Conclusão

Os comandos **maker.lesson-detailed** e **tutor.course** são ferramentas poderosas que:

✅ Reduzem em 70-75% o tempo de criação de conteúdo  
✅ Mantêm qualidade e consistência  
✅ Adicionam elementos pedagógicos (analogias, diagramas)  
✅ Buscam referências atualizadas automaticamente  
✅ Permitem foco no que importa: contexto CWI específico  

**Resultado**: Curso completo de 40 horas criado em 3-4 dias ao invés de 2-3 semanas! 🚀
