# 📐 Estrutura Padrão de Aulas - Análise e Padronização

## 🎯 Objetivo

Este documento define a estrutura padrão que todas as aulas dos módulos 1, 2, 3 e 4 devem seguir, baseado na análise das aulas do Módulo 1 (que são as referências corretas).

---

## ✅ Estrutura Padrão Identificada (Módulo 1)

### 1. Frontmatter (YAML)

```yaml
---
layout: lesson
title: "Aula X.X: [Título Completo]"
slug: slug-url-friendly
module: module-X
lesson_id: lesson-X-X
duration: "XX minutos"
level: "Básico|Intermediário|Avançado"
prerequisites: ["lesson-X-Y"]  # Array de pré-requisitos
exercises:  # Array de referências aos exercícios (não inline)
  - lesson-X-X-exercise-1-nome
  - lesson-X-X-exercise-2-nome
video:  # Objeto com metadados do vídeo
  file: "assets/videos/nome-video.mp4"
  title: "Título do Vídeo"
  thumbnail: "assets/images/thumbnail.png"
  description: "Descrição do vídeo"
  duration: "XX-XX minutos"
image: "assets/images/podcasts/X.X-Imagem.png"  # Opcional
permalink: /modules/slug-modulo/lessons/slug-aula/
---
```

### 2. Estrutura do Conteúdo

#### A. Cabeçalho e Objetivos
```markdown
# Aula X.X: [Título Completo]

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- [Lista de objetivos específicos e mensuráveis]
- [Usar verbo de ação: Compreender, Aplicar, Criar, etc.]
```

#### B. Introdução ao Tema
```markdown
## 📚 Introdução ao [Tema]

### O que é [Tema]?

**Definição concisa**: [Tema] é...

#### 🎭 Analogia: [Título da Analogia]

**Cenário 1 (Negativo)**: ...
**Cenário 2 (Positivo)**: ...

### Por que [Tema] é Importante?

#### [Título da Seção de Benefícios]

[Dados e estatísticas quando aplicável]

#### Benefícios do [Tema]

| Benefício | Descrição | Impacto |
|-----------|-----------|---------|
| ... | ... | ... |

### Contexto Histórico (quando aplicável)

[Linha do tempo ou evolução histórica com diagramas ASCII]
```

#### C. Conceitos Teóricos Detalhados
```markdown
## 🔄 ou 📋 ou 🔟 [Nome da Seção Principal]

### [Nome do Conceito 1]

**Definição**: [Definição técnica precisa]

**Explicação Detalhada**:

[Explicação em múltiplos parágrafos]

#### 🎭 Analogia: [Título]

**Analogia detalhada mapeando para conceito técnico**

**Visualização** (quando aplicável):

```
[Diagrama ASCII detalhado]
```

**Fluxo/Processo** (quando aplicável):

```
[Diagrama de fluxo ASCII]
```

**Exemplo Prático**:

```linguagem
[Código completo e comentado]
```

#### Contexto CWI - Exemplos Hipotéticos (quando aplicável)

> **Nota**: Os exemplos abaixo são cenários hipotéticos criados para fins educacionais.

**Exemplo: Caso [Setor]**:
[Descrição do caso hipotético]
```

#### D. Comparações e Tabelas (quando aplicável)
```markdown
## 🔄 [Tema] vs Outras [Abordagens/Ferramentas]

### Comparação: [Tema A] vs [Tema B] vs [Tema C]

**Tabela Comparativa Detalhada**:

| Aspecto | [Tema A] | [Tema B] | [Tema C] |
|---------|----------|----------|----------|
| ... | ... | ... | ... |

**Análise Detalhada por [Tema]**:

#### [Tema A] - [Características]

**Vantagens**:
- ✅ ...
- ✅ ...

**Desvantagens**:
- ❌ ...
- ❌ ...

**Quando Usar**:
- ✅ ...
```

#### E. Exemplos Práticos Completos
```markdown
## 🛠️ Exemplos Práticos Completos

### Exemplo 1: [Título do Exemplo]

**Contexto**: [Descrição do contexto do exemplo]

**Requisitos** (quando aplicável):
- [Lista de requisitos]

**Código Completo**:

```linguagem
[Código completo, funcional e comentado]
```

**Explicação Detalhada**:

[Explicação passo a passo]

**Saída Esperada** (quando aplicável):

```
[Exemplo de saída]
```
```

#### F. Casos Práticos CWI (Obrigatório para módulos de segurança)
```markdown
## 💼 Casos Práticos CWI

> **Nota**: Os casos abaixo são exemplos hipotéticos criados para fins educacionais, ilustrando como os conceitos podem ser aplicados.

### Caso Hipotético 1: [Título do Caso]

**Contexto**:
[Descrição do contexto hipotético]

**Aplicação de [Tema]**:

**Fase/Etapa 1**:
- [Descrição]

**Fase/Etapa 2**:
- [Descrição]

**Resultado**:
- [Resultado hipotético]

**Lição Aprendida**:
- [Lição aprendida]
```

#### G. Boas Práticas e Anti-padrões
```markdown
## ✅ Padrões e Boas Práticas

### Boas Práticas de [Tema]

1. **[Título da Prática]**
   - **Por quê**: [Razão]
   - **Como**: [Como implementar]
   - **Exemplo**: [Exemplo prático]
   - **Benefício**: [Benefício]

2. **[Próxima Prática]**
   ...

### Anti-padrões Comuns

1. **[Título do Anti-padrão]**
   - **Problema**: [Descrição do problema]
   - **Solução**: [Como resolver]
   - **Impacto**: [Impacto do problema]

2. **[Próximo Anti-padrão]**
   ...
```

#### H. Exercícios Práticos
```markdown
## 🎓 Exercícios Práticos

### Exercício 1: [Título] ([Nível])

**Objetivo**: [Objetivo do exercício]

**Descrição**:
[Descrição detalhada do exercício]

**Arquivo**: `exercises/exercise-X-X-1-slug.md`

---

### Exercício 2: [Título] ([Nível])
...
```

**NOTA**: Exercícios são referenciados no frontmatter, mas descritos brevemente aqui. Arquivos completos ficam em `exercises/`.

#### I. Referências Externas
```markdown
## 📚 Referências Externas
## ou
## 🔗 Referências Externas Validadas

### Documentação Oficial

- **[Título](URL)**: Descrição do recurso

### Artigos e Tutoriais

- **[Título](URL)**: Descrição

### Ferramentas e Recursos

- **[Título](URL)**: Descrição

### Comunidade (quando aplicável)

- **[Título](URL)**: Descrição

### Laboratórios Práticos (quando aplicável)

- **[Título](URL)**: Descrição
```

#### J. Resumo e Próximos Passos
```markdown
## 📝 Resumo

### Principais Conceitos

- **[Conceito 1]**: [Definição breve]
- **[Conceito 2]**: [Definição breve]
- ...

### Pontos-Chave para Lembrar

- ✅ **[Ponto importante 1]**
- ✅ **[Ponto importante 2]**
- ...

### Próximos Passos

- Próxima aula: [Nome da próxima aula]
- Praticar [atividade prática]
- Explorar [tema relacionado]
```

#### K. Checklist de Qualidade
```markdown
## ✅ Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente
- [x] [Item específico da aula]
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias presentes para conceitos abstratos
- [x] Diagramas ASCII para visualização de conceitos complexos
- [x] Exemplos práticos completos e funcionais
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Resumo com pontos principais
```

#### L. Quiz de Verificação de Conhecimento (🔍)

**IMPORTANTE**: O quiz NÃO fica dentro do arquivo `.md` da aula, mas sim no arquivo `_data/quizzes.yml`. O quiz é renderizado automaticamente no final da aula através do layout.

**Estrutura do Quiz no `_data/quizzes.yml`**:

```yaml
quizzes:
  - lesson_id: lesson-X-X  # DEVE corresponder ao lesson_id da aula
    questions:
      - id: q1
        question: "Pergunta completa e clara?"
        options:
          - "Opção 1"
          - "Opção 2 (correta)"
          - "Opção 3"
          - "Opção 4"
        correct: 1  # Índice da opção correta (0-based)
        explanation: "Explicação detalhada da resposta correta e por que as outras estão erradas."
      
      - id: q2
        question: "Outra pergunta?"
        options:
          - "Opção A"
          - "Opção B"
          - "Opção C (correta)"
          - "Opção D"
        correct: 2
        explanation: "Explicação da resposta correta."
      
      # ... total de 10 perguntas por aula
```

**Regras para Quizes**:
- ✅ **10 perguntas por aula** (padrão)
- ✅ Perguntas devem testar conceitos principais da aula
- ✅ Cada pergunta deve ter **4 opções**
- ✅ A opção correta (`correct`) deve ser o **índice 0-based** (0, 1, 2, ou 3)
- ✅ `explanation` deve explicar por que a resposta está correta E por que as outras estão erradas
- ✅ Perguntas devem variar em dificuldade (algumas básicas, algumas avançadas)
- ✅ O `lesson_id` no quiz DEVE corresponder exatamente ao `lesson_id` da aula no frontmatter

**Exemplo de Pergunta Bem Estruturada**:

```yaml
- id: q1
  question: "O que é SAST (Static Application Security Testing)?"
  options:
    - "Teste de segurança que analisa código em execução"
    - "Teste de segurança que analisa código-fonte sem executar a aplicação"
    - "Teste de segurança que verifica dependências vulneráveis"
    - "Teste de segurança que simula ataques em produção"
  correct: 1
  explanation: "SAST (Static Application Security Testing) analisa o código-fonte estático, sem executar a aplicação. Isso permite identificar vulnerabilidades cedo no ciclo de desenvolvimento. A opção 1 descreve DAST, a opção 3 descreve SCA, e a opção 4 descreve pentest."
```

**Onde criar o Quiz**:
- Arquivo: `/crescidos-qualidade/_data/quizzes.yml`
- Localizar seção do módulo correspondente
- Adicionar entrada com `lesson_id` correto
- Criar 10 perguntas seguindo estrutura acima

**Validação**:
- [ ] Quiz criado no `_data/quizzes.yml`
- [ ] `lesson_id` corresponde ao da aula
- [ ] Exatamente 10 perguntas
- [ ] Todas as perguntas têm 4 opções
- [ ] `correct` está entre 0-3 (índices válidos)
- [ ] Todas as perguntas têm `explanation` completa
- [ ] Perguntas cobrem conceitos principais da aula

#### M. Navegação (Links)
```markdown
---

**Aula Anterior**: [Aula X.Y: Título](./lesson-X-Y.md)  
**Próxima Aula**: [Aula X.Z: Título](./lesson-X-Z.md)  
**Voltar ao Módulo**: [Módulo X: Título do Módulo](../index.md)
```

**NOTA**: O quiz será renderizado automaticamente ANTES dos links de navegação através do layout `lesson.html`.

---

## 📊 Análise de Conformidade por Módulo

### Módulo 1 ✅ (Referência)

**Status**: ✅ **PADRONIZADO**

Todas as aulas do módulo 1 seguem a estrutura padrão:
- ✅ Frontmatter completo (exercises, video)
- ✅ Objetivos de Aprendizado (🎯)
- ✅ Introdução com analogias (📚)
- ✅ Conceitos teóricos detalhados
- ✅ Casos Práticos CWI (💼)
- ✅ Checklists (✅)
- ✅ Referências externas (🔗)
- ✅ Links de navegação completos

**Aulas analisadas**: lesson-1-1, lesson-1-2, lesson-1-3, lesson-1-4, lesson-1-5

---

### Módulo 2 ⚠️ (Necessita Ajustes)

**Status**: ⚠️ **PARCIALMENTE CONFORME** - Necessita ajustes

#### Aula 2.1 (SAST) - ✅ RECÉM CRIADA/REESCRITA
**Conformidade**: ✅ **95% Conforme**

✅ Tem:
- Frontmatter (falta exercises e video no frontmatter)
- Objetivos de Aprendizado (🎯)
- Introdução com contexto histórico (📚)
- Conceitos teóricos detalhados (🔍)
- Exemplos práticos completos (🛠️)
- Boas práticas e anti-padrões (✅)
- Exercícios práticos (🎓) - mas não referenciados no frontmatter
- Referências externas (📚)
- Resumo (📝)
- Checklist (✅)
- Links de navegação

❌ Falta:
- Seção dedicada "💼 Casos Práticos CWI" (tem conteúdo mas não em seção dedicada)
- Frontmatter completo (exercises: [], video: {})

#### Aula 2.2 (DAST) - ❌ NECESSITA REWRITE COMPLETO
**Conformidade**: ❌ **0% Conforme** - Conteúdo sobre Angular Router

**Problemas**:
- ❌ Conteúdo completamente errado (Angular Router ao invés de DAST)
- ❌ Estrutura não segue padrão
- ❌ Falta todos os elementos obrigatórios

#### Aula 2.3 (Pentest) - ❌ NECESSITA REWRITE COMPLETO
**Conformidade**: ❌ **0% Conforme** - Conteúdo sobre Angular Forms

**Problemas**:
- ❌ Conteúdo completamente errado (Angular Forms ao invés de Pentest)
- ❌ Estrutura não segue padrão
- ❌ Falta todos os elementos obrigatórios

#### Aula 2.4 (Automação) - ❌ NECESSITA REWRITE COMPLETO
**Conformidade**: ❌ **0% Conforme** - Conteúdo sobre Angular HttpClient

**Problemas**:
- ❌ Conteúdo completamente errado (Angular HttpClient ao invés de Automação de Testes de Segurança)
- ❌ Estrutura não segue padrão
- ❌ Falta todos os elementos obrigatórios

#### Aula 2.5 (SCA) - ❌ NECESSITA REWRITE COMPLETO
**Conformidade**: ❌ **0% Conforme** - Conteúdo sobre Angular Components

**Problemas**:
- ❌ Conteúdo completamente errado (Comunicação entre Componentes ao invés de Dependency Scanning)
- ❌ Estrutura não segue padrão
- ❌ Falta todos os elementos obrigatórios

---

### Módulo 3 ⚠️ (Necessita Verificação)

**Status**: ⚠️ **VERIFICAR** - Parece ter conteúdo sobre Angular (RxJS) quando deveria ser sobre segurança

**Aulas encontradas**:
- lesson-3-1.md: RxJS Operators (conteúdo parece Angular, não segurança)
- lesson-3-2.md, lesson-3-3.md, lesson-3-4.md, lesson-3-5.md

**Estrutura observada**:
- ✅ Tem Objetivos de Aprendizado
- ✅ Tem Introdução
- ✅ Tem Conceitos Teóricos
- ⚠️ **VERIFICAR**: Conteúdo parece sobre Angular, não sobre segurança em QA

**Ação necessária**: Verificar se módulo 3 está correto ou se também precisa reescrita.

---

### Módulo 4 ✅ (Parece Conforme)

**Status**: ✅ **PARECE CONFORME** - Estrutura observada segue padrão

**Aulas encontradas**:
- lesson-4-1.md: DevSecOps (estrutura parece correta)
- lesson-4-2.md, lesson-4-3.md, lesson-4-4.md, lesson-4-5.md

**Estrutura observada**:
- ✅ Tem Objetivos de Aprendizado (🎯)
- ✅ Tem Introdução (📚)
- ✅ Tem Casos Práticos CWI (💼)
- ✅ Tem Resumo (📝)
- ✅ Tem Recursos Adicionais (📚)

**Ação necessária**: Revisão rápida para confirmar 100% de conformidade.

---

## 🔧 Elementos Obrigatórios vs Opcionais

### Elementos Obrigatórios

1. ✅ **Frontmatter completo** (layout, title, slug, module, lesson_id, duration, level, prerequisites)
2. ✅ **Objetivos de Aprendizado** (🎯) - Lista de 4-7 objetivos específicos
3. ✅ **Introdução ao Tema** (📚) - Com analogia (🎭) e contexto histórico (quando aplicável)
4. ✅ **Conceitos Teóricos** - Pelo menos 3-5 conceitos principais detalhados
5. ✅ **Exemplos Práticos** (🛠️) - Mínimo 3 exemplos completos e funcionais
6. ✅ **Boas Práticas e Anti-padrões** (✅) - Mínimo 8-10 boas práticas e 5-8 anti-padrões
7. ✅ **Exercícios Práticos** (🎓) - Mínimo 3 exercícios ordenados por dificuldade
8. ✅ **Referências Externas** (📚 ou 🔗) - Organizadas por categoria
9. ✅ **Resumo** (📝) - Com principais conceitos e pontos-chave
10. ✅ **Checklist de Qualidade** (✅)
11. ✅ **Quiz de Verificação** (🔍) - **10 perguntas no arquivo `_data/quizzes.yml`** vinculado por `lesson_id`
12. ✅ **Links de Navegação** - Aula anterior, próxima, voltar ao módulo
13. ✅ **Casos Práticos CWI** (💼) - OBRIGATÓRIO para módulos de segurança (1, 2, 4)

### Elementos Opcionais (mas Recomendados)

1. ⭐ **Comparações com Outras Abordagens** - Quando aplicável
2. ⭐ **Tabelas Comparativas** - Ferramentas, metodologias, etc.
3. ⭐ **Diagramas ASCII Complexos** - Para visualização
4. ⭐ **Laboratórios Práticos** (🧪) - Quando aplicável
5. ⭐ **Métricas** (📊) - Quando aplicável
6. ⭐ **Ferramentas** (🛠️) - Seção dedicada quando há muitas ferramentas

---

## 📋 Checklist de Validação por Aula

Antes de considerar uma aula completa e padronizada, verifique:

### Frontmatter
- [ ] layout: lesson presente
- [ ] title completo e descritivo
- [ ] slug em formato URL-friendly
- [ ] module correto
- [ ] lesson_id no formato lesson-X-X
- [ ] duration especificada
- [ ] level especificado (Básico/Intermediário/Avançado)
- [ ] prerequisites como array (pode ser [])
- [ ] exercises como array (pode ser [])
- [ ] video como objeto (pode ser {} se não houver vídeo)
- [ ] image presente (quando aplicável)
- [ ] permalink correto

### Conteúdo
- [ ] Título da aula (# Aula X.X: ...)
- [ ] Seção 🎯 Objetivos de Aprendizado (4-7 objetivos)
- [ ] Seção 📚 Introdução com analogia 🎭
- [ ] Contexto histórico (quando aplicável) com diagrama ASCII
- [ ] Seção de Conceitos Teóricos com pelo menos 3 conceitos detalhados
- [ ] Cada conceito tem: Definição, Explicação, Analogia, Diagrama (quando aplicável), Exemplo
- [ ] Seção 🛠️ Exemplos Práticos Completos (mínimo 3)
- [ ] Seção 💼 Casos Práticos CWI (OBRIGATÓRIO para segurança)
- [ ] Seção ✅ Padrões e Boas Práticas (8-10 boas práticas, 5-8 anti-padrões)
- [ ] Seção 🎓 Exercícios Práticos (mínimo 3, ordenados por dificuldade)
- [ ] Seção 📚/🔗 Referências Externas (organizadas por categoria)
- [ ] Seção 📝 Resumo (conceitos principais + pontos-chave)
- [ ] Seção ✅ Checklist de Qualidade
- [ ] Links de navegação (Aula Anterior, Próxima, Voltar ao Módulo)

### Quiz (no arquivo `_data/quizzes.yml`)
- [ ] Quiz criado com `lesson_id` correspondente à aula
- [ ] Exatamente 10 perguntas por aula
- [ ] Cada pergunta tem 4 opções
- [ ] `correct` está entre 0-3 (índices válidos)
- [ ] Todas as perguntas têm `explanation` completa e informativa
- [ ] Perguntas cobrem conceitos principais da aula
- [ ] Variação de dificuldade (básicas e avançadas)

### Qualidade do Conteúdo
- [ ] Analogias são claras e mapeiam bem para conceitos técnicos
- [ ] Diagramas ASCII são legíveis e informativos
- [ ] Exemplos de código são completos, funcionais e comentados
- [ ] Tabelas comparativas são completas e precisas
- [ ] Casos CWI são claramente marcados como hipotéticos
- [ ] Referências externas têm URLs válidas e descrições

---

## 🚨 Problemas Identificados

### Módulo 2 - CRÍTICO

#### Problema 1: Conteúdo Incorreto
- **Aula 2.2**: Tem conteúdo sobre Angular Router, deveria ser sobre DAST
- **Aula 2.3**: Tem conteúdo sobre Angular Forms, deveria ser sobre Pentest
- **Aula 2.4**: Tem conteúdo sobre Angular HttpClient, deveria ser sobre Automação de Testes de Segurança
- **Aula 2.5**: Tem conteúdo sobre Angular Components, deveria ser sobre Dependency Scanning (SCA)

**Ação**: Reescrever completamente essas 4 aulas seguindo estrutura padrão.

#### Problema 2: Aula 2.1 Incompleta
- ✅ Conteúdo correto sobre SAST
- ❌ Falta frontmatter completo (exercises, video)
- ⚠️ Falta seção dedicada "💼 Casos Práticos CWI" (tem conteúdo mas misturado)
- ❌ Falta quiz no arquivo `_data/quizzes.yml`

**Ação**: 
- Completar frontmatter e criar seção dedicada de Casos CWI
- Criar quiz completo (10 perguntas) no arquivo `_data/quizzes.yml` com `lesson_id: lesson-2-1`

#### Problema 3: Quizes Faltando
- ❌ Módulo 2: Nenhum quiz criado (todas as aulas precisam de quiz)
- ⚠️ Verificar módulos 3 e 4 se têm quizes para todas as aulas

**Ação**: Criar quizes completos para todas as aulas de todos os módulos.

---

## ✅ Plano de Ação

### Prioridade 1: Corrigir Módulo 2

1. **Aula 2.1 (SAST)** - ✅ Já reescrita, precisa apenas:
   - [ ] Completar frontmatter (exercises, video)
   - [ ] Criar seção dedicada "💼 Casos Práticos CWI"
   - [ ] Validar que todos os elementos estão presentes

2. **Aula 2.2 (DAST)** - ❌ Reescrever completamente:
   - [ ] Remover todo conteúdo sobre Angular Router
   - [ ] Criar conteúdo completo sobre DAST seguindo estrutura padrão
   - [ ] Adicionar analogias, diagramas, exemplos práticos
   - [ ] Criar casos práticos CWI

3. **Aula 2.3 (Pentest)** - ❌ Reescrever completamente:
   - [ ] Remover todo conteúdo sobre Angular Forms
   - [ ] Criar conteúdo completo sobre Pentest Básico
   - [ ] Seguir estrutura padrão

4. **Aula 2.4 (Automação)** - ❌ Reescrever completamente:
   - [ ] Remover todo conteúdo sobre Angular HttpClient
   - [ ] Criar conteúdo sobre Automação de Testes de Segurança
   - [ ] Seguir estrutura padrão

5. **Aula 2.5 (SCA)** - ❌ Reescrever completamente:
   - [ ] Remover todo conteúdo sobre Angular Components
   - [ ] Criar conteúdo sobre Dependency Scanning e SCA
   - [ ] Seguir estrutura padrão

### Prioridade 2: Verificar Módulo 3

- [ ] Verificar se módulo 3 está correto (parece sobre Angular, pode ser outro contexto)
- [ ] Se incorreto, reescrever seguindo estrutura padrão

### Prioridade 3: Validar Módulo 4

- [ ] Revisar todas as aulas do módulo 4
- [ ] Confirmar conformidade 100% com estrutura padrão
- [ ] Ajustar se necessário

---

## 📐 Template de Aula Completa

Para referência futura, use este template ao criar novas aulas:

```markdown
---
layout: lesson
title: "Aula X.X: [Título Completo]"
slug: slug-url-friendly
module: module-X
lesson_id: lesson-X-X
duration: "XX minutos"
level: "Básico|Intermediário|Avançado"
prerequisites: ["lesson-X-Y"]
exercises:
  - lesson-X-X-exercise-1-nome
  - lesson-X-X-exercise-2-nome
video:
  file: "assets/videos/nome-video.mp4"
  title: "Título do Vídeo"
  thumbnail: "assets/images/thumbnail.png"
  description: "Descrição do vídeo"
  duration: "XX-XX minutos"
image: "assets/images/podcasts/X.X-Imagem.png"
permalink: /modules/slug-modulo/lessons/slug-aula/
---

# Aula X.X: [Título Completo]

## 🎯 Objetivos de Aprendizado

Ao final desta aula, você será capaz de:

- [Objetivo 1 específico e mensurável]
- [Objetivo 2 específico e mensurável]
- [Objetivo 3 específico e mensurável]

---

## 📚 Introdução ao [Tema]

### O que é [Tema]?

**Definição**: [Tema] é...

#### 🎭 Analogia: [Título]

[Analogia detalhada]

### Por que [Tema] é Importante?

[Seção de importância]

### Contexto Histórico

[Quando aplicável - linha do tempo com diagrama ASCII]

---

## [Seção Principal de Conceitos]

### [Conceito 1]

**Definição**: ...

**Explicação Detalhada**: ...

#### 🎭 Analogia: ...

[Analogia]

**Visualização**:

```
[Diagrama ASCII]
```

**Exemplo Prático**:

```linguagem
[Código completo]
```

---

## 💼 Casos Práticos CWI

> **Nota**: Os casos abaixo são exemplos hipotéticos criados para fins educacionais.

### Caso Hipotético 1: [Título]

**Contexto**: ...

**Aplicação**: ...

**Resultado**: ...

---

## 🛠️ Exemplos Práticos Completos

### Exemplo 1: [Título]

**Contexto**: ...

**Código**:

```linguagem
[Código completo]
```

---

## ✅ Padrões e Boas Práticas

### Boas Práticas

1. **[Prática]**
   - **Por quê**: ...
   - **Como**: ...
   - **Benefício**: ...

### Anti-padrões Comuns

1. **[Anti-padrão]**
   - **Problema**: ...
   - **Solução**: ...
   - **Impacto**: ...

---

## 🎓 Exercícios Práticos

### Exercício 1: [Título] ([Nível])

**Objetivo**: ...

**Descrição**: ...

**Arquivo**: `exercises/exercise-X-X-1-slug.md`

---

## 📚 Referências Externas

### Documentação Oficial

- **[Título](URL)**: Descrição

### Artigos e Tutoriais

- **[Título](URL)**: Descrição

---

## 📝 Resumo

### Principais Conceitos

- **[Conceito]**: Definição breve

### Pontos-Chave para Lembrar

- ✅ [Ponto importante]

### Próximos Passos

- Próxima aula: [Nome]
- Praticar: [Atividade]

---

## ✅ Checklist de Qualidade

- [x] Introdução clara
- [x] Conceitos detalhados
- [x] Analogias presentes
- [x] Diagramas ASCII
- [x] Exemplos práticos
- [x] Boas práticas documentadas
- [x] Exercícios ordenados
- [x] Referências validadas
- [x] Resumo completo

---

**NOTA IMPORTANTE**: O Quiz será renderizado automaticamente aqui pelo layout. Certifique-se de criar o quiz correspondente no arquivo `_data/quizzes.yml` com o mesmo `lesson_id`.

**Aula Anterior**: [Aula X.Y](./lesson-X-Y.md)  
**Próxima Aula**: [Aula X.Z](./lesson-X-Z.md)  
**Voltar ao Módulo**: [Módulo X](../index.md)
```

---

## 🔍 Sistema de Quiz - Informações Adicionais

### Como o Quiz Funciona

1. **Arquivo de Dados**: Todos os quizes ficam em `_data/quizzes.yml`
2. **Vinculação**: O quiz é vinculado à aula através do campo `lesson_id`
3. **Renderização Automática**: O layout `_layouts/lesson.html` inclui automaticamente o componente `quiz.html` no final da página
4. **Estrutura**: Cada quiz tem exatamente 10 perguntas
5. **JavaScript**: O arquivo `assets/js/quiz.js` gerencia a interatividade

### Localização dos Arquivos

```
crescidos-qualidade/
├── _data/
│   └── quizzes.yml          # ← AQUI ficam todos os quizes
├── _includes/
│   └── quiz.html            # Componente que renderiza o quiz
├── _layouts/
│   └── lesson.html          # Layout que inclui o quiz automaticamente
└── assets/js/
    └── quiz.js              # JavaScript que gerencia o quiz
```

### Processo de Criação de Quiz

1. **Após criar a aula**: Crie o quiz correspondente em `_data/quizzes.yml`
2. **Localização**: Adicione o quiz na seção do módulo correspondente
3. **Validação**: Certifique-se de que o `lesson_id` corresponde exatamente ao da aula
4. **Teste**: Verifique se o quiz aparece corretamente na página da aula

### Exemplo Completo de Quiz no `quizzes.yml`

```yaml
quizzes:
  # ============================================================================
  # MÓDULO X: [Nome do Módulo]
  # ============================================================================
  
  - lesson_id: lesson-X-X  # DEVE corresponder ao lesson_id da aula
    questions:
      - id: q1
        question: "Qual é a principal vantagem do SAST sobre DAST?"
        options:
          - "SAST identifica vulnerabilidades mais rapidamente"
          - "SAST identifica vulnerabilidades sem executar a aplicação, permitindo detecção cedo"
          - "SAST é mais barato que DAST"
          - "SAST não produz false positives"
        correct: 1
        explanation: "SAST analisa código-fonte estático sem executar a aplicação, permitindo identificar vulnerabilidades desde o início do desenvolvimento (Shift-Left). Isso reduz custos de correção drasticamente. SAST pode sim produzir false positives e requer análise manual."
      
      - id: q2
        question: "Qual ferramenta SAST é conhecida por 'rules as code'?"
        options:
          - "SonarQube"
          - "Semgrep"
          - "Checkmarx"
          - "Bandit"
        correct: 1
        explanation: "Semgrep é conhecida por sua abordagem 'rules as code', onde regras de segurança são definidas como código YAML, facilitando criação de regras customizadas. SonarQube é mais completo mas menos flexível, Checkmarx é enterprise, e Bandit é específico para Python."
      
      # ... continuar até 10 perguntas
```

### Boas Práticas para Quizes

1. ✅ **Cobertura**: Questões devem cobrir TODOS os conceitos principais da aula
2. ✅ **Dificuldade Progressiva**: Começar com perguntas básicas, progredir para avançadas
3. ✅ **Opções Realistas**: As opções incorretas devem ser plausíveis (não óbvias demais)
4. ✅ **Explicações Úteis**: A `explanation` deve educar, não apenas confirmar a resposta
5. ✅ **Contexto**: Quando possível, incluir perguntas que relacionem conceitos da aula
6. ✅ **Aplicação Prática**: Incluir perguntas sobre quando usar/quando não usar conceitos

```

---

## 📊 Resumo Executivo

### Status Geral por Módulo

| Módulo | Status | Conformidade | Ação Necessária |
|--------|--------|--------------|-----------------|
| **Módulo 1** | ✅ Padronizado | 100% | ✅ Quizes completos (5/5) - serve como referência |
| **Módulo 2** | ❌ Crítico | 20% | Reescrever 4 aulas (2.2, 2.3, 2.4, 2.5) + Criar 5 quizes (0/5) |
| **Módulo 3** | ⚠️ Verificar | ?% | Verificar conteúdo + Criar quizes (0/5) |
| **Módulo 4** | ✅ Parece OK | ~90% | Validação final + Criar quizes (0/5) |

### Status de Quizes

| Módulo | Aulas com Quiz | Total de Aulas | Status |
|--------|----------------|----------------|--------|
| **Módulo 1** | ✅ 5/5 | 5 | ✅ Completo |
| **Módulo 2** | ❌ 0/5 | 5 | ❌ Nenhum quiz criado |
| **Módulo 3** | ❌ 0/5 | 5 | ❌ Nenhum quiz criado |
| **Módulo 4** | ❌ 0/5 | 5 | ❌ Nenhum quiz criado |

### Priorização

1. **URGENTE**: Módulo 2 - Aulas 2.2, 2.3, 2.4, 2.5 têm conteúdo completamente errado
2. **URGENTE**: Criar Quizes - Módulos 2, 3 e 4 não têm nenhum quiz (15 quizes faltando)
3. **IMPORTANTE**: Verificar Módulo 3 - Pode ter mesmo problema de conteúdo incorreto
4. **DESEJÁVEL**: Validar Módulo 4 completamente

### Checklist de Quiz por Módulo

**Módulo 2 - Quizes Faltando**:
- [ ] Quiz lesson-2-1 (SAST) - Criar 10 perguntas
- [ ] Quiz lesson-2-2 (DAST) - Criar 10 perguntas (após reescrever aula)
- [ ] Quiz lesson-2-3 (Pentest) - Criar 10 perguntas (após reescrever aula)
- [ ] Quiz lesson-2-4 (Automação) - Criar 10 perguntas (após reescrever aula)
- [ ] Quiz lesson-2-5 (SCA) - Criar 10 perguntas (após reescrever aula)

**Módulo 3 - Quizes Faltando**:
- [ ] Quiz lesson-3-1 - Criar 10 perguntas (após verificar/corrigir conteúdo)
- [ ] Quiz lesson-3-2 - Criar 10 perguntas (após verificar/corrigir conteúdo)
- [ ] Quiz lesson-3-3 - Criar 10 perguntas (após verificar/corrigir conteúdo)
- [ ] Quiz lesson-3-4 - Criar 10 perguntas (após verificar/corrigir conteúdo)
- [ ] Quiz lesson-3-5 - Criar 10 perguntas (após verificar/corrigir conteúdo)

**Módulo 4 - Quizes Faltando**:
- [ ] Quiz lesson-4-1 - Criar 10 perguntas
- [ ] Quiz lesson-4-2 - Criar 10 perguntas
- [ ] Quiz lesson-4-3 - Criar 10 perguntas
- [ ] Quiz lesson-4-4 - Criar 10 perguntas
- [ ] Quiz lesson-4-5 - Criar 10 perguntas

---

**Documento criado em**: [Data]  
**Última atualização**: [Data]  
**Responsável**: Análise estrutural completa das aulas