# Mapeamento da Estrutura do Módulo 2: Testes de Segurança na Prática

Este documento mapeia detalhadamente a estrutura completa do Módulo 2, incluindo organização de aulas, exercícios, vídeos, infográficos e quizzes.

---

## 📋 Visão Geral do Módulo

- **Título**: Testes de Segurança na Prática
- **Duração Total**: 8 horas
- **Nível**: Intermediário a Avançado
- **Pré-requisitos**: Módulo 1 completo (Fundamentos de Segurança em QA)
- **Total de Aulas**: 5 aulas
- **Total de Exercícios**: *[A ser definido - placeholders preparados]*
- **Total de Quizzes**: *[A ser definido - estrutura para 5 quizzes]*

---

## 🎓 Estrutura das Aulas

Cada aula possui uma estrutura consistente com os seguintes componentes:

### Componentes Padrão de uma Aula

1. **Front Matter (Metadados Jekyll)**
   - `layout: lesson`
   - `title`: Título da aula
   - `slug`: URL slug da aula
   - `module: module-2`
   - `lesson_id`: ID único da aula
   - `duration`: Duração estimada
   - `level`: Nível (Intermediário, Avançado)
   - `prerequisites`: Array de IDs de aulas pré-requisitas
   - `exercises`: Array de IDs de exercícios associados (*[a ser definido]*)
   - `video`: Objeto com informações do vídeo (*[a ser definido]*)
     - `file`: Caminho do arquivo de vídeo
     - `title`: Título do vídeo
     - `thumbnail`: Caminho da thumbnail/miniatura
     - `description`: Descrição (opcional)
     - `duration`: Duração (opcional)
   - `image`: Imagem/thumbnail alternativa (quando vídeo ainda não disponível)
   - `permalink`: URL permanente da aula

2. **Conteúdo da Aula**
   - Título principal
   - Seção de Objetivos de Aprendizado (🎯)
   - Seção de Conteúdo (📚)
   - Infográfico (quando aplicável)
   - Aplicação no Contexto CWI (💼)
   - Material Complementar (📖)
   - Próximos Passos (🎯)

3. **Vídeo da Aula** (*[a ser definido]*)
   - Arquivo de vídeo principal
   - Thumbnail/imagem de capa
   - Descrição opcional

4. **Infográfico** (*[a ser definido]*)
   - Imagem visual explicativa
   - Localizado dentro do conteúdo da aula

5. **Quiz** (*[a ser definido]*)
   - 10 questões por aula
   - Formato de múltipla escolha
   - Cada questão tem:
     - ID único
     - Texto da pergunta
     - 4 opções
     - Índice da resposta correta (0-3)
     - Explicação da resposta correta

---

## 📝 Detalhamento por Aula

### Aula 2.1: SAST: Static Application Security Testing

#### Metadados
- **ID**: `lesson-2-1`
- **Título**: "SAST: Static Application Security Testing"
- **Slug**: `sast-testes-estaticos`
- **Duração**: 90 minutos
- **Nível**: Intermediário
- **Pré-requisitos**: `["lesson-1-5"]`
- **Exercícios associados**: *[A ser definido]*

#### Vídeo
- **Arquivo**: *[A ser definido - placeholder: `assets/videos/2.1-SAST_Testes_Estaticos.mp4`]*
- **Título**: *[A ser definido]*
- **Thumbnail**: *[A ser definido - placeholder: `assets/images/infografico-lesson-2-1.png`]*
- **Imagem atual**: `assets/images/podcasts/2.1-SAST_Testes_Estaticos.png`

#### Infográfico
- **Arquivo**: *[A ser definido - placeholder: `assets/images/infografico-lesson-2-1.png`]*
- **Localização**: Dentro do conteúdo da aula

#### Quiz
- **ID do Quiz**: `lesson-2-1`
- **Total de Questões**: *[A ser definido - estrutura para 10 questões]*
- **Temas das Questões**: *[A ser definido]*

#### Estrutura do Conteúdo
1. Objetivos de Aprendizado
2. Conteúdo:
   - *[Conteúdo da aula a ser desenvolvido]*
3. Aplicação no Contexto CWI
4. Material Complementar
5. Próximos Passos

---

### Aula 2.2: DAST: Dynamic Application Security Testing

#### Metadados
- **ID**: `lesson-2-2`
- **Título**: "DAST: Dynamic Application Security Testing"
- **Slug**: `dast-testes-dinamicos`
- **Duração**: 90 minutos
- **Nível**: Intermediário
- **Pré-requisitos**: `["lesson-2-1"]`
- **Exercícios associados**: *[A ser definido]*

#### Vídeo
- **Arquivo**: *[A ser definido - placeholder: `assets/videos/2.2-DAST_Testes_Dinamicos.mp4`]*
- **Título**: *[A ser definido]*
- **Thumbnail**: *[A ser definido - placeholder: `assets/images/infografico-lesson-2-2.png`]*
- **Imagem atual**: `assets/images/podcasts/2.2-DAST_Testes_Dinamicos.png`

#### Infográfico
- **Arquivo**: *[A ser definido - placeholder: `assets/images/infografico-lesson-2-2.png`]*

#### Quiz
- **ID do Quiz**: `lesson-2-2`
- **Total de Questões**: *[A ser definido - estrutura para 10 questões]*

---

### Aula 2.3: Testes de Penetração (Pentest) Básico

#### Metadados
- **ID**: `lesson-2-3`
- **Título**: "Testes de Penetração (Pentest) Básico"
- **Slug**: `pentest-basico`
- **Duração**: 120 minutos
- **Nível**: Avançado
- **Pré-requisitos**: `["lesson-2-2"]`
- **Exercícios associados**: *[A ser definido]*

#### Vídeo
- **Arquivo**: *[A ser definido - placeholder: `assets/videos/2.3-Pentest_Basico.mp4`]*
- **Título**: *[A ser definido]*
- **Thumbnail**: *[A ser definido - placeholder: `assets/images/infografico-lesson-2-3.png`]*
- **Imagem atual**: `assets/images/podcasts/2.3-Pentest_Basico.png`

#### Infográfico
- **Arquivo**: *[A ser definido - placeholder: `assets/images/infografico-lesson-2-3.png`]*

#### Quiz
- **ID do Quiz**: `lesson-2-3`
- **Total de Questões**: *[A ser definido - estrutura para 10 questões]*

---

### Aula 2.4: Automação de Testes de Segurança

#### Metadados
- **ID**: `lesson-2-4`
- **Título**: "Automação de Testes de Segurança"
- **Slug**: `automacao-testes-seguranca`
- **Duração**: 120 minutos
- **Nível**: Avançado
- **Pré-requisitos**: `["lesson-2-3"]`
- **Exercícios associados**: *[A ser definido]*

#### Vídeo
- **Arquivo**: *[A ser definido - placeholder: `assets/videos/2.4-Automacao_Testes_Seguranca.mp4`]*
- **Título**: *[A ser definido]*
- **Thumbnail**: *[A ser definido - placeholder: `assets/images/infografico-lesson-2-4.png`]*
- **Imagem atual**: `assets/images/podcasts/2.4-Automacao_Testes_Seguranca.png`

#### Infográfico
- **Arquivo**: *[A ser definido - placeholder: `assets/images/infografico-lesson-2-4.png`]*

#### Quiz
- **ID do Quiz**: `lesson-2-4`
- **Total de Questões**: *[A ser definido - estrutura para 10 questões]*

---

### Aula 2.5: Dependency Scanning e SCA

#### Metadados
- **ID**: `lesson-2-5`
- **Título**: "Dependency Scanning e SCA"
- **Slug**: `dependency-scanning-sca`
- **Duração**: 90 minutos
- **Nível**: Intermediário
- **Pré-requisitos**: `["lesson-2-4"]`
- **Exercícios associados**: *[A ser definido]*

#### Vídeo
- **Arquivo**: *[A ser definido - placeholder: `assets/videos/2.5-Dependency_Scanning_SCA.mp4`]*
- **Título**: *[A ser definido]*
- **Thumbnail**: *[A ser definido - placeholder: `assets/images/infografico-lesson-2-5.png`]*
- **Imagem atual**: `assets/images/podcasts/2.5-Dependency_Scanning_SCA.png`

#### Infográfico
- **Arquivo**: *[A ser definido - placeholder: `assets/images/infografico-lesson-2-5.png`]*

#### Quiz
- **ID do Quiz**: `lesson-2-5`
- **Total de Questões**: *[A ser definido - estrutura para 10 questões]*

---

## 🎯 Estrutura dos Exercícios

*[Estrutura preparada - exercícios a serem criados]*

Cada exercício possui uma estrutura padronizada:

### Componentes Padrão de um Exercício

1. **Front Matter (Metadados Jekyll)**
   - `layout: exercise`
   - `title`: Título do exercício
   - `slug`: URL slug do exercício
   - `lesson_id`: ID da aula associada
   - `module`: Módulo (module-2)
   - `difficulty`: Nível de dificuldade (Básico, Intermediário, Avançado)
   - `permalink`: URL permanente
   - `lesson_url`: URL da aula relacionada
   - `video`: Objeto com informações do vídeo (quando aplicável)
     - `file`: Caminho do arquivo
     - `title`: Título
     - `description`: Descrição

2. **Conteúdo do Exercício**
   - Objetivo
   - Descrição
   - Contexto
   - Tarefa/Requisitos
   - Dicas
   - Próximos Passos
   - Formulário de Submissão
   - Duração Estimada

### Vídeos Explicativos de Exercícios

*[Estrutura preparada - vídeos introdutórios a serem criados por aula com exercícios]*

Cada aula com exercícios deve possuir um vídeo introdutório:

- **Formato**: Página especial com layout `exercise`
- **Conteúdo**: Visão geral dos exercícios da aula
- **Componentes**:
  - Vídeo explicativo
  - Lista de exercícios da aula
  - Descrição de cada exercício
  - Dicas para aproveitar os exercícios

---

## 📚 Placeholders para Exercícios por Aula

### Aula 2.1: SAST (*[A ser definido]*)
- **Vídeo Introdutório**: *[A ser criado]*
- **Exercícios**: *[A ser definido - sugestão: 3-5 exercícios práticos de SAST]*

### Aula 2.2: DAST (*[A ser definido]*)
- **Vídeo Introdutório**: *[A ser criado]*
- **Exercícios**: *[A ser definido - sugestão: 3-5 exercícios práticos de DAST]*

### Aula 2.3: Pentest Básico (*[A ser definido]*)
- **Vídeo Introdutório**: *[A ser criado]*
- **Exercícios**: *[A ser definido - sugestão: 4-6 exercícios práticos de pentest]*

### Aula 2.4: Automação de Testes (*[A ser definido]*)
- **Vídeo Introdutório**: *[A ser criado]*
- **Exercícios**: *[A ser definido - sugestão: 4-6 exercícios de automação]*

### Aula 2.5: Dependency Scanning (*[A ser definido]*)
- **Vídeo Introdutório**: *[A ser criado]*
- **Exercícios**: *[A ser definido - sugestão: 3-5 exercícios de SCA]*

---

## 📊 Estrutura dos Quizzes

### Formato dos Quizzes

*[Estrutura preparada - quizzes a serem criados]*

Cada quiz está associado a uma aula e deve conter 10 questões no formato de múltipla escolha.

#### Estrutura de uma Questão

```yaml
- id: q1  # ID único da questão (q1, q2, ..., q10)
  question: "Texto da pergunta"
  options:
    - "Opção 1"
    - "Opção 2"
    - "Opção 3"
    - "Opção 4"
  correct: 0  # Índice da opção correta (0-3)
  explanation: "Explicação da resposta correta"
```

#### Distribuição de Quizzes

| Aula | ID do Quiz | Total de Questões | Arquivo |
|------|------------|-------------------|---------|
| 2.1 | `lesson-2-1` | *[A ser criado - 10 questões]* | `_data/quizzes.yml` |
| 2.2 | `lesson-2-2` | *[A ser criado - 10 questões]* | `_data/quizzes.yml` |
| 2.3 | `lesson-2-3` | *[A ser criado - 10 questões]* | `_data/quizzes.yml` |
| 2.4 | `lesson-2-4` | *[A ser criado - 10 questões]* | `_data/quizzes.yml` |
| 2.5 | `lesson-2-5` | *[A ser criado - 10 questões]* | `_data/quizzes.yml` |

**Total**: *[A ser criado - 50 questões distribuídas em 5 quizzes]*

---

## 📁 Estrutura de Arquivos e Diretórios

### Diretório Raiz do Módulo
```
modules/module-2/
├── index.md                    # Página principal do módulo ✅
├── summary.md                  # *[A ser criado - Resumo do módulo]*
└── lessons/                    # Aulas do módulo
    ├── lesson-2-1.md          # Aula 2.1 ✅
    ├── lesson-2-2.md          # Aula 2.2 ✅
    ├── lesson-2-3.md          # Aula 2.3 ✅
    ├── lesson-2-4.md          # Aula 2.4 ✅
    ├── lesson-2-5.md          # Aula 2.5 ✅
    └── exercises/             # *[A ser criado - Diretório para exercícios]*
        ├── lesson-2-1-exercises-intro.md          # *[A ser criado]*
        ├── lesson-2-1-exercise-1-*.md            # *[A ser criado]*
        ├── lesson-2-2-exercises-intro.md          # *[A ser criado]*
        ├── lesson-2-2-exercise-1-*.md            # *[A ser criado]*
        ├── lesson-2-3-exercises-intro.md          # *[A ser criado]*
        ├── lesson-2-3-exercise-1-*.md            # *[A ser criado]*
        ├── lesson-2-4-exercises-intro.md          # *[A ser criado]*
        ├── lesson-2-4-exercise-1-*.md            # *[A ser criado]*
        ├── lesson-2-5-exercises-intro.md          # *[A ser criado]*
        └── lesson-2-5-exercise-1-*.md            # *[A ser criado]*
```

### Arquivos de Dados (Data Files)

#### `_data/lessons.yml`
✅ **Já contém metadados das aulas do módulo 2**, incluindo:
- IDs das aulas
- Títulos e slugs
- Duração e nível
- Pré-requisitos
- Imagens/podcasts

*[A adicionar quando exercícios forem criados]*:
- Lista de exercícios associados por aula
- Informações de vídeo (arquivo, título, thumbnail)

#### `_data/exercises.yml`
*[A ser criado - seção para módulo 2]*
Estrutura preparada para conter metadados de todos os exercícios, incluindo:
- IDs dos exercícios
- Títulos e slugs
- IDs das aulas associadas
- Ordem dos exercícios
- URLs permanentes

#### `_data/quizzes.yml`
*[A ser criado - seção para módulo 2]*
Estrutura preparada para conter todas as questões dos quizzes, organizadas por aula:
- ID da aula associada
- Array de questões (10 por aula)
- Cada questão com ID, texto, opções, resposta correta e explicação

### Arquivos de Assets (Recursos)

#### Vídeos das Aulas
```
assets/videos/
├── 2.1-SAST_Testes_Estaticos.mp4              # *[A ser criado]*
├── 2.2-DAST_Testes_Dinamicos.mp4              # *[A ser criado]*
├── 2.3-Pentest_Basico.mp4                     # *[A ser criado]*
├── 2.4-Automacao_Testes_Seguranca.mp4         # *[A ser criado]*
└── 2.5-Dependency_Scanning_SCA.mp4            # *[A ser criado]*
```

#### Vídeos dos Exercícios
```
assets/videos/
├── Exercicios_Seguranca-lesson-2-1-exercises-intro.mp4  # *[A ser criado]*
├── Exercicios_Seguranca-lesson-2-2-exercises-intro.mp4  # *[A ser criado]*
├── Exercicios_Seguranca-lesson-2-3-exercises-intro.mp4  # *[A ser criado]*
├── Exercicios_Seguranca-lesson-2-4-exercises-intro.mp4  # *[A ser criado]*
└── Exercicios_Seguranca-lesson-2-5-exercises-intro.mp4  # *[A ser criado]*
```

#### Infográficos
```
assets/images/
├── infografico-introducao-modulo-2.png        # *[A ser criado]*
├── infografico-lesson-2-1.png                 # *[A ser criado]*
├── infografico-lesson-2-2.png                 # *[A ser criado]*
├── infografico-lesson-2-3.png                 # *[A ser criado]*
├── infografico-lesson-2-4.png                 # *[A ser criado]*
└── infografico-lesson-2-5.png                 # *[A ser criado]*
```

#### Thumbnails/Podcasts
```
assets/images/podcasts/
├── 2.1-SAST_Testes_Estaticos.png              # ✅ Já existe
├── 2.2-DAST_Testes_Dinamicos.png              # ✅ Já existe
├── 2.3-Pentest_Basico.png                     # ✅ Já existe
├── 2.4-Automacao_Testes_Seguranca.png         # ✅ Já existe
└── 2.5-Dependency_Scanning_SCA.png            # ✅ Já existe
```

---

## 📈 Resumo Estatístico do Módulo 2

### Conteúdo Teórico
- **Total de Aulas**: 5
- **Duração Total das Aulas**: 8 horas (510 minutos)
  - Aula 2.1: 90 minutos
  - Aula 2.2: 90 minutos
  - Aula 2.3: 120 minutos
  - Aula 2.4: 120 minutos
  - Aula 2.5: 90 minutos

### Conteúdo Prático
- **Total de Exercícios**: *[A ser definido - estrutura preparada]*
  - **Básicos**: *[A ser definido]*
  - **Intermediários**: *[A ser definido]*
  - **Avançados**: *[A ser definido]*
- **Duração Total Estimada dos Exercícios**: *[A ser calculado após definição]*

### Vídeos
- **Vídeos de Aulas**: *[A ser criado - 5 vídeos]*
- **Vídeos de Exercícios**: *[A ser criado - vídeos introdutórios]*

### Quizzes
- **Total de Quizzes**: *[A ser criado - 5]*
- **Total de Questões**: *[A ser criado - 50 (10 por quiz)]*

### Infográficos
- **Total de Infográficos**: *[A ser criado - 6]*
  - 1 infográfico de introdução do módulo
  - 5 infográficos (um por aula)

---

## 🔗 Relacionamentos e Dependências

### Fluxo de Aprendizado
```
Módulo 1 (Pré-requisito)
    ↓
Aula 2.1 (SAST)
    ↓
Aula 2.2 (DAST)
    ↓
Aula 2.3 (Pentest)
    ↓
Aula 2.4 (Automação)
    ↓
Aula 2.5 (SCA)
    ↓
Módulo 3
```

### Distribuição de Exercícios
*[A ser definido após criação dos exercícios]*

### Níveis de Dificuldade

#### Por Aula
- **Intermediário**: Aulas 2.1, 2.2, 2.5
- **Avançado**: Aulas 2.3, 2.4

#### Por Exercício
*[A ser definido após criação dos exercícios]*

---

## 📝 Padrões de Nomenclatura

### IDs de Aulas
- Formato: `lesson-{módulo}-{número}`
- Exemplo: `lesson-2-2`

### IDs de Exercícios
- Formato: `lesson-{módulo}-{aula}-exercise-{número}-{nome-descritivo}`
- Exemplo: *[A ser definido - exemplo: `lesson-2-1-exercise-1-sonarqube-setup`]*

### IDs de Vídeos Introdutórios
- Formato: `lesson-{módulo}-{aula}-exercises-intro`
- Exemplo: `lesson-2-1-exercises-intro`

### Slugs
- Formato: `kebab-case` (minúsculas com hífens)
- Exemplo: `sast-testes-estaticos`

### Arquivos de Vídeo
- Formato: `{número}-{título-descriptivo}.mp4`
- Exemplo: `2.1-SAST_Testes_Estaticos.mp4`

### Arquivos de Infográfico
- Formato: `infografico-{localização}.png`
- Exemplo: `infografico-lesson-2-1.png`

---

## ✅ Checklist de Componentes por Aula

Para cada aula, verificar se possui:

- [x] Front matter básico (layout, title, slug, module, lesson_id, duration, level, prerequisites)
- [ ] Front matter completo com vídeo (*[a ser adicionado]*)
- [ ] Vídeo principal da aula (*[a ser criado]*)
- [ ] Thumbnail do vídeo (*[a ser criado]*)
- [x] Imagem/podcast (já existe)
- [ ] Infográfico (*[a ser criado]*)
- [x] Seção de Objetivos de Aprendizado (nas aulas existentes)
- [x] Seção de Conteúdo detalhado (nas aulas existentes)
- [ ] Aplicação no Contexto CWI (*[a verificar/criar]*)
- [ ] Material Complementar (*[a verificar/criar]*)
- [ ] Próximos Passos (*[a verificar/criar]*)
- [ ] Quiz com 10 questões (*[a ser criado em `_data/quizzes.yml`]*)
- [ ] Exercícios associados (*[a ser criado]*)
- [ ] Vídeo introdutório dos exercícios (*[a ser criado quando houver exercícios]*)

---

## 📌 Notas Importantes

1. **Status Atual**: Aulas teóricas criadas, estrutura de diretórios preparada
2. **Próximos Passos**: Criar exercícios, vídeos, quizzes e infográficos
3. **Dependências**: Módulo 2 depende da conclusão do Módulo 1
4. **Nível**: Módulo mais prático, com foco em ferramentas e técnicas
5. **Exercícios**: Devem ser hands-on com ferramentas reais (SonarQube, ZAP, etc.)

---

**Última atualização**: Estrutura preparada para receber conteúdo - placeholders definidos
