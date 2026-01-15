# Mapeamento da Estrutura do Módulo 4: Segurança em CI/CD e DevSecOps

Este documento mapeia detalhadamente a estrutura completa do Módulo 4, incluindo organização de aulas, exercícios, vídeos, infográficos e quizzes.

---

## 📋 Visão Geral do Módulo

- **Título**: Segurança em CI/CD e DevSecOps
- **Duração Total**: 8 horas
- **Nível**: Avançado
- **Pré-requisitos**: Módulo 3 completo (Segurança por Setor)
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
   - `module: module-4`
   - `lesson_id`: ID único da aula
   - `duration`: Duração estimada
   - `level`: Nível (Avançado)
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

### Aula 4.1: DevSecOps: Cultura e Práticas

#### Metadados
- **ID**: `lesson-4-1`
- **Título**: "DevSecOps: Cultura e Práticas"
- **Slug**: `devsecops-cultura-praticas`
- **Duração**: 90 minutos
- **Nível**: Avançado
- **Pré-requisitos**: `["lesson-3-5"]`
- **Exercícios associados**: *[A ser definido]*

#### Vídeo
- **Arquivo**: *[A ser definido - placeholder: `assets/videos/4.1-DevSecOps_Cultura_Praticas.mp4`]*
- **Título**: *[A ser definido]*
- **Thumbnail**: *[A ser definido - placeholder: `assets/images/infografico-lesson-4-1.png`]*
- **Imagem atual**: `assets/images/podcasts/4.1-DevSecOps_Cultura_Praticas.png`

#### Infográfico
- **Arquivo**: *[A ser definido - placeholder: `assets/images/infografico-lesson-4-1.png`]*
- **Localização**: Dentro do conteúdo da aula

#### Quiz
- **ID do Quiz**: `lesson-4-1`
- **Total de Questões**: *[A ser definido - estrutura para 10 questões]*
- **Temas das Questões**: *[A ser definido - foco em cultura DevSecOps, responsabilidade compartilhada, segurança como código]*

#### Estrutura do Conteúdo
1. Objetivos de Aprendizado
2. Conteúdo:
   - *[Conteúdo da aula a ser desenvolvido]*
3. Aplicação no Contexto CWI
4. Material Complementar
5. Próximos Passos

---

### Aula 4.2: Pipeline de Segurança

#### Metadados
- **ID**: `lesson-4-2`
- **Título**: "Pipeline de Segurança"
- **Slug**: `pipeline-seguranca`
- **Duração**: 120 minutos
- **Nível**: Avançado
- **Pré-requisitos**: `["lesson-4-1"]`
- **Exercícios associados**: *[A ser definido]*

#### Vídeo
- **Arquivo**: *[A ser definido - placeholder: `assets/videos/4.2-Pipeline_Seguranca.mp4`]*
- **Título**: *[A ser definido]*
- **Thumbnail**: *[A ser definido - placeholder: `assets/images/infografico-lesson-4-2.png`]*
- **Imagem atual**: `assets/images/podcasts/4.2-Pipeline_Seguranca.png`

#### Infográfico
- **Arquivo**: *[A ser definido - placeholder: `assets/images/infografico-lesson-4-2.png`]*

#### Quiz
- **ID do Quiz**: `lesson-4-2`
- **Total de Questões**: *[A ser definido - estrutura para 10 questões]*
- **Temas das Questões**: *[A ser definido - foco em integração de segurança no CI/CD, GitHub Actions, GitLab CI, automação]*

---

### Aula 4.3: Container Security e Kubernetes

#### Metadados
- **ID**: `lesson-4-3`
- **Título**: "Container Security e Kubernetes"
- **Slug**: `container-security-kubernetes`
- **Duração**: 90 minutos
- **Nível**: Avançado
- **Pré-requisitos**: `["lesson-4-2"]`
- **Exercícios associados**: *[A ser definido]*

#### Vídeo
- **Arquivo**: *[A ser definido - placeholder: `assets/videos/4.3-Container_Security_Kubernetes.mp4`]*
- **Título**: *[A ser definido]*
- **Thumbnail**: *[A ser definido - placeholder: `assets/images/infografico-lesson-4-3.png`]*
- **Imagem atual**: `assets/images/podcasts/4.3-Container_Security_Kubernetes.png`

#### Infográfico
- **Arquivo**: *[A ser definido - placeholder: `assets/images/infografico-lesson-4-3.png`]*

#### Quiz
- **ID do Quiz**: `lesson-4-3`
- **Total de Questões**: *[A ser definido - estrutura para 10 questões]*
- **Temas das Questões**: *[A ser definido - foco em segurança de containers, Docker security, Kubernetes security, scanning de imagens]*

---

### Aula 4.4: Secrets Management

#### Metadados
- **ID**: `lesson-4-4`
- **Título**: "Secrets Management"
- **Slug**: `secrets-management`
- **Duração**: 90 minutos
- **Nível**: Avançado
- **Pré-requisitos**: `["lesson-4-3"]`
- **Exercícios associados**: *[A ser definido]*

#### Vídeo
- **Arquivo**: *[A ser definido - placeholder: `assets/videos/4.4-Secrets_Management.mp4`]*
- **Título**: *[A ser definido]*
- **Thumbnail**: *[A ser definido - placeholder: `assets/images/infografico-lesson-4-4.png`]*
- **Imagem atual**: `assets/images/podcasts/4.4-Secrets_Management.png`

#### Infográfico
- **Arquivo**: *[A ser definido - placeholder: `assets/images/infografico-lesson-4-4.png`]*

#### Quiz
- **ID do Quiz**: `lesson-4-4`
- **Total de Questões**: *[A ser definido - estrutura para 10 questões]*
- **Temas das Questões**: *[A ser definido - foco em HashiCorp Vault, AWS Secrets Manager, gerenciamento seguro de credenciais, rotação de secrets]*

---

### Aula 4.5: Monitoramento e Resposta a Incidentes

#### Metadados
- **ID**: `lesson-4-5`
- **Título**: "Monitoramento e Resposta a Incidentes"
- **Slug**: `monitoramento-resposta-incidentes`
- **Duração**: 90 minutos
- **Nível**: Avançado
- **Pré-requisitos**: `["lesson-4-4"]`
- **Exercícios associados**: *[A ser definido]*

#### Vídeo
- **Arquivo**: *[A ser definido - placeholder: `assets/videos/4.5-Monitoramento_Resposta_Incidentes.mp4`]*
- **Título**: *[A ser definido]*
- **Thumbnail**: *[A ser definido - placeholder: `assets/images/infografico-lesson-4-5.png`]*
- **Imagem atual**: `assets/images/podcasts/4.5-Monitoramento_Resposta_Incidentes.png`

#### Infográfico
- **Arquivo**: *[A ser definido - placeholder: `assets/images/infografico-lesson-4-5.png`]*

#### Quiz
- **ID do Quiz**: `lesson-4-5`
- **Total de Questões**: *[A ser definido - estrutura para 10 questões]*
- **Temas das Questões**: *[A ser definido - foco em SIEM, detecção de ameaças, resposta a incidentes, logging de segurança, alertas]*

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
   - `module`: Módulo (module-4)
   - `difficulty`: Nível de dificuldade (Intermediário, Avançado)
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

### Aula 4.1: DevSecOps (*[A ser definido]*)
- **Vídeo Introdutório**: *[A ser criado]*
- **Exercícios**: *[A ser definido - sugestão: 3-5 exercícios sobre cultura DevSecOps, responsabilidade compartilhada, segurança como código]*

### Aula 4.2: Pipeline de Segurança (*[A ser definido]*)
- **Vídeo Introdutório**: *[A ser criado]*
- **Exercícios**: *[A ser definido - sugestão: 4-6 exercícios práticos sobre GitHub Actions, GitLab CI, integração de SAST/DAST/SCA no pipeline]*

### Aula 4.3: Container Security (*[A ser definido]*)
- **Vídeo Introdutório**: *[A ser criado]*
- **Exercícios**: *[A ser definido - sugestão: 4-6 exercícios sobre Docker security scanning, Kubernetes security policies, scanning de imagens]*

### Aula 4.4: Secrets Management (*[A ser definido]*)
- **Vídeo Introdutório**: *[A ser criado]*
- **Exercícios**: *[A ser definido - sugestão: 3-5 exercícios sobre HashiCorp Vault, AWS Secrets Manager, implementação de secrets management]*

### Aula 4.5: Monitoramento (*[A ser definido]*)
- **Vídeo Introdutório**: *[A ser criado]*
- **Exercícios**: *[A ser definido - sugestão: 4-6 exercícios sobre SIEM, detecção de ameaças, resposta a incidentes, criação de alertas]*

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
| 4.1 | `lesson-4-1` | *[A ser criado - 10 questões]* | `_data/quizzes.yml` |
| 4.2 | `lesson-4-2` | *[A ser criado - 10 questões]* | `_data/quizzes.yml` |
| 4.3 | `lesson-4-3` | *[A ser criado - 10 questões]* | `_data/quizzes.yml` |
| 4.4 | `lesson-4-4` | *[A ser criado - 10 questões]* | `_data/quizzes.yml` |
| 4.5 | `lesson-4-5` | *[A ser criado - 10 questões]* | `_data/quizzes.yml` |

**Total**: *[A ser criado - 50 questões distribuídas em 5 quizzes]*

---

## 📁 Estrutura de Arquivos e Diretórios

### Diretório Raiz do Módulo
```
modules/module-4/
├── index.md                    # Página principal do módulo ✅
├── summary.md                  # *[A ser criado - Resumo do módulo]*
└── lessons/                    # Aulas do módulo
    ├── lesson-4-1.md          # Aula 4.1 ✅
    ├── lesson-4-2.md          # Aula 4.2 ✅
    ├── lesson-4-3.md          # Aula 4.3 ✅
    ├── lesson-4-4.md          # Aula 4.4 ✅
    ├── lesson-4-5.md          # Aula 4.5 ✅
    └── exercises/             # *[A ser criado - Diretório para exercícios]*
        ├── lesson-4-1-exercises-intro.md          # *[A ser criado]*
        ├── lesson-4-1-exercise-1-*.md            # *[A ser criado]*
        ├── lesson-4-2-exercises-intro.md          # *[A ser criado]*
        ├── lesson-4-2-exercise-1-*.md            # *[A ser criado]*
        ├── lesson-4-3-exercises-intro.md          # *[A ser criado]*
        ├── lesson-4-3-exercise-1-*.md            # *[A ser criado]*
        ├── lesson-4-4-exercises-intro.md          # *[A ser criado]*
        ├── lesson-4-4-exercise-1-*.md            # *[A ser criado]*
        ├── lesson-4-5-exercises-intro.md          # *[A ser criado]*
        └── lesson-4-5-exercise-1-*.md            # *[A ser criado]*
```

### Arquivos de Dados (Data Files)

#### `_data/lessons.yml`
✅ **Já contém metadados das aulas do módulo 4**, incluindo:
- IDs das aulas
- Títulos e slugs
- Duração e nível
- Pré-requisitos
- Imagens/podcasts

*[A adicionar quando exercícios forem criados]*:
- Lista de exercícios associados por aula
- Informações de vídeo (arquivo, título, thumbnail)

#### `_data/exercises.yml`
*[A ser criado - seção para módulo 4]*
Estrutura preparada para conter metadados de todos os exercícios, incluindo:
- IDs dos exercícios
- Títulos e slugs
- IDs das aulas associadas
- Ordem dos exercícios
- URLs permanentes

#### `_data/quizzes.yml`
*[A ser criado - seção para módulo 4]*
Estrutura preparada para conter todas as questões dos quizzes, organizadas por aula:
- ID da aula associada
- Array de questões (10 por aula)
- Cada questão com ID, texto, opções, resposta correta e explicação

### Arquivos de Assets (Recursos)

#### Vídeos das Aulas
```
assets/videos/
├── 4.1-DevSecOps_Cultura_Praticas.mp4          # *[A ser criado]*
├── 4.2-Pipeline_Seguranca.mp4                  # *[A ser criado]*
├── 4.3-Container_Security_Kubernetes.mp4       # *[A ser criado]*
├── 4.4-Secrets_Management.mp4                  # *[A ser criado]*
└── 4.5-Monitoramento_Resposta_Incidentes.mp4   # *[A ser criado]*
```

#### Vídeos dos Exercícios
```
assets/videos/
├── Exercicios_Seguranca-lesson-4-1-exercises-intro.mp4  # *[A ser criado]*
├── Exercicios_Seguranca-lesson-4-2-exercises-intro.mp4  # *[A ser criado]*
├── Exercicios_Seguranca-lesson-4-3-exercises-intro.mp4  # *[A ser criado]*
├── Exercicios_Seguranca-lesson-4-4-exercises-intro.mp4  # *[A ser criado]*
└── Exercicios_Seguranca-lesson-4-5-exercises-intro.mp4  # *[A ser criado]*
```

#### Infográficos
```
assets/images/
├── infografico-introducao-modulo-4.png        # *[A ser criado]*
├── infografico-lesson-4-1.png                 # *[A ser criado]*
├── infografico-lesson-4-2.png                 # *[A ser criado]*
├── infografico-lesson-4-3.png                 # *[A ser criado]*
├── infografico-lesson-4-4.png                 # *[A ser criado]*
└── infografico-lesson-4-5.png                 # *[A ser criado]*
```

#### Thumbnails/Podcasts
```
assets/images/podcasts/
├── 4.1-DevSecOps_Cultura_Praticas.png          # ✅ Já existe
├── 4.2-Pipeline_Seguranca.png                  # ✅ Já existe
├── 4.3-Container_Security_Kubernetes.png       # ✅ Já existe
├── 4.4-Secrets_Management.png                  # ✅ Já existe
└── 4.5-Monitoramento_Resposta_Incidentes.png   # ✅ Já existe
```

---

## 📈 Resumo Estatístico do Módulo 4

### Conteúdo Teórico
- **Total de Aulas**: 5
- **Duração Total das Aulas**: 8 horas (480 minutos)
  - Aula 4.1: 90 minutos
  - Aula 4.2: 120 minutos
  - Aula 4.3: 90 minutos
  - Aula 4.4: 90 minutos
  - Aula 4.5: 90 minutos

### Conteúdo Prático
- **Total de Exercícios**: *[A ser definido - estrutura preparada]*
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
Módulo 3 (Pré-requisito)
    ↓
Aula 4.1 (DevSecOps - Cultura)
    ↓
Aula 4.2 (Pipeline de Segurança)
    ↓
Aula 4.3 (Container Security)
    ↓
Aula 4.4 (Secrets Management)
    ↓
Aula 4.5 (Monitoramento)
    ↓
[Finalização do Curso]
```

### Distribuição de Exercícios
*[A ser definido após criação dos exercícios]*

### Níveis de Dificuldade

#### Por Aula
- **Avançado**: Todas as aulas (4.1, 4.2, 4.3, 4.4, 4.5)

#### Por Exercício
*[A ser definido após criação dos exercícios]*

---

## 📝 Padrões de Nomenclatura

### IDs de Aulas
- Formato: `lesson-{módulo}-{número}`
- Exemplo: `lesson-4-2`

### IDs de Exercícios
- Formato: `lesson-{módulo}-{aula}-exercise-{número}-{nome-descritivo}`
- Exemplo: *[A ser definido - exemplo: `lesson-4-2-exercise-1-github-actions-pipeline`]*

### IDs de Vídeos Introdutórios
- Formato: `lesson-{módulo}-{aula}-exercises-intro`
- Exemplo: `lesson-4-2-exercises-intro`

### Slugs
- Formato: `kebab-case` (minúsculas com hífens)
- Exemplo: `pipeline-seguranca`

### Arquivos de Vídeo
- Formato: `{número}-{título-descriptivo}.mp4`
- Exemplo: `4.2-Pipeline_Seguranca.mp4`

### Arquivos de Infográfico
- Formato: `infografico-{localização}.png`
- Exemplo: `infografico-lesson-4-2.png`

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
3. **Dependências**: Módulo 4 depende da conclusão do Módulo 3 - é o módulo final do curso
4. **Nível**: Módulo totalmente avançado, foco em integração e automação
5. **Exercícios**: Devem ser hands-on com ferramentas reais (GitHub Actions, Docker, Kubernetes, Vault, SIEM)
6. **Finalização**: Este é o último módulo do curso - pode incluir projeto final ou capstone

---

**Última atualização**: Estrutura preparada para receber conteúdo - placeholders definidos
