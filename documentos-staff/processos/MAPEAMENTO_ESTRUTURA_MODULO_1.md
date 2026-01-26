# Mapeamento da Estrutura do Módulo 1: Fundamentos de Segurança em QA

Este documento mapeia detalhadamente a estrutura completa do Módulo 1, incluindo organização de aulas, exercícios, vídeos, infográficos e quizzes.

---

## 📋 Visão Geral do Módulo

- **Título**: Fundamentos de Segurança em QA
- **Duração Total**: 8 horas
- **Nível**: Básico a Intermediário
- **Pré-requisitos**: Conhecimento básico de QA e desenvolvimento web
- **Total de Aulas**: 5 aulas
- **Total de Exercícios**: 18 exercícios práticos
- **Total de Quizzes**: 5 quizzes (um por aula) com gabaritos em `documentos-staff/resolucao-exercicios/modulo-1/GABARITOS_QUIZZES_MODULO_1.md`

---

## 🎓 Estrutura das Aulas

Cada aula possui uma estrutura consistente com os seguintes componentes:

### Componentes Padrão de uma Aula

1. **Front Matter (Metadados Jekyll)**
   - `layout: lesson`
   - `title`: Título da aula
   - `slug`: URL slug da aula
   - `module: module-1`
   - `lesson_id`: ID único da aula
   - `duration`: Duração estimada
   - `level`: Nível (Básico, Intermediário, Avançado)
   - `prerequisites`: Array de IDs de aulas pré-requisitas
   - `exercises`: Array de IDs de exercícios associados
   - `video`: Objeto com informações do vídeo
     - `file`: Caminho do arquivo de vídeo
     - `title`: Título do vídeo
     - `thumbnail`: Caminho da thumbnail/miniatura
     - `description`: Descrição (opcional)
     - `duration`: Duração (opcional)
   - `permalink`: URL permanente da aula

2. **Conteúdo da Aula**
   - Título principal
   - Seção de Objetivos de Aprendizado (🎯)
   - Seção de Conteúdo (📚)
   - Infográfico (quando aplicável)
   - Aplicação no Contexto CWI (💼)
   - Material Complementar (📖)
   - Próximos Passos (🎯)

3. **Vídeo da Aula**
   - Arquivo de vídeo principal
   - Thumbnail/imagem de capa
   - Descrição opcional

4. **Infográfico**
   - Imagem visual explicativa
   - Localizado dentro do conteúdo da aula

5. **Quiz**
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

### Aula 1.1: Introdução à Segurança em QA

#### Metadados
- **ID**: `lesson-1-1`
- **Título**: "Introdução à Segurança em QA"
- **Slug**: `introducao-seguranca-qa`
- **Duração**: 60 minutos
- **Nível**: Básico
- **Pré-requisitos**: Nenhum
- **Exercícios associados**: Nenhum

#### Vídeo
- **Arquivo**: `assets/videos/1.1-Introducao_Seguranca_QA.mp4`
- **Título**: "Introdução à Segurança em QA"
- **Thumbnail**: `assets/images/podcasts/1.1-Introducao_Seguranca_QA.png`

#### Infográfico
- **Arquivo**: `assets/images/infografico-lesson1-1.png`
- **Localização**: Dentro do conteúdo, seção sobre "Segurança em QA - Ciclo de Desenvolvimento"

#### Quiz
- **ID do Quiz**: `lesson-1-1`
- **Total de Questões**: 10 (gabaritos em `documentos-staff/resolucao-exercicios/modulo-1/GABARITOS_QUIZZES_MODULO_1.md`)
- **Temas das Questões**:
  1. Tríade CIA (Confidencialidade, Integridade, Disponibilidade)
  2. Diferença entre QA Tradicional e Security QA
  3. Significado de Confidencialidade
  4. Quando segurança deve ser considerada
  5. Custo médio de violação de dados
  6. Significado de Integridade
  7. Posição única do QA
  8. Modelo correto de segurança
  9. Significado de Disponibilidade
  10. Setor com proteção especial para menores

#### Estrutura do Conteúdo
1. Objetivos de Aprendizado
2. Conteúdo:
   - Por que Segurança em QA?
   - QA Tradicional vs Security QA
   - A Tríade CIA
   - Segurança é Responsabilidade de Todos
   - Quando Segurança Deve Ser Considerada
3. Aplicação no Contexto CWI
4. Material Complementar
5. Próximos Passos

---

### Aula 1.2: OWASP Top 10 e Principais Vulnerabilidades

#### Metadados
- **ID**: `lesson-1-2`
- **Título**: "OWASP Top 10 e Principais Vulnerabilidades"
- **Slug**: `owasp-top-10`
- **Duração**: 90 minutos
- **Nível**: Básico
- **Pré-requisitos**: `["lesson-1-1"]`
- **Exercícios associados**: 
  - `lesson-1-2-exercise-1-identificar-vulnerabilidades`
  - `lesson-1-2-exercise-2-sql-injection`
  - `lesson-1-2-exercise-3-broken-access-control`
  - `lesson-1-2-exercise-4-owasp-checklist`

#### Vídeo
- **Arquivo**: `assets/videos/video-lesson1-2.mp4`
- **Título**: "OWASP Top 10 - Vulnerabilidades que Todo QA Deve Conhecer"
- **Thumbnail**: `assets/images/infografico-lesson-1-2.png`
- **Descrição**: "Análise detalhada das 10 principais vulnerabilidades de segurança web segundo OWASP: Injection, Broken Authentication, XSS, e mais. Aprenda a identificá-las em testes."
- **Duração**: "60-75 minutos"

#### Infográfico
- **Arquivo**: `assets/images/infografico-lesson-1-2.png`
- **Localização**: Final do conteúdo, seção "OWASP Top 10 - Vulnerabilidades e Prevenção"

#### Quiz
- **ID do Quiz**: `lesson-1-2`
- **Total de Questões**: 10 (gabaritos em `documentos-staff/resolucao-exercicios/modulo-1/GABARITOS_QUIZZES_MODULO_1.md`)
- **Temas das Questões**:
  1. Vulnerabilidade #1 do OWASP Top 10 2021
  2. O que é SQL Injection
  3. Melhor forma de prevenir XSS
  4. O que caracteriza Broken Access Control
  5. Vulnerabilidade que permite falsificar identidades
  6. O que é IDOR
  7. Impacto de ataque de Injection
  8. O que é Security Misconfiguration
  9. Vulnerabilidade relacionada a componentes vulneráveis
  10. Vulnerabilidade mais crítica em contexto financeiro

#### Estrutura do Conteúdo
1. Objetivos de Aprendizado
2. Introdução ao OWASP Top 10
3. As 10 Vulnerabilidades Críticas (detalhadas uma a uma):
   - Broken Access Control
   - Cryptographic Failures
   - Injection
   - Insecure Design
   - Security Misconfiguration
   - Vulnerable and Outdated Components
   - Identification and Authentication Failures
   - Software and Data Integrity Failures
   - Security Logging and Monitoring Failures
   - Server-Side Request Forgery (SSRF)
4. Aplicação por Setor CWI
5. Laboratório Prático
6. Tabela de Referência Rápida
7. Checklist de Testes por Vulnerabilidade
8. Referências Externas
9. Próximos Passos

---

### Aula 1.3: Shift-Left Security: Segurança desde o Início

#### Metadados
- **ID**: `lesson-1-3`
- **Título**: "Shift-Left Security: Segurança desde o Início"
- **Slug**: `shift-left-security`
- **Duração**: 60 minutos
- **Nível**: Básico
- **Pré-requisitos**: `["lesson-1-2"]`
- **Exercícios associados**:
  - `lesson-1-3-exercise-1-security-requirements`
  - `lesson-1-3-exercise-2-threat-modeling-early`
  - `lesson-1-3-exercise-3-devqa-security-collab`
  - `lesson-1-3-exercise-4-shift-left-checklist`

#### Vídeo
- **Arquivo**: `assets/videos/Seguranca_Shift-Left-lesson-1-3.mp4`
- **Título**: "Shift-Left Security: Segurança desde o Início"
- **Thumbnail**: `assets/images/info-grafico-lesson-1-3.png`

#### Infográfico
- **Arquivo**: `assets/images/info-grafico-lesson-1-3.png`

#### Quiz
- **ID do Quiz**: `lesson-1-3`
- **Total de Questões**: 10 (gabaritos em `documentos-staff/resolucao-exercicios/modulo-1/GABARITOS_QUIZZES_MODULO_1.md`)
- **Temas das Questões**:
  1. O que significa Shift-Left Security
  2. Custo de corrigir vulnerabilidade em produção
  3. Fase do SDLC onde Shift-Left começa
  4. Papel do QA no Shift-Left
  5. O que são Security Requirements
  6. Diferença entre abordagem tradicional e Shift-Left
  7. Benefícios do Shift-Left Security
  8. Quando Security Requirements devem ser definidos
  9. O que é colaboração Dev-QA-Security
  10. Métricas de sucesso do Shift-Left

---

### Aula 1.4: Threat Modeling e Análise de Riscos

#### Metadados
- **ID**: `lesson-1-4`
- **Título**: "Threat Modeling e Análise de Riscos"
- **Slug**: `threat-modeling`
- **Duração**: 90 minutos
- **Nível**: Intermediário
- **Pré-requisitos**: `["lesson-1-3"]`
- **Exercícios associados**:
  - `lesson-1-4-exercise-1-stride-basico`
  - `lesson-1-4-exercise-2-identificar-ameacas`
  - `lesson-1-4-exercise-3-analise-riscos`
  - `lesson-1-4-exercise-4-threat-model-completo`
  - `lesson-1-4-exercise-5-mitigacao-priorizacao`

#### Vídeo
- **Arquivo**: `assets/videos/Modelagem_de_Ameacas-lesson-1-4.mp4`
- **Título**: "Threat Modeling e Análise de Riscos"
- **Thumbnail**: `assets/images/infografico-lesson-1-4.png`

#### Infográfico
- **Arquivo**: `assets/images/infografico-lesson-1-4.png`

#### Quiz
- **ID do Quiz**: `lesson-1-4`
- **Total de Questões**: 10 (gabaritos em `documentos-staff/resolucao-exercicios/modulo-1/GABARITOS_QUIZZES_MODULO_1.md`)
- **Temas das Questões**:
  1. O que é Threat Modeling
  2. Metodologia STRIDE
  3. Significado de 'S' em STRIDE
  4. O que são Ativos
  5. O que são Pontos de Entrada
  6. Metodologia DREAD
  7. Ameaça mais crítica em API financeira
  8. Quando Threat Modeling deve ser realizado
  9. O que é Mitigação
  10. Ferramenta gratuita baseada em STRIDE

---

### Aula 1.5: Compliance e Regulamentações (LGPD, PCI-DSS, SOC2)

#### Metadados
- **ID**: `lesson-1-5`
- **Título**: "Compliance e Regulamentações (LGPD, PCI-DSS, SOC2)"
- **Slug**: `compliance-regulamentacoes`
- **Duração**: 90 minutos
- **Nível**: Intermediário
- **Pré-requisitos**: `["lesson-1-4"]`
- **Exercícios associados**:
  - `lesson-1-5-exercise-1-lgpd-checklist`
  - `lesson-1-5-exercise-2-pci-dss-validacao`
  - `lesson-1-5-exercise-3-soc2-controles`
  - `lesson-1-5-exercise-4-compliance-por-setor`
  - `lesson-1-5-exercise-5-auditoria-qa`

#### Vídeo
- **Arquivo**: `assets/videos/Compliance__As_Regras_Ocultas-lesson-1-5.mp4`
- **Título**: "Compliance e Regulamentações (LGPD, PCI-DSS, SOC2)"
- **Thumbnail**: `assets/images/infografico-lesson-1-5.png`

#### Infográfico
- **Arquivo**: `assets/images/infografico-lesson-1-5.png`

#### Quiz
- **ID do Quiz**: `lesson-1-5`
- **Total de Questões**: 10 (gabaritos em `documentos-staff/resolucao-exercicios/modulo-1/GABARITOS_QUIZZES_MODULO_1.md`)
- **Temas das Questões**:
  1. O que é Compliance
  2. Multa máxima da LGPD
  3. Quantos requisitos tem PCI-DSS
  4. Princípio da LGPD sobre finalidade
  5. Requisito PCI-DSS mais crítico para QA em ecommerce
  6. Trust Service Criteria do SOC2
  7. Proteção especial para dados de menores
  8. Papel do QA em auditorias
  9. Nível PCI-DSS que requer auditoria anual
  10. Abordagem de compliance em projeto multi-setor

---

## 🎯 Estrutura dos Exercícios

Cada exercício possui uma estrutura padronizada:

### Componentes Padrão de um Exercício

1. **Front Matter (Metadados Jekyll)**
   - `layout: exercise`
   - `title`: Título do exercício
   - `slug`: URL slug do exercício
   - `lesson_id`: ID da aula associada
   - `module`: Módulo (module-1)
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

Cada aula com exercícios possui um vídeo introdutório:

- **Formato**: Página especial com layout `exercise`
- **Conteúdo**: Visão geral dos exercícios da aula
- **Componentes**:
  - Vídeo explicativo
  - Lista de exercícios da aula
  - Descrição de cada exercício
  - Dicas para aproveitar os exercícios

---

## 📚 Detalhamento dos Exercícios por Aula

### Aula 1.2: Exercícios sobre OWASP Top 10

#### Vídeo Introdutório
- **ID**: `lesson-1-2-exercises-intro`
- **Título**: "📹 Vídeo: Introdução aos Exercícios - OWASP Top 10"
- **Slug**: `exercises-intro-owasp`
- **Vídeo**: `assets/videos/Exercicios_Seguranca-lesson-1-2-exercises-intro.mp4`

#### Exercício 1.2.1: Identificar Vulnerabilidades OWASP
- **ID**: `lesson-1-2-exercise-1-identificar-vulnerabilidades`
- **Título**: "Exercício 1.2.1: Identificar Vulnerabilidades OWASP Top 10"
- **Slug**: `identificar-vulnerabilidades`
- **Dificuldade**: Básico
- **Duração**: 30-45 minutos
- **Estrutura**:
  - Objetivo
  - Descrição
  - Contexto
  - Tarefa: Análise de 5 códigos diferentes
    - Código 1: Autenticação (SQL Injection)
    - Código 2: Acesso a Recursos (Broken Access Control)
    - Código 3: Upload de Arquivo
    - Código 4: Consulta de Dados (NoSQL Injection)
    - Código 5: Mensagens de Erro (Security Misconfiguration)
  - Dicas
  - Próximos Passos
  - Formulário de Submissão

#### Exercício 1.2.2: SQL Injection - Exploração e Prevenção
- **ID**: `lesson-1-2-exercise-2-sql-injection`
- **Título**: "Exercício 1.2.2: Testar SQL Injection"
- **Slug**: `sql-injection`
- **Dificuldade**: Intermediário
- **Duração**: 60-90 minutos

#### Exercício 1.2.3: Broken Access Control
- **ID**: `lesson-1-2-exercise-3-broken-access-control`
- **Título**: "Exercício 1.2.3: Broken Access Control"
- **Slug**: `broken-access-control`
- **Dificuldade**: Intermediário
- **Duração**: 60-90 minutos

#### Exercício 1.2.4: Checklist OWASP Top 10
- **ID**: `lesson-1-2-exercise-4-owasp-checklist`
- **Título**: "Exercício 1.2.4: Checklist OWASP Top 10"
- **Slug**: `owasp-checklist`
- **Dificuldade**: Básico
- **Duração**: 30-45 minutos

---

### Aula 1.3: Exercícios sobre Shift-Left Security

#### Vídeo Introdutório
- **ID**: `lesson-1-3-exercises-intro`
- **Título**: "📹 Vídeo: Introdução aos Exercícios - Shift-Left Security"
- **Slug**: `exercises-intro-shift-left`
- **Vídeo**: `assets/videos/Exercicios_Seguranca-lesson-1-3-exercises-intro.mp4`

#### Exercício 1.3.1: Security Requirements
- **ID**: `lesson-1-3-exercise-1-security-requirements`
- **Título**: "Exercício 1.3.1: Security Requirements"
- **Slug**: `security-requirements`
- **Dificuldade**: Básico
- **Duração**: 30-45 minutos

#### Exercício 1.3.2: Threat Modeling Early
- **ID**: `lesson-1-3-exercise-2-threat-modeling-early`
- **Título**: "Exercício 1.3.2: Threat Modeling Early"
- **Slug**: `threat-modeling-early`
- **Dificuldade**: Intermediário
- **Duração**: 60-90 minutos

#### Exercício 1.3.3: Colaboração Dev/QA/Security
- **ID**: `lesson-1-3-exercise-3-devqa-security-collab`
- **Título**: "Exercício 1.3.3: Colaboração Dev/QA/Security"
- **Slug**: `devqa-security-collab`
- **Dificuldade**: Básico
- **Duração**: 30-45 minutos

#### Exercício 1.3.4: Checklist Shift-Left
- **ID**: `lesson-1-3-exercise-4-shift-left-checklist`
- **Título**: "Exercício 1.3.4: Checklist Shift-Left"
- **Slug**: `shift-left-checklist`
- **Dificuldade**: Básico
- **Duração**: 30-45 minutos

---

### Aula 1.4: Exercícios sobre Threat Modeling

#### Vídeo Introdutório
- **ID**: `lesson-1-4-exercises-intro`
- **Título**: "📹 Vídeo: Introdução aos Exercícios - Threat Modeling"
- **Slug**: `exercises-intro-threat-modeling`
- **Vídeo**: `assets/videos/Exercicios_Seguranca-lesson-1-4-exercises-intro.mp4`

#### Exercício 1.4.1: STRIDE Básico
- **ID**: `lesson-1-4-exercise-1-stride-basico`
- **Título**: "Exercício 1.4.1: STRIDE Básico"
- **Slug**: `stride-basico`
- **Dificuldade**: Básico
- **Duração**: 30-45 minutos

#### Exercício 1.4.2: Identificar Ameaças
- **ID**: `lesson-1-4-exercise-2-identificar-ameacas`
- **Título**: "Exercício 1.4.2: Identificar Ameaças"
- **Slug**: `identificar-ameacas`
- **Dificuldade**: Intermediário
- **Duração**: 60-90 minutos

#### Exercício 1.4.3: Análise de Riscos
- **ID**: `lesson-1-4-exercise-3-analise-riscos`
- **Título**: "Exercício 1.4.3: Análise de Riscos"
- **Slug**: `analise-riscos`
- **Dificuldade**: Intermediário
- **Duração**: 60-90 minutos

#### Exercício 1.4.4: Threat Model Completo
- **ID**: `lesson-1-4-exercise-4-threat-model-completo`
- **Título**: "Exercício 1.4.4: Threat Model Completo"
- **Slug**: `threat-model-completo`
- **Dificuldade**: Avançado
- **Duração**: 90-120 minutos

#### Exercício 1.4.5: Mitigação e Priorização
- **ID**: `lesson-1-4-exercise-5-mitigacao-priorizacao`
- **Título**: "Exercício 1.4.5: Mitigação e Priorização"
- **Slug**: `mitigacao-priorizacao`
- **Dificuldade**: Intermediário
- **Duração**: 60-90 minutos

---

### Aula 1.5: Exercícios sobre Compliance

#### Vídeo Introdutório
- **ID**: `lesson-1-5-exercises-intro`
- **Título**: "📹 Vídeo: Introdução aos Exercícios - Compliance e Regulamentações"
- **Slug**: `exercises-intro-compliance`
- **Vídeo**: `assets/videos/Exercicios_Seguranca-lesson-1-5-exercises-intro.mp4`

#### Exercício 1.5.1: Checklist LGPD para Projeto
- **ID**: `lesson-1-5-exercise-1-lgpd-checklist`
- **Título**: "Exercício 1.5.1: Checklist LGPD para Projeto"
- **Slug**: `lgpd-checklist`
- **Dificuldade**: Básico
- **Duração**: 30-45 minutos

#### Exercício 1.5.2: Validação PCI-DSS
- **ID**: `lesson-1-5-exercise-2-pci-dss-validacao`
- **Título**: "Exercício 1.5.2: Validação PCI-DSS"
- **Slug**: `pci-dss-validacao`
- **Dificuldade**: Intermediário
- **Duração**: 60-90 minutos

#### Exercício 1.5.3: Controles SOC2
- **ID**: `lesson-1-5-exercise-3-soc2-controles`
- **Título**: "Exercício 1.5.3: Controles SOC2"
- **Slug**: `soc2-controles`
- **Dificuldade**: Intermediário
- **Duração**: 60-90 minutos

#### Exercício 1.5.4: Compliance por Setor
- **ID**: `lesson-1-5-exercise-4-compliance-por-setor`
- **Título**: "Exercício 1.5.4: Compliance por Setor"
- **Slug**: `compliance-por-setor`
- **Dificuldade**: Intermediário
- **Duração**: 60-90 minutos

#### Exercício 1.5.5: Auditoria QA - Preparação e Execução
- **ID**: `lesson-1-5-exercise-5-auditoria-qa`
- **Título**: "Exercício 1.5.5: Auditoria QA - Preparação e Execução"
- **Slug**: `auditoria-qa`
- **Dificuldade**: Avançado
- **Duração**: 90-120 minutos

---

## 📊 Estrutura dos Quizzes

### Formato dos Quizzes

Cada quiz está associado a uma aula e contém 10 questões no formato de múltipla escolha. Os gabaritos consolidados estão em `documentos-staff/resolucao-exercicios/modulo-1/GABARITOS_QUIZZES_MODULO_1.md`.

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
| 1.1 | `lesson-1-1` | 10 | `_data/quizzes.yml` |
| 1.2 | `lesson-1-2` | 10 | `_data/quizzes.yml` |
| 1.3 | `lesson-1-3` | 10 | `_data/quizzes.yml` |
| 1.4 | `lesson-1-4` | 10 | `_data/quizzes.yml` |
| 1.5 | `lesson-1-5` | 10 | `_data/quizzes.yml` |

**Total**: 50 questões distribuídas em 5 quizzes

---

## 📁 Estrutura de Arquivos e Diretórios

### Diretório Raiz do Módulo
```
modules/module-1/
├── index.md                    # Página principal do módulo
├── summary.md                  # Resumo do módulo
└── lessons/                    # Aulas do módulo
    ├── lesson-1-1.md          # Aula 1.1
    ├── lesson-1-2.md          # Aula 1.2
    ├── lesson-1-3.md          # Aula 1.3
    ├── lesson-1-4.md          # Aula 1.4
    ├── lesson-1-5.md          # Aula 1.5
    └── exercises/             # Exercícios do módulo
        ├── lesson-1-2-exercises-intro.md
        ├── lesson-1-2-exercise-1-identificar-vulnerabilidades.md
        ├── lesson-1-2-exercise-2-sql-injection.md
        ├── lesson-1-2-exercise-3-broken-access-control.md
        ├── lesson-1-2-exercise-4-owasp-checklist.md
        ├── lesson-1-3-exercises-intro.md
        ├── lesson-1-3-exercise-1-security-requirements.md
        ├── lesson-1-3-exercise-2-threat-modeling-early.md
        ├── lesson-1-3-exercise-3-devqa-security-collab.md
        ├── lesson-1-3-exercise-4-shift-left-checklist.md
        ├── lesson-1-4-exercises-intro.md
        ├── lesson-1-4-exercise-1-stride-basico.md
        ├── lesson-1-4-exercise-2-identificar-ameacas.md
        ├── lesson-1-4-exercise-3-analise-riscos.md
        ├── lesson-1-4-exercise-4-threat-model-completo.md
        ├── lesson-1-4-exercise-5-mitigacao-priorizacao.md
        ├── lesson-1-5-exercises-intro.md
        ├── lesson-1-5-exercise-1-lgpd-checklist.md
        ├── lesson-1-5-exercise-2-pci-dss-validacao.md
        ├── lesson-1-5-exercise-3-soc2-controles.md
        ├── lesson-1-5-exercise-4-compliance-por-setor.md
        └── lesson-1-5-exercise-5-auditoria-qa.md
```

### Arquivos de Dados (Data Files)

#### `_data/lessons.yml`
Contém metadados de todas as aulas do módulo 1, incluindo:
- IDs das aulas
- Títulos e slugs
- Duração e nível
- Pré-requisitos
- Lista de exercícios associados
- Informações de vídeo (arquivo, título, thumbnail)

#### `_data/exercises.yml`
Contém metadados de todos os exercícios do módulo 1, incluindo:
- IDs dos exercícios
- Títulos e slugs
- IDs das aulas associadas
- Ordem dos exercícios
- URLs permanentes

#### `_data/quizzes.yml`
Contém todas as questões dos quizzes, organizadas por aula:
- ID da aula associada
- Array de questões (10 por aula)
- Cada questão com ID, texto, opções, resposta correta e explicação
 - Gabaritos consolidados na documentação da staff

### Arquivos de Assets (Recursos)

#### Vídeos das Aulas
```
assets/videos/
├── 1.1-Introducao_Seguranca_QA.mp4
├── video-lesson1-2.mp4
├── Seguranca_Shift-Left-lesson-1-3.mp4
├── Modelagem_de_Ameacas-lesson-1-4.mp4
└── Compliance__As_Regras_Ocultas-lesson-1-5.mp4
```

#### Vídeos dos Exercícios
```
assets/videos/
├── Exercicios_Seguranca-lesson-1-2-exercises-intro.mp4
├── Exercicios_Seguranca-lesson-1-3-exercises-intro.mp4
├── Exercicios_Seguranca-lesson-1-4-exercises-intro.mp4
└── Exercicios_Seguranca-lesson-1-5-exercises-intro.mp4
```

#### Infográficos
```
assets/images/
├── infografico-introducao-modulo-1.png
├── infografico-lesson1-1.png
├── infografico-lesson-1-2.png
├── info-grafico-lesson-1-3.png
├── infografico-lesson-1-4.png
└── infografico-lesson-1-5.png
```

#### Thumbnails/Podcasts
```
assets/images/podcasts/
└── 1.1-Introducao_Seguranca_QA.png
```

---

## 📈 Resumo Estatístico do Módulo 1

### Conteúdo Teórico
- **Total de Aulas**: 5
- **Duração Total das Aulas**: 8 horas (390 minutos)
  - Aula 1.1: 60 minutos
  - Aula 1.2: 90 minutos
  - Aula 1.3: 60 minutos
  - Aula 1.4: 90 minutos
  - Aula 1.5: 90 minutos

### Conteúdo Prático
- **Total de Exercícios**: 18
  - **Básicos**: 7 exercícios (30-45 min cada)
  - **Intermediários**: 9 exercícios (60-90 min cada)
  - **Avançados**: 2 exercícios (90-120 min cada)
- **Duração Total Estimada dos Exercícios**: ~20-25 horas

### Vídeos
- **Vídeos de Aulas**: 5
- **Vídeos de Exercícios**: 4 (vídeos introdutórios)

### Quizzes
- **Total de Quizzes**: 5
- **Total de Questões**: 50 (10 por quiz)

### Infográficos
- **Total de Infográficos**: 6
  - 1 infográfico de introdução do módulo
  - 5 infográficos (um por aula)

---

## 🔗 Relacionamentos e Dependências

### Fluxo de Aprendizado
```
Aula 1.1 (Introdução)
    ↓
Aula 1.2 (OWASP Top 10)
    ↓
Aula 1.3 (Shift-Left Security)
    ↓
Aula 1.4 (Threat Modeling)
    ↓
Aula 1.5 (Compliance)
```

### Distribuição de Exercícios
- **Aula 1.1**: 0 exercícios (aula introdutória)
- **Aula 1.2**: 4 exercícios + 1 vídeo introdutório
- **Aula 1.3**: 4 exercícios + 1 vídeo introdutório
- **Aula 1.4**: 5 exercícios + 1 vídeo introdutório
- **Aula 1.5**: 5 exercícios + 1 vídeo introdutório

### Níveis de Dificuldade

#### Por Aula
- **Básico**: Aulas 1.1, 1.2, 1.3
- **Intermediário**: Aulas 1.4, 1.5

#### Por Exercício
- **Básico**: 7 exercícios (~35%)
- **Intermediário**: 9 exercícios (~50%)
- **Avançado**: 2 exercícios (~11%)

---

## 📝 Padrões de Nomenclatura

### IDs de Aulas
- Formato: `lesson-{módulo}-{número}`
- Exemplo: `lesson-1-2`

### IDs de Exercícios
- Formato: `lesson-{módulo}-{aula}-exercise-{número}-{nome-descritivo}`
- Exemplo: `lesson-1-2-exercise-1-identificar-vulnerabilidades`

### IDs de Vídeos Introdutórios
- Formato: `lesson-{módulo}-{aula}-exercises-intro`
- Exemplo: `lesson-1-2-exercises-intro`

### Slugs
- Formato: `kebab-case` (minúsculas com hífens)
- Exemplo: `identificar-vulnerabilidades`

### Arquivos de Vídeo
- Formato: `{título-descriptivo}.mp4`
- Exemplo: `1.1-Introducao_Seguranca_QA.mp4`

### Arquivos de Infográfico
- Formato: `infografico-{localização}.png`
- Exemplo: `infografico-lesson-1-2.png`

---

## ✅ Checklist de Componentes por Aula

Para cada aula, verificar se possui:

- [ ] Front matter completo (layout, title, slug, module, lesson_id, duration, level, prerequisites, video)
- [ ] Vídeo principal da aula
- [ ] Thumbnail do vídeo
- [ ] Infográfico (quando aplicável)
- [ ] Seção de Objetivos de Aprendizado
- [ ] Seção de Conteúdo detalhado
- [ ] Aplicação no Contexto CWI
- [ ] Material Complementar
- [ ] Próximos Passos
- [ ] Quiz com 10 questões (em `_data/quizzes.yml`)
- [ ] Exercícios associados (quando aplicável)
- [ ] Vídeo introdutório dos exercícios (quando há exercícios)

---

## 📌 Notas Importantes

1. **Aula 1.1** não possui exercícios, sendo puramente introdutória
2. Cada aula com exercícios possui um **vídeo introdutório** explicando os exercícios
3. Todos os **infográficos** estão localizados em `assets/images/`
4. Os **vídeos** estão em `assets/videos/`
5. Os **quizzes** são armazenados centralmente em `_data/quizzes.yml`
6. A **ordem dos exercícios** é definida pelo campo `order` em `exercises.yml`
7. Cada exercício possui um **formulário de submissão** incluído via template Jekyll

---

**Última atualização**: Documento criado para mapeamento completo da estrutura do Módulo 1
