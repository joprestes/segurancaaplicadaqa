# Curso de Qualidade e Segurança da Informação - CWI

**Curso online** sobre **Qualidade e Segurança da Informação** desenvolvido especificamente para profissionais de QA da CWI Software. Este curso foi criado a partir da plataforma de ensino desenvolvida pelo projeto [OnoSendae](https://github.com/OnoSendae/angular) e adaptado para abordar desde fundamentos de segurança aplicada à qualidade de software até compliance e práticas avançadas de segurança da informação.

O curso é construído com Jekyll e suporta vídeos, imagens, rastreamento de progresso e navegação intuitiva entre módulos, aulas e exercícios.

## 📋 Índice

- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Sobre o Curso](#sobre-o-curso)
- [Como Rodar](#como-rodar)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Como Utilizar](#como-utilizar)
- [Estrutura Técnica do Curso](#estrutura-técnica-do-curso)
- [Créditos e Origem](#créditos-e-origem)

## 🔧 Requisitos

- **Ruby** 2.7 ou superior
- **RubyGems** (geralmente vem com Ruby)
- **Bundler** (instalado via `gem install bundler`)
- **Git** (para controle de versão)

### Verificando Instalações

```bash
ruby --version    # Deve ser 2.7+
gem --version     # Deve estar instalado
bundler --version # Deve estar instalado
```

## 📦 Instalação

### 1. Clone o Repositório

```bash
git clone <url-do-repositorio>
cd crescidos-qualidade
```

### 2. Instale as Dependências

```bash
bundle install
```

Isso instalará todas as gems necessárias definidas no `Gemfile`:
- Jekyll 4.3+
- jekyll-feed
- jekyll-sitemap
- jekyll-seo-tag
- minima (tema Jekyll)

### 3. Verifique a Instalação

```bash
bundle exec jekyll --version
```

## 📚 Sobre o Curso

Este **curso online de Qualidade e Segurança da Informação** foi desenvolvido especificamente para profissionais de QA da CWI Software. O programa aborda:

- **Fundamentos de Segurança**: OWASP Top 10, threat modeling, compliance (LGPD, PCI-DSS, SOC2)
- **Ferramentas e Técnicas**: SAST, DAST, dependency scanning, pentest básico
- **Segurança por Setor**: Requisitos específicos para setores financeiro, educacional, ecommerce e IA
- **DevSecOps**: Integração de segurança em pipelines CI/CD
- **Compliance e Regulamentações**: LGPD, PCI-DSS, SOC2 e outras normas aplicáveis

O curso combina teoria e prática, com exemplos reais de projetos em diferentes setores, permitindo que profissionais de QA integrem segurança no processo de qualidade desde o início do desenvolvimento.

**Nota**: Este é um curso específico sobre Qualidade e Segurança da Informação. O código-fonte está disponível para referência e estudo, mas o foco principal é o conteúdo educacional deste curso.

## 🚀 Como Rodar

### Modo Desenvolvimento (com hot reload)

```bash
bundle exec jekyll serve
```

O site estará disponível em: `http://localhost:4000`

### Modo Desenvolvimento com Watch (recomendado)

```bash
bundle exec jekyll serve --watch
```

Isso recarrega automaticamente quando você faz alterações nos arquivos.

### Opções Adicionais

```bash
# Rodar em porta específica
bundle exec jekyll serve --port 3000

# Rodar com drafts habilitados
bundle exec jekyll serve --drafts

# Build sem servidor (gera arquivos estáticos)
bundle exec jekyll build

# Build para produção (otimizado)
JEKYLL_ENV=production bundle exec jekyll build
```

### Acessando o Site

Após iniciar o servidor, acesse:
- **URL Local**: `http://localhost:4000`
- **URL da Rede**: `http://<seu-ip>:4000` (para acessar de outros dispositivos)

## 📁 Estrutura do Projeto

### Organização de Assets

Os assets (vídeos, imagens, infográficos) estão organizados por módulo para facilitar a manutenção e escalabilidade:

- **`assets/module-{N}/videos/`**: Vídeos das aulas e exercícios do módulo
- **`assets/module-{N}/images/infograficos/`**: Infográficos das aulas
- **`assets/module-{N}/images/podcasts/`**: Imagens de podcasts
- **`assets/shared/images/`**: Imagens compartilhadas (logo, infográficos gerais)

Consulte `assets/README.md` para mais detalhes sobre convenções de nomenclatura e como adicionar novos assets.

```
crescidos-qualidade/
├── _config.yml              # Configuração principal do Jekyll
├── _data/                   # Arquivos de dados YAML/JSON
│   ├── modules.yml          # Definição dos módulos
│   ├── lessons.yml          # Definição das aulas
│   ├── exercises.yml        # Definição dos exercícios
│   ├── videos.yml          # Metadados dos vídeos
│   ├── quizzes.yml          # Metadados dos quizzes
│   └── monitores.json      # Configuração de monitores para correção
├── _includes/               # Componentes reutilizáveis
│   ├── header.html
│   ├── footer.html
│   ├── navigation.html
│   ├── breadcrumbs.html
│   ├── video-player.html
│   ├── progress-tracker.html
│   ├── exercise-submission-form.html  # Formulário de submissão de exercícios
│   └── ...
├── _layouts/               # Templates de página
│   ├── default.html
│   ├── module.html
│   ├── lesson.html
│   ├── exercise.html
│   └── module-summary.html
├── _sass/                   # Estilos SCSS (partials)
│   ├── _theme.scss
│   ├── _variables.scss
│   ├── _colors.scss
│   ├── components/          # Componentes de estilo
│   ├── utilities/           # Utilitários
│   └── animations/         # Animações
├── assets/                  # Recursos estáticos organizados por módulo
│   ├── main.scss            # Arquivo principal de estilos (com front matter)
│   ├── js/                 # JavaScript fonte
│   │   ├── emailjs-config.js  # Configuração EmailJS para submissão
│   │   └── ...
│   ├── module-1/           # Assets do Módulo 1
│   │   ├── videos/         # Vídeos das aulas e exercícios
│   │   └── images/
│   │       ├── infograficos/  # Infográficos das aulas
│   │       └── podcasts/   # Imagens de podcasts
│   ├── module-2/           # Assets do Módulo 2
│   │   ├── videos/
│   │   └── images/
│   │       ├── infograficos/
│   │       └── podcasts/
│   ├── module-3/           # Assets do Módulo 3
│   │   ├── videos/
│   │   └── images/
│   │       ├── infograficos/
│   │       └── podcasts/
│   ├── module-4/           # Assets do Módulo 4
│   │   ├── videos/
│   │   └── images/
│   │       ├── infograficos/
│   │       └── podcasts/
│   └── shared/             # Assets compartilhados (logo, imagens gerais)
│       └── images/
├── documentos-staff/        # Documentação exclusiva para monitores/instrutores
│   ├── resolucao-exercicios/  # Gabaritos e soluções dos exercícios
│   ├── orientacoes-monitores/  # Orientações para correção
│   ├── criterios-avaliacao/    # Critérios de avaliação
│   └── processos/              # Processos e mapeamentos internos
│       ├── MAPEAMENTO_ESTRUTURA_MODULO_*.md  # Mapeamentos de estrutura
│       └── README.md            # Documentação dos processos
├── _module-summaries/       # Resumos dos módulos (coleção Jekyll)
│   ├── module-1-summary.md
│   ├── module-2-summary.md
│   ├── module-3-summary.md
│   └── module-4-summary.md
├── modules/                 # Conteúdo dos módulos
│   ├── module-1/
│   │   ├── index.md        # Página do módulo
│   │   └── lessons/        # Aulas do módulo
│   │       ├── lesson-1-1.md
│   │       └── exercises/  # Exercícios
│   └── ...
├── scripts/                 # Scripts utilitários
│   ├── fix-all-liquid.py        # Script para corrigir sintaxe Liquid
│   ├── force-rebuild.sh         # Script para rebuild completo
│   ├── rebuild.sh               # Script para rebuild simples
│   ├── regenerar-gemfile-lock.sh # Script para regenerar Gemfile.lock
│   ├── start.sh                 # Script para iniciar servidor (Docker)
│   └── README.md                # Documentação dos scripts
├── index.md                 # Página inicial
├── about.md                 # Página sobre
├── Gemfile                  # Dependências Ruby
└── README.md                # Este arquivo
```

### Scripts Utilitários

Os scripts utilitários estão organizados na pasta `scripts/` para facilitar a manutenção e uso:

- **`scripts/fix-all-liquid.py`**: Corrige sintaxe Liquid em arquivos Markdown
- **`scripts/force-rebuild.sh`**: Força recompilação completa do Jekyll (limpa todos os caches)
- **`scripts/rebuild.sh`**: Limpa cache e recompila o Jekyll
- **`scripts/regenerar-gemfile-lock.sh`**: Regenera Gemfile.lock (útil para builds Docker)
- **`scripts/start.sh`**: Inicia servidor Jekyll (usado em Docker)

Consulte `scripts/README.md` para mais detalhes sobre uso e configuração dos scripts.

### Documentação de Processos

A pasta `documentos-staff/processos/` contém documentação interna sobre processos e mapeamentos:

- **Mapeamentos de Estrutura**: Arquivos `MAPEAMENTO_ESTRUTURA_MODULO_*.md` documentam a estrutura completa de cada módulo
- **Revisões**: Relatórios de revisão e padronização de conteúdo

Consulte `documentos-staff/processos/README.md` para mais informações.

## 🎯 Como Utilizar

### Navegação

1. **Página Inicial** (`/`): Lista todos os módulos disponíveis
2. **Módulo** (`/modules/<slug>`): Página do módulo com lista de aulas
3. **Aula** (`/modules/<slug>/lessons/<lesson-slug>`): Conteúdo da aula com player de vídeo ou imagem
4. **Exercício** (`/modules/<slug>/lessons/exercises/<exercise-slug>`): Exercício prático

### Funcionalidades

- **Player de Vídeo**: Reproduz vídeos em formato MP4
- **Imagens**: Exibe imagens quando não há vídeo disponível
- **Rastreamento de Progresso**: Salva progresso localmente no navegador
- **Navegação entre Aulas**: Botões de próxima/anterior
- **Tema Claro/Escuro**: Alternância automática baseada em preferências do sistema
- **Breadcrumbs**: Navegação hierárquica
- **Sistema de Submissão de Exercícios**: Formulário integrado com EmailJS para envio de respostas

## Convenção de Test IDs

Para facilitar automação de testes, use `data-testid` em todos os elementos interativos e em estados importantes.

### Padrão de nomenclatura

- Formato: `data-testid="[contexto]-[elemento]-[tipo]"`
- Use kebab-case, nomes semânticos e estáveis
- Em listas dinâmicas, incluir identificador único (id, slug ou índice)

### Boas práticas

- Manter unicidade por página
- Não depender de estrutura HTML ou CSS no nome
- Preservar `id` existente quando for usado por JavaScript

### Checklist rápido

- [ ] Botões, links, inputs, selects e checkboxes têm `data-testid`
- [ ] Elementos dinâmicos gerados via JavaScript têm `data-testid`
- [ ] Containers de estado (ex.: empty state, toast, progress) têm `data-testid`
- [ ] Nomes são consistentes e sem duplicidade

### Segurança e Limitações

- **Progresso local**: O progresso é salvo no `localStorage`, portanto pode ser alterado manualmente pelo usuário.
- **Regras client-side**: Liberação de módulos e validações no front-end não substituem validações no servidor.
- **Uploads**: A validação de arquivos ocorre no cliente e deve ser complementada com validação server-side quando aplicável.

### Sistema de Submissão de Exercícios

O projeto inclui um sistema completo de submissão de exercícios que permite aos alunos enviarem suas respostas diretamente pela plataforma.

#### Funcionalidades

- **Formulário de Submissão**: Cada exercício possui um formulário integrado
- **Upload de Arquivos**: Suporte para PDF, DOCX, DOC, MD e TXT (máx. 10MB)
- **Seleção de Monitor**: Dropdown dinâmico com lista de monitores configurados
- **Validação Client-side**: Validação de campos obrigatórios, tipo e tamanho de arquivo
- **Integração EmailJS**: Envio automático de emails com anexos

#### Configuração

1. **Configurar EmailJS**:
   - Criar conta no [EmailJS](https://www.emailjs.com/)
   - Configurar service (Gmail/Outlook)
   - Criar template de email
   - Atualizar `assets/js/emailjs-config.js` com suas credenciais:
     ```javascript
     const EMAILJS_CONFIG = {
       serviceId: 'seu_service_id',
       templateId: 'seu_template_id',
       publicKey: 'sua_public_key',
     };
     ```

2. **Configurar Monitores**:
   - Editar `_data/monitores.json` com a lista de monitores:
     ```json
     {
       "monitores": [
         {
           "nome": "Nome do Monitor",
           "email": "monitor@exemplo.com"
         }
       ]
     }
     ```

#### Documentação para Monitores

As soluções dos exercícios e critérios de avaliação estão disponíveis em `documentos-staff/`:

- **`documentos-staff/resolucao-exercicios/`**: Gabaritos e soluções detalhadas
- **`documentos-staff/orientacoes-monitores/`**: Orientações para correção
- **`documentos-staff/criterios-avaliacao/`**: Critérios de avaliação padronizados

**Nota**: A pasta `documentos-staff/` está excluída do build Jekyll (via `_config.yml`), mas está disponível no repositório Git para acesso dos monitores/instrutores.

### Estrutura de Dados

O projeto usa arquivos YAML em `_data/` para definir a estrutura:

- **modules.yml**: Define módulos e suas aulas
- **lessons.yml**: Define aulas com metadados (duração, nível, pré-requisitos)
- **exercises.yml**: Define exercícios vinculados às aulas
- **videos.yml**: Metadados dos vídeos (opcional)

## 🔧 Estrutura Técnica do Curso

Este curso foi desenvolvido usando a plataforma de ensino base do projeto [OnoSendae](https://github.com/OnoSendae/angular). A estrutura técnica permite:

- **Módulos e Aulas**: Organização hierárquica do conteúdo
- **Exercícios Práticos**: Sistema de submissão integrado
- **Rastreamento de Progresso**: Acompanhamento do aprendizado
- **Player de Vídeo**: Reprodução de conteúdo multimídia
- **Navegação Intuitiva**: Interface responsiva e acessível

Para entender melhor a estrutura técnica e como o conteúdo é organizado, consulte a seção [Estrutura do Projeto](#-estrutura-do-projeto) acima.

---

## 🙏 Créditos e Origem

Este **curso online** foi criado a partir da plataforma de ensino desenvolvida pelo projeto [OnoSendae](https://github.com/OnoSendae/angular).

**Projeto Base Original:** [Angular Expert 5 Dias - Plataforma de Ensino](https://github.com/OnoSendae/angular)

A estrutura base, sistema de módulos, aulas e exercícios, player de vídeo, rastreamento de progresso e outros componentes foram adaptados do projeto original para criar este curso específico de **Qualidade e Segurança da Informação** para profissionais de QA da CWI Software.

**Agradecimentos:** Agradecemos ao projeto OnoSendae por disponibilizar uma base sólida e bem estruturada que facilitou a criação deste curso educacional.

---

**Nota**: Este é um curso específico sobre Qualidade e Segurança da Informação. O código-fonte está disponível para referência técnica, mas o objetivo principal é fornecer conteúdo educacional estruturado sobre segurança da informação aplicada à qualidade de software.

**Quer criar seu próprio curso?** Se você deseja criar um curso online com estrutura similar, acesse o repositório original do [OnoSendae](https://github.com/OnoSendae/angular), faça um fork e adapte para sua temática. O projeto base oferece toda a estrutura necessária para criar cursos online estruturados em módulos, aulas e exercícios.
