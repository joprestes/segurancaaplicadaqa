# Qualidade e Segurança da Informação - CWI - Plataforma de Ensino

Plataforma de ensino online construída com Jekyll para cursos estruturados em módulos, aulas e exercícios sobre **Qualidade e Segurança da Informação**. Desenvolvida para profissionais de QA da CWI, aborda desde fundamentos de segurança aplicada à qualidade de software até compliance e práticas avançadas de segurança da informação. Suporta vídeos e imagens, rastreamento de progresso e navegação intuitiva.

## 📋 Índice

- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Sobre o Curso](#sobre-o-curso)
- [Como Rodar](#como-rodar)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Como Utilizar](#como-utilizar)
- [Personalização para Outra Temática](#personalização-para-outra-temática)
- [Alterando Conteúdo](#alterando-conteúdo)
- [Deploy](#deploy)
- [Troubleshooting](#troubleshooting)
- [Créditos](#créditos)

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

Este curso de **Qualidade e Segurança da Informação** foi desenvolvido especificamente para profissionais de QA da CWI Software. O programa aborda:

- **Fundamentos de Segurança**: OWASP Top 10, threat modeling, compliance (LGPD, PCI-DSS, SOC2)
- **Ferramentas e Técnicas**: SAST, DAST, dependency scanning, pentest básico
- **Segurança por Setor**: Requisitos específicos para setores financeiro, educacional, ecommerce e IA
- **DevSecOps**: Integração de segurança em pipelines CI/CD
- **Compliance e Regulamentações**: LGPD, PCI-DSS, SOC2 e outras normas aplicáveis

O curso combina teoria e prática, com exemplos reais de projetos em diferentes setores, permitindo que profissionais de QA integrem segurança no processo de qualidade desde o início do desenvolvimento.

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
├── assets/                  # Recursos estáticos
│   ├── main.scss            # Arquivo principal de estilos (com front matter)
│   ├── js/                 # JavaScript fonte
│   │   ├── emailjs-config.js  # Configuração EmailJS para submissão
│   │   └── ...
│   ├── images/             # Imagens e logos
│   └── videos/             # Arquivos de vídeo (.mp4)
├── documentos-staff/        # Documentação exclusiva para monitores/instrutores
│   ├── resolucao-exercicios/  # Gabaritos e soluções dos exercícios
│   ├── orientacoes-monitores/  # Orientações para correção
│   └── criterios-avaliacao/    # Critérios de avaliação
├── modules/                 # Conteúdo dos módulos
│   ├── module-1/
│   │   ├── index.md        # Página do módulo
│   │   └── lessons/        # Aulas do módulo
│   │       ├── lesson-1-1.md
│   │       └── exercises/  # Exercícios
│   └── ...
├── index.md                 # Página inicial
├── about.md                 # Página sobre
├── Gemfile                  # Dependências Ruby
├── rebuild.sh               # Script para rebuild simples
├── force-rebuild.sh         # Script para rebuild completo
├── fix-all-liquid.py        # Script para corrigir sintaxe Liquid
└── README.md                # Este arquivo
```

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

## 🔄 Personalização para Outra Temática

Para adaptar este projeto para outra temática (ex: React, Vue, Python, etc.), siga estes passos:

### 1. Atualizar Configuração Principal

Edite `_config.yml`:

```yaml
title: "Sua Nova Temática"
description: "Descrição do seu curso"
url: "https://seu-dominio.github.io"
baseurl: "/seu-curso"
author: "Seu Nome"
```

### 2. Atualizar Dados dos Módulos

Edite `_data/modules.yml`:

```yaml
modules:
  - id: module-1
    title: "Fundamentos da Nova Temática"
    slug: "fundamentos"
    duration: "8 horas"
    description: "Descrição do módulo"
    lessons:
      - lesson-1-1
      - lesson-1-2
    order: 1
```

### 3. Atualizar Dados das Aulas

Edite `_data/lessons.yml`:

```yaml
lessons:
  - id: lesson-1-1
    title: "Introdução à Nova Temática"
    slug: "introducao"
    module: module-1
    order: 1
    duration: "60 minutos"
    level: "Básico"
    prerequisites: []
    video:
      file: "assets/videos/01-introducao.mp4"
      title: "Introdução"
      thumbnail: "assets/images/01-introducao.png"
      description: "Descrição do vídeo"
      duration: "45-60 minutos"
```

### 4. Substituir Conteúdo dos Arquivos Markdown

- Edite `index.md` para refletir a nova temática
- Atualize `modules/module-1/index.md` com conteúdo do novo módulo
- Atualize `modules/module-1/lessons/lesson-1-1.md` com conteúdo da nova aula

### 5. Substituir Mídia

- Substitua arquivos em `assets/videos/` pelos seus vídeos
- Substitua imagens em `assets/images/` pelas suas imagens

### 6. Atualizar Metadados de Vídeos

Edite `_data/videos.yml` (se usado) ou adicione diretamente no front matter dos arquivos .md:

```yaml
videos:
  - id: video-1-1
    lesson_id: lesson-1-1
    file: "assets/videos/01-introducao.mp4"
    title: "Introdução"
    description: "Descrição do vídeo"
    duration: "45-60 minutos"
    thumbnail: "assets/images/01-introducao.png"
```

### 7. Atualizar Estilos (Opcional)

Modifique arquivos em `_sass/` para personalizar cores e estilos:

- `_colors.scss`: Cores do tema
- `_theme.scss`: Estilos gerais
- `_variables.scss`: Variáveis SCSS

### 8. Limpar Dados Antigos

Remova ou atualize:
- Conteúdo antigo em `modules/`
- Exercícios antigos em `modules/*/lessons/exercises/`
- Referências antigas nos arquivos YAML

## ✏️ Alterando Conteúdo

### Passo a Passo Detalhado

#### 1. Adicionar um Novo Módulo

**Passo 1.1**: Edite `_data/modules.yml`

```yaml
modules:
  - id: module-6
    title: "Novo Módulo"
    slug: "novo-modulo"
    duration: "8 horas"
    description: "Descrição do novo módulo"
    lessons:
      - lesson-6-1
      - lesson-6-2
    order: 6
```

**Passo 1.2**: Crie o diretório do módulo

```bash
mkdir -p modules/module-6/lessons/exercises
```

**Passo 1.3**: Crie `modules/module-6/index.md`

```markdown
---
layout: module
title: "Novo Módulo"
slug: novo-modulo
duration: "8 horas"
description: "Descrição do novo módulo"
lessons: 
  - "lesson-6-1"
  - "lesson-6-2"
module: module-6
permalink: /modules/novo-modulo/
---

## Conteúdo do Módulo

Aqui vai o conteúdo do módulo...
```

#### 2. Adicionar uma Nova Aula

**Passo 2.1**: Edite `_data/lessons.yml`

```yaml
lessons:
  - id: lesson-6-1
    title: "Nova Aula"
    slug: "nova-aula"
    module: module-6
    order: 1
    duration: "60 minutos"
    level: "Básico"
    prerequisites: []
    video:
      file: "assets/videos/06.1-nova-aula.mp4"
      title: "Nova Aula"
      thumbnail: "assets/images/06.1-nova-aula.png"
      description: "Descrição"
      duration: "45-60 minutos"
```

**Passo 2.2**: Crie `modules/module-6/lessons/lesson-6-1.md`

```markdown
---
layout: lesson
title: "Aula 6.1: Nova Aula"
slug: nova-aula
module: module-6
lesson_id: lesson-6-1
duration: "60 minutos"
level: "Básico"
prerequisites: []
exercises: []
video:
  file: "assets/videos/06.1-nova-aula.mp4"
  title: "Nova Aula"
  thumbnail: "assets/images/06.1-nova-aula.png"
  description: "Descrição"
  duration: "45-60 minutos"
permalink: /modules/novo-modulo/lessons/nova-aula/
---

## Conteúdo da Aula

Aqui vai o conteúdo da aula...
```

**Passo 2.3**: Adicione os arquivos de mídia

- Coloque o vídeo em `assets/videos/06.1-nova-aula.mp4`
- Coloque a imagem/thumbnail em `assets/images/06.1-nova-aula.png`
- (Opcional) Se não houver vídeo, adicione campo `image:` no front matter

**Passo 2.4**: Atualize `_data/videos.yml` se necessário

#### 3. Adicionar um Novo Exercício

**Passo 3.1**: Edite `_data/exercises.yml`

```yaml
exercises:
  - id: lesson-6-1-exercise-1
    title: "Exercício 6.1.1: Primeiro Exercício"
    lesson_id: lesson-6-1
    module: module-6
    slug: primeiro-exercicio
    order: 1
    url: /modules/novo-modulo/lessons/exercises/lesson-6-1-exercise-1-primeiro-exercicio
```

**Passo 3.2**: Crie `modules/module-6/lessons/exercises/lesson-6-1-exercise-1-primeiro-exercicio.md`

```markdown
---
layout: exercise
title: "Exercício 6.1.1: Primeiro Exercício"
slug: primeiro-exercicio
lesson_id: lesson-6-1
module: module-6
order: 1
permalink: /modules/novo-modulo/lessons/exercises/primeiro-exercicio/
---

## Objetivo

Descrição do exercício...

## Instruções

1. Passo 1
2. Passo 2
3. Passo 3

## Solução

```typescript
// Código da solução
```
```

**Passo 3.3**: Atualize a aula para referenciar o exercício

Edite `modules/module-6/lessons/lesson-6-1.md`:

```markdown
---
layout: lesson
...
exercises: 
  - lesson-6-1-exercise-1
...
---
```

#### 4. Editar Conteúdo Existente

**Para editar uma aula existente**:

1. Abra o arquivo `.md` correspondente em `modules/<module>/lessons/`
2. Edite o conteúdo markdown
3. Salve o arquivo
4. O Jekyll recarrega automaticamente (se estiver rodando com `--watch`)

**Para editar metadados**:

1. Edite o arquivo YAML correspondente em `_data/`
2. Salve o arquivo
3. O Jekyll recarrega automaticamente

#### 5. Adicionar Vídeo a uma Aula

**Passo 5.1**: Adicione o vídeo em `assets/videos/`

**Passo 5.2**: Edite `_data/videos.yml`

```yaml
videos:
  - id: video-6-1
    lesson_id: lesson-6-1
    file: "assets/videos/06.1-nova-aula.mp4"
    title: "Nova Aula"
    description: "Descrição"
    duration: "45-60 minutos"
    thumbnail: "assets/images/06.1-nova-aula.png"
```

**Passo 5.3**: Edite a aula para incluir o vídeo

Em `modules/module-6/lessons/lesson-6-1.md`:

```markdown
---
layout: lesson
...
video:
  file: "assets/videos/06.1-nova-aula.mp4"
  thumbnail: "assets/images/podcasts/06.1-nova-aula.png"
  title: "Nova Aula"
  description: "Descrição"
  duration: "45-60 minutos"
---
```

#### 6. Reordenar Módulos/Aulas

**Para reordenar módulos**:

Edite `_data/modules.yml` e ajuste o campo `order`:

```yaml
modules:
  - id: module-1
    order: 1  # Primeiro módulo
  - id: module-2
    order: 2  # Segundo módulo
```

**Para reordenar aulas**:

Edite `_data/lessons.yml` e ajuste o campo `order`:

```yaml
lessons:
  - id: lesson-1-1
    order: 1  # Primeira aula
  - id: lesson-1-2
    order: 2  # Segunda aula
```

#### 7. Atualizar Pré-requisitos

Edite `_data/lessons.yml`:

```yaml
lessons:
  - id: lesson-6-2
    prerequisites: ["lesson-6-1"]  # Requer lesson-6-1
```

#### 8. Modificar Navegação

Edite `_includes/navigation.html` para personalizar o menu de navegação.

#### 9. Personalizar Estilos

**Cores**: Edite `_sass/_colors.scss`

```scss
// O projeto usa CSS Custom Properties (CSS Variables)
:root {
  --color-primary: #your-color;
  --color-primary-hover: #your-hover-color;
  --color-success: #your-success-color;
}
```

**Tema**: Edite `_sass/_theme.scss` para modificar estilos gerais.

**Variáveis**: Edite `_sass/_variables.scss` para ajustar espaçamentos, fontes, etc.

### Formato de Arquivos Markdown

Os arquivos `.md` usam Front Matter YAML no topo:

```markdown
---
layout: lesson
title: "Título"
slug: slug-da-pagina
module: module-1
lesson_id: lesson-1-1
duration: "60 minutos"
level: "Básico"
prerequisites: []
exercises: []
video:
  file: "assets/videos/01-aula.mp4"
  title: "Título do Vídeo"
  thumbnail: "assets/images/01-aula.png"
  description: "Descrição"
  duration: "45-60 minutos"
permalink: /modules/modulo/lessons/aula/
---

## Conteúdo Markdown

Aqui vai o conteúdo da página usando Markdown...
```

### Convenções de Nomenclatura

- **Módulos**: `module-1`, `module-2`, etc.
- **Aulas**: `lesson-1-1`, `lesson-1-2`, etc. (módulo-aula)
- **Exercícios**: `lesson-1-1-exercise-1`, `lesson-1-1-exercise-2`, etc.
- **Slugs**: kebab-case (ex: `introducao-seguranca-qa`)
- **Arquivos de mídia**: Seguir padrão `MM.N-titulo.extensao`

## 🚢 Deploy

### GitHub Pages

**Passo 1**: Configure `_config.yml`

```yaml
url: "https://seu-usuario.github.io"
baseurl: "/nome-do-repositorio"
```

**Passo 2**: Faça build para produção

```bash
JEKYLL_ENV=production bundle exec jekyll build
```

**Passo 3**: Commit e push

```bash
git add .
git commit -m "Build para produção"
git push origin main
```

**Passo 4**: Configure GitHub Pages

1. Vá em Settings > Pages
2. Selecione a branch `main`
3. Selecione a pasta `/docs` ou `/ (root)`
4. Salve

### Netlify

**Passo 1**: Crie `netlify.toml`

```toml
[build]
  command = "bundle exec jekyll build"
  publish = "_site"

[[plugins]]
  package = "@netlify/plugin-jekyll"
```

**Passo 2**: Faça deploy via Netlify CLI ou interface web

### Vercel

**Passo 1**: Crie `vercel.json`

```json
{
  "buildCommand": "bundle exec jekyll build",
  "outputDirectory": "_site"
}
```

**Passo 2**: Faça deploy via Vercel CLI ou interface web

## 🛠️ Scripts Utilitários

O projeto inclui scripts utilitários para facilitar o desenvolvimento e manutenção:

### `rebuild.sh`

Script simples para limpar cache e recompilar o site Jekyll.

```bash
./rebuild.sh
```

**O que faz:**
- Remove caches do Jekyll (`_site`, `.jekyll-cache`, `.sass-cache`)
- Recompila o site com `bundle exec jekyll build`

**Quando usar:**
- Quando mudanças no CSS/SCSS não aparecem
- Após atualizar configurações do Jekyll
- Para garantir build limpo antes de deploy

### `force-rebuild.sh`

Script avançado para forçar recompilação completa com validações.

```bash
./force-rebuild.sh
```

**O que faz:**
- Para processos Jekyll em execução
- Limpa todos os caches (incluindo `.jekyll-metadata`)
- Verifica se arquivos fonte essenciais existem
- Recompila com trace (logs detalhados)
- Valida se CSS foi compilado corretamente
- Gera `build.log` com saída completa

**Quando usar:**
- Quando `rebuild.sh` não resolve problemas
- Para debug de problemas de compilação
- Antes de fazer deploy em produção

### `fix-all-liquid.py`

Script Python para corrigir problemas de sintaxe Liquid em arquivos Markdown.

```bash
python3 fix-all-liquid.py
```

**O que faz:**
- Processa todos os arquivos `.md` em `modules/`
- Protege blocos de código que contêm sintaxe Liquid (`{{ }}`)
- Adiciona tags `{% raw %}` e `{% endraw %}` automaticamente
- Evita conflitos entre sintaxe Liquid e código de exemplo

**Quando usar:**
- Após adicionar código de exemplo que contém `{{ }}` ou `|`
- Quando Jekyll interpreta incorretamente código dentro de blocos markdown
- Para corrigir erros de parsing em arquivos de conteúdo

**Requisitos:**
- Python 3.x instalado

## 🧪 Test IDs e Automação de Testes

O projeto utiliza `data-testid` para identificar elementos interativos, facilitando a automação de testes e garantindo testes mais robustos e estáveis.

### Padrão de Nomenclatura

Todos os test IDs seguem o formato: `{component}-{element}-{identifier}`

**Exemplos:**
- `nav-link-home` - Link de navegação para home
- `nav-module-link-fundamentos` - Link de módulo específico
- `lesson-nav-prev` - Navegação para aula anterior
- `mark-lesson-complete-btn` - Botão para marcar aula como concluída
- `quiz-option-0` - Opção de resposta do quiz (índice 0)
- `video-play-btn` - Botão de play do vídeo (se aplicável)

### Regras de Nomenclatura

1. **Use kebab-case** (minúsculas com hífens)
2. **Seja descritivo mas conciso**
3. **Inclua contexto** quando necessário (ex: `nav-`, `lesson-`, `module-`)
4. **Use sufixos** para tipo de elemento:
   - `-btn` para botões
   - `-link` para links
   - `-select` para selects
   - `-input` ou `-slider` para inputs
5. **Evite duplicatas** - use identificadores únicos quando necessário

### Quando Usar Test IDs

**Sempre adicione `data-testid` em:**
- Botões interativos
- Links de navegação
- Inputs e selects
- Elementos gerados dinamicamente via JavaScript
- Componentes reutilizáveis

**Exemplo em HTML/Liquid:**
```html
<a href="{{ '/' | relative_url }}" data-testid="nav-link-home">Início</a>
<button data-testid="mark-lesson-complete-btn">Marcar como concluída</button>
```

**Exemplo em JavaScript (elementos dinâmicos):**
```javascript
const optionButton = document.createElement('button');
optionButton.setAttribute('data-testid', `quiz-option-${index}`);
```

### Checklist para Novos Componentes

Ao adicionar novos componentes ou elementos interativos, verifique:

- [ ] Todos os botões têm `data-testid`?
- [ ] Todos os links de navegação têm `data-testid`?
- [ ] Todos os inputs/selects têm `data-testid`?
- [ ] Elementos dinâmicos gerados via JS têm `data-testid`?
- [ ] Test IDs seguem o padrão de nomenclatura?
- [ ] Test IDs são únicos no contexto da página?
- [ ] Test IDs são descritivos e semânticos?

### Documentação Completa

Para análise detalhada de cobertura de test IDs, consulte:
- `docs/TEST_IDS_AUDIT.md` - Relatório completo de auditoria de test IDs

## 🔍 Troubleshooting

### Problema: `bundle install` falha

**Solução**: Instale dependências do sistema

```bash
# macOS
brew install ruby

# Ubuntu/Debian
sudo apt-get install ruby-full build-essential

# Windows
# Use RubyInstaller
```

### Problema: Jekyll não inicia

**Solução**: Verifique se todas as dependências estão instaladas

```bash
bundle install
bundle exec jekyll doctor
```

### Problema: Mudanças não aparecem

**Solução**: 
1. Limpe o cache: `bundle exec jekyll clean`
2. Rebuild: `bundle exec jekyll build`
3. Reinicie o servidor

### Problema: Erro de permissão

**Solução**: 

```bash
# macOS/Linux
sudo gem install bundler

# Ou use rbenv/rvm para gerenciar versões Ruby
```

### Problema: Assets não carregam

**Solução**: 
1. Verifique se os caminhos estão corretos em `_config.yml`
2. Use `relative_url` nos templates: `{{ '/assets/file.css' | relative_url }}`
3. Verifique se os arquivos existem em `assets/`

### Problema: Vídeo não reproduz

**Solução**:
1. Verifique se o arquivo existe no caminho especificado
2. Verifique o formato do arquivo (MP4 recomendado para vídeos)
3. Verifique os metadados no front matter do arquivo .md ou em `_data/videos.yml` (se usado)
4. Verifique o console do navegador para erros JavaScript

### Problema: Progresso não salva

**Solução**:
1. Verifique se o localStorage está habilitado no navegador
2. Verifique o console do navegador para erros JavaScript
3. Verifique se `assets/js/progress-tracker.js` está carregado

## 📚 Recursos Adicionais

### Documentação Jekyll

- [Jekyll Docs](https://jekyllrb.com/docs/)
- [Liquid Template Language](https://shopify.github.io/liquid/)
- [Jekyll Front Matter](https://jekyllrb.com/docs/front-matter/)

### Markdown

- [Markdown Guide](https://www.markdownguide.org/)
- [GitHub Flavored Markdown](https://github.github.com/gfm/)

### YAML

- [YAML Syntax](https://yaml.org/spec/1.2/spec.html)

## 🤝 Contribuindo

1. Faça fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

## 📝 Licença

[Especifique a licença do projeto aqui]

## 👤 Autor

[Seu Nome] - [seu-email@exemplo.com]

---

## 🙏 Créditos

Este projeto é baseado na plataforma de ensino original desenvolvida por [OnoSendae](https://github.com/OnoSendae):

**Projeto Original:** [Angular Expert 5 Dias - Plataforma de Ensino](https://github.com/OnoSendae/angular)

A estrutura base, sistema de módulos, aulas e exercícios, player de vídeo, rastreamento de progresso e outros componentes foram adaptados do projeto original para o curso de **Qualidade e Segurança da Informação** da CWI.

**Agradecimentos:** Agradecemos ao autor original por disponibilizar uma base sólida e bem estruturada que facilitou a criação desta plataforma educacional.

---

**Nota**: Este projeto está configurado para o curso de **Qualidade e Segurança da Informação** da CWI, mas pode ser facilmente adaptado para qualquer temática seguindo os passos de personalização acima.
