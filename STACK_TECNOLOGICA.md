# 🛠️ Stack Tecnológica - Curso Segurança em QA

**Data:** Janeiro 2025  
**Projeto:** Plataforma de Ensino Online - Segurança em QA  
**Tipo:** Site Estático (JAMstack)

---

## 📊 Resumo Executivo

**Stack Principal:** Jekyll (SSG) + SCSS + JavaScript Vanilla  
**Arquitetura:** Static Site Generator (SSG)  
**Deploy:** GitHub Pages (compatível)  
**Complexidade:** Média - Stack moderna mas simples

---

## 🎯 Stack Completa

### Backend / Build System

#### Jekyll 4.3+
- **Tipo:** Static Site Generator (SSG)
- **Versão:** ~> 4.3
- **Função:** Gera site estático a partir de arquivos Markdown e templates
- **Vantagens:**
  - ✅ Rápido (site estático)
  - ✅ SEO-friendly
  - ✅ Fácil deploy (GitHub Pages)
  - ✅ Sem necessidade de banco de dados
  - ✅ Seguro (sem servidor dinâmico)

**Plugins Jekyll:**
- `jekyll-feed` (~> 0.15) - Gera feed RSS/Atom
- `jekyll-sitemap` (~> 1.4) - Gera sitemap.xml
- `jekyll-seo-tag` (~> 2.8) - Meta tags SEO automáticas

**Tema Base:**
- `minima` (~> 2.5) - Tema Jekyll minimalista (customizado)

---

### Frontend - Estilização

#### Sass/SCSS
- **Tipo:** Pré-processador CSS
- **Versão:** Incluído no Jekyll
- **Estilo:** Compressed (produção)
- **Estrutura:**
  ```
  _sass/
  ├── _variables.scss      # Variáveis (cores, espaçamento, tipografia)
  ├── _colors.scss         # Paleta de cores CWI
  ├── _theme.scss          # Mixins e transições
  ├── main.scss            # Arquivo principal
  ├── components/          # Componentes SCSS
  │   ├── _hero.scss
  │   ├── _footer.scss
  │   ├── _empty-states.scss
  │   ├── _skeleton.scss
  │   ├── _toast.scss
  │   ├── _command-palette.scss
  │   └── _interactions.scss
  ├── utilities/           # Utilitários
  │   └── _transitions.scss
  └── animations/          # Animações
      └── _keyframes.scss
  ```

**Características:**
- ✅ Variáveis CSS (custom properties)
- ✅ Mixins reutilizáveis
- ✅ Sistema de design modular
- ✅ Dark mode nativo
- ✅ Responsive design

---

### Frontend - JavaScript

#### JavaScript Vanilla (ES6+)
- **Tipo:** JavaScript puro (sem frameworks)
- **Versão:** ES6+ (Classes, Arrow Functions, Template Literals)
- **Arquitetura:** Modular por funcionalidade

**Módulos JavaScript (13 arquivos):**

1. **analytics.js** - Google Analytics integration
2. **command-palette.js** - Command palette (Cmd+K)
3. **fix-content-height.js** - Ajuste de altura de conteúdo
4. **module-gate.js** - Controle de acesso a módulos
5. **module-summary.js** - Resumo e estatísticas de módulos
6. **navigation.js** - Navegação lateral e breadcrumbs
7. **podcast-player.js** - Player de podcasts
8. **progress-tracker.js** - Rastreamento de progresso
9. **quiz.js** - Sistema de quizzes interativos
10. **skeleton-loader.js** - Loading states
11. **theme-toggle.js** - Alternância tema claro/escuro
12. **toast.js** - Notificações toast
13. **video-player.js** - Player de vídeos

**Características:**
- ✅ Classes ES6 para organização
- ✅ LocalStorage para persistência
- ✅ Event delegation
- ✅ Sem dependências externas
- ✅ Modular e reutilizável

---

### Linguagens de Marcação

#### Markdown (Kramdown)
- **Parser:** Kramdown
- **Função:** Conteúdo das aulas, exercícios, módulos
- **Extensões:** 
  - Syntax highlighting (Rouge)
  - Front matter (YAML)
  - Liquid templates

#### HTML5
- **Templates:** Liquid (Jekyll)
- **Layouts:** 5 layouts customizados
- **Includes:** 12 componentes reutilizáveis

#### YAML
- **Função:** Dados estruturados (collections)
- **Arquivos:**
  - `_data/modules.yml` - Módulos do curso
  - `_data/lessons.yml` - Aulas
  - `_data/exercises.yml` - Exercícios
  - `_data/podcasts.yml` - Podcasts
  - `_data/quizzes.yml` - Quizzes
  - `_data/videos.yml` - Vídeos

---

### Syntax Highlighting

#### Rouge
- **Tipo:** Syntax highlighter
- **Função:** Destacar código em blocos Markdown
- **Suporta:** Múltiplas linguagens de programação

---

### Tipografia

#### Google Fonts - Inter
- **Fonte:** Inter
- **Pesos:** 300, 400, 500, 600, 700
- **Carregamento:** Preconnect + async
- **Fallback:** System fonts (-apple-system, Segoe UI, Roboto)

---

### Analytics & Tracking

#### Google Analytics 4
- **ID:** G-QGD9NFSVPG
- **Tipo:** GA4 (Google Analytics 4)
- **Integração:** Via gtag.js
- **Função:** Tracking de visitantes e comportamento

---

### Armazenamento Local

#### LocalStorage (Browser API)
- **Função:** Persistência de dados do usuário
- **Dados salvos:**
  - Progresso do curso
  - Resultados de quizzes
  - Preferência de tema
  - Posição de podcasts/vídeos

---

### Mídia

#### Formatos Suportados
- **Podcasts:** `.m4a` (27 arquivos)
- **Vídeos:** `.mp4` (25 arquivos)
- **Imagens:** `.png` (19 imagens de podcasts)

**Players:**
- HTML5 Audio API (podcasts)
- HTML5 Video API (vídeos)
- Custom controls com JavaScript

---

## 🏗️ Arquitetura do Projeto

### Estrutura de Diretórios

```
crescidos-qualidade/
├── _config.yml              # Configuração Jekyll
├── _data/                    # Dados YAML (collections)
├── _includes/                # Componentes HTML reutilizáveis
├── _layouts/                 # Templates de página
├── _plugins/                  # Plugins Ruby customizados
├── _sass/                    # Estilos SCSS
├── assets/                   # Assets estáticos
│   ├── js/                   # JavaScript
│   ├── images/               # Imagens
│   ├── podcasts/             # Arquivos de áudio
│   └── videos/               # Arquivos de vídeo
├── modules/                  # Conteúdo do curso
│   └── module-*/             # Módulos individuais
│       ├── index.md          # Página do módulo
│       ├── summary.md        # Resumo do módulo
│       └── lessons/          # Aulas
│           └── exercises/    # Exercícios
└── _site/                    # Build output (gerado)
```

---

## 🔧 Ferramentas de Desenvolvimento

### Gerenciamento de Dependências

#### Bundler
- **Função:** Gerenciar gems Ruby
- **Arquivo:** `Gemfile` + `Gemfile.lock`
- **Comandos:**
  ```bash
  bundle install    # Instalar dependências
  bundle exec       # Executar com gems corretas
  ```

### Versionamento

#### Git
- **Função:** Controle de versão
- **Repositório:** GitHub (assumido)

---

## 📦 Dependências Principais

### Ruby Gems

```ruby
# Core
gem "jekyll", "~> 4.3"              # SSG principal
gem "minima", "~> 2.5"              # Tema base

# Plugins
gem "jekyll-feed", "~> 0.15"        # RSS feed
gem "jekyll-sitemap", "~> 1.4"     # Sitemap
gem "jekyll-seo-tag", "~> 2.8"     # SEO tags
```

### JavaScript

**Nenhuma dependência externa!** ✅
- Todo JavaScript é vanilla (puro)
- Sem npm/node_modules necessário
- Sem build step para JS

### CSS

**Nenhuma dependência externa!** ✅
- SCSS compilado pelo Jekyll
- Sem frameworks CSS (Bootstrap, Tailwind, etc.)
- Design system customizado

---

## 🌐 Deploy & Hosting

### Compatível com:

#### GitHub Pages ✅
- **Suporte nativo:** Jekyll é suportado nativamente
- **Build automático:** GitHub compila automaticamente
- **Custom domain:** Suportado
- **HTTPS:** Automático

#### Netlify ✅
- **Build command:** `bundle exec jekyll build`
- **Publish directory:** `_site`
- **Deploy automático:** Via Git

#### Vercel ✅
- **Build command:** `bundle exec jekyll build`
- **Output directory:** `_site`

#### Qualquer servidor estático ✅
- **Arquivos gerados:** HTML, CSS, JS estáticos
- **Sem necessidade de:** Servidor, banco de dados, runtime

---

## 🎨 Design System

### Cores
- **Sistema:** CSS Custom Properties (variáveis CSS)
- **Paleta:** Baseada em identidade CWI
- **Modos:** Light + Dark mode

### Tipografia
- **Fonte:** Inter (Google Fonts)
- **Escala:** Harmônica (2.75rem → 12px)
- **Pesos:** 5 níveis (300-700)

### Espaçamento
- **Sistema:** 8 níveis (xs → 4xl)
- **Base:** 4px (0.25rem)
- **Grid:** Flexível

### Componentes
- Empty states
- Skeleton loaders
- Toast notifications
- Command palette
- Progress tracker
- Podcast/Video players

---

## 📊 Métricas da Stack

### Tamanho do Projeto
- **Linhas de código:** ~2000+ (estimado)
- **Componentes SCSS:** 7
- **Scripts JavaScript:** 13
- **Layouts Jekyll:** 5
- **Includes:** 12
- **Módulos:** 5+
- **Aulas:** 24+
- **Exercícios:** 18+

### Performance
- **Tipo:** Site estático (rápido)
- **First Load:** < 2s (estimado)
- **SEO:** Excelente (HTML estático)
- **Acessibilidade:** WCAG AA (em progresso)

---

## 🔄 Fluxo de Build

```
1. Jekyll lê arquivos fonte
   ├── Markdown (.md)
   ├── YAML (_data/*.yml)
   ├── SCSS (_sass/*.scss)
   └── Templates Liquid (_layouts/, _includes/)

2. Processamento
   ├── Markdown → HTML (Kramdown)
   ├── SCSS → CSS (Sass)
   ├── Liquid → HTML renderizado
   └── Collections → Páginas

3. Output
   └── _site/ (HTML, CSS, JS estáticos)
```

---

## 🎯 Vantagens da Stack

### ✅ Pontos Fortes

1. **Performance**
   - Site estático = carregamento rápido
   - Sem JavaScript pesado
   - SEO otimizado

2. **Simplicidade**
   - Sem build complexo
   - Sem dependências npm
   - Fácil de entender

3. **Manutenibilidade**
   - Código organizado
   - Componentes reutilizáveis
   - Sistema de design consistente

4. **Deploy**
   - GitHub Pages nativo
   - Qualquer servidor estático
   - CDN-friendly

5. **Custo**
   - Hosting gratuito (GitHub Pages)
   - Sem servidor necessário
   - Sem banco de dados

### ⚠️ Limitações

1. **Funcionalidades Dinâmicas**
   - Sem backend (API externa se necessário)
   - Sem autenticação nativa
   - Sem banco de dados

2. **Build Time**
   - Recompilação necessária para mudanças
   - Não ideal para sites muito grandes (1000+ páginas)

3. **Interatividade**
   - Limitada ao que JavaScript vanilla pode fazer
   - Sem state management complexo

---

## 🚀 Stack em Resumo

| Categoria | Tecnologia | Versão |
|-----------|-----------|--------|
| **SSG** | Jekyll | 4.3+ |
| **CSS** | Sass/SCSS | (via Jekyll) |
| **JS** | JavaScript ES6+ | Vanilla |
| **Markdown** | Kramdown | (via Jekyll) |
| **Syntax** | Rouge | (via Jekyll) |
| **Fontes** | Inter (Google Fonts) | - |
| **Analytics** | Google Analytics 4 | - |
| **Storage** | LocalStorage | Browser API |
| **Deploy** | GitHub Pages | Compatível |

---

## 📚 Recursos Adicionais

### Documentação
- [Jekyll Docs](https://jekyllrb.com/docs/)
- [Liquid Template Language](https://shopify.github.io/liquid/)
- [Sass Documentation](https://sass-lang.com/documentation)
- [Kramdown Syntax](https://kramdown.gettalong.org/syntax.html)

### Ferramentas Úteis
- **Jekyll Admin** (opcional) - Interface admin
- **Jekyll Plugins** - Extensões adicionais
- **Sass Compiler** - Compilação manual (se necessário)

---

## ✅ Conclusão

**Stack:** Moderna, simples e eficiente

**Características:**
- ✅ JAMstack (JavaScript, APIs, Markup)
- ✅ Site estático (rápido e seguro)
- ✅ Zero dependências JavaScript externas
- ✅ Design system customizado
- ✅ Totalmente compatível com GitHub Pages

**Ideal para:**
- Cursos online
- Documentação
- Blogs
- Sites corporativos simples
- Landing pages

**Não ideal para:**
- Aplicações web complexas
- E-commerce completo
- Sistemas com muita interatividade
- Apps que precisam de backend robusto

---

**Última Atualização:** Janeiro 2025
