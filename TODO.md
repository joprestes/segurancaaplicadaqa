# Lista de Tarefas - Angular Expert 5 Dias Site

## ✅ Concluído Automaticamente

- [x] Estrutura base do Jekyll criada
- [x] Arquivos YAML de dados criados (_data/*.yml)
- [x] Layouts e includes criados
- [x] Estilos SCSS implementados
- [x] JavaScript do player e tracker implementado
- [x] Google Analytics configurado
- [x] **25 aulas migradas** para estrutura Jekyll
- [x] **5 páginas de módulos criadas**
- [x] **119 exercícios migrados**
- [x] **18 arquivos de podcast copiados** para assets/podcasts/
- [x] Breadcrumbs implementados
- [x] Página 404 criada
- [x] GitHub Actions workflow configurado

## 🔴 Crítico - Antes do Deploy

### Configuração Inicial
- [ ] Criar repositório GitHub `angular-expert-5-days-site`
- [ ] Configurar Google Analytics ID no `_config.yml`:
  ```yaml
  google_analytics:
    id: "G-SEU-ID-AQUI"
    enabled: true
  ```
- [ ] Atualizar URL e baseurl no `_config.yml` após criar repositório:
  ```yaml
  url: "https://seu-usuario.github.io"
  baseurl: "/angular-expert-5-days-site"  # ou nome do repositório
  ```
- [ ] Atualizar URL no `robots.txt` com a URL final do site

### Verificação de Conteúdo
- [ ] Verificar se todas as 25 aulas foram migradas corretamente
- [ ] Verificar front matter de todas as aulas
- [ ] Verificar se exercícios estão vinculados corretamente nas aulas
- [ ] Verificar se podcasts estão referenciados corretamente
- [ ] Revisar conteúdo das aulas migradas

## 🟡 Importante - Testes Locais

### Setup Local
- [ ] Instalar dependências: `cd angular-expert-5-days-site && bundle install`
- [ ] Testar build local: `bundle exec jekyll build`
- [ ] Testar servidor local: `bundle exec jekyll serve`
- [ ] Acessar `http://localhost:4000` e verificar funcionamento

### Testes de Funcionalidades
- [ ] Verificar se todas as páginas carregam corretamente
- [ ] Testar navegação entre módulos e aulas
- [ ] Testar player de podcast (carregar arquivo de teste)
- [ ] Testar sistema de progresso (localStorage)
- [ ] Verificar breadcrumbs em todas as páginas
- [ ] Verificar responsividade em mobile
- [ ] Verificar responsividade em tablet
- [ ] Verificar responsividade em desktop

### Testes do Player
- [ ] Play/Pause funciona
- [ ] Barra de progresso interativa funciona
- [ ] Controle de velocidade funciona
- [ ] Controle de volume funciona
- [ ] Persistência de progresso funciona
- [ ] Indicador visual aparece quando tocando
- [ ] Player funciona em diferentes navegadores

### Testes do Progress Tracker
- [ ] Marcar aula como completa funciona
- [ ] Progresso geral é calculado corretamente
- [ ] Progresso por módulo é calculado corretamente
- [ ] Dados persistem no localStorage
- [ ] Indicadores visuais aparecem na navegação

### Testes de Google Analytics
- [ ] Script GA4 carrega corretamente (quando ID configurado)
- [ ] Eventos de podcast são enviados
- [ ] Eventos de progresso são enviados
- [ ] Page views são rastreados
- [ ] Tempo na página é rastreado
- [ ] Scroll depth é rastreado

## 🟢 SEO e Acessibilidade

- [ ] Verificar meta tags em todas as páginas
- [ ] Adicionar structured data (JSON-LD) para curso nos layouts
- [ ] Verificar títulos de página únicos
- [ ] Verificar descrições meta únicas
- [ ] Testar acessibilidade com leitor de tela
- [ ] Verificar contraste de cores (WCAG AA)
- [ ] Verificar navegação por teclado
- [ ] Adicionar alt text em imagens (quando houver)

## 📋 Checklist de Deploy

### Antes do Primeiro Deploy
- [ ] Todas as tarefas críticas concluídas
- [ ] Testes locais passando
- [ ] Google Analytics configurado
- [ ] URLs atualizadas no _config.yml
- [ ] Conteúdo revisado

### Processo de Deploy
- [ ] Criar repositório GitHub
- [ ] Fazer commit inicial:
  ```bash
  cd angular-expert-5-days-site
  git init
  git add .
  git commit -m "Initial commit: Angular Expert 5 Dias site"
  git branch -M main
  git remote add origin https://github.com/seu-usuario/angular-expert-5-days-site.git
  git push -u origin main
  ```
- [ ] Configurar GitHub Pages no repositório (Settings > Pages)
- [ ] Verificar se GitHub Actions executou com sucesso
- [ ] Acessar site publicado e verificar funcionamento

### Pós-Deploy
- [ ] Verificar se site está acessível
- [ ] Testar todas as funcionalidades no ambiente de produção
- [ ] Verificar Google Analytics recebendo dados
- [ ] Testar em diferentes navegadores
- [ ] Testar em diferentes dispositivos
- [ ] Verificar sitemap.xml gerado (será em /sitemap.xml)
- [ ] Verificar robots.txt acessível
- [ ] Enviar sitemap para Google Search Console

## 📝 Notas Importantes

### Estrutura Criada
- ✅ 25 aulas migradas com front matter completo
- ✅ 5 páginas de módulos criadas
- ✅ 119 exercícios migrados
- ✅ 18 arquivos de podcast copiados
- ✅ Todos os componentes JavaScript implementados
- ✅ Estilos SCSS completos e responsivos

### Arquivos de Configuração
- `_config.yml` - Precisa atualizar URL e Google Analytics ID
- `robots.txt` - Precisa atualizar URL do sitemap
- `.github/workflows/deploy.yml` - Já configurado

### Comandos Úteis

```bash
# Instalar dependências
cd angular-expert-5-days-site
bundle install

# Servidor local
bundle exec jekyll serve

# Build para produção
bundle exec jekyll build

# Verificar estrutura
bundle exec jekyll doctor
```

### Próximos Passos Imediatos
1. Configurar Google Analytics ID
2. Criar repositório GitHub
3. Fazer commit e push
4. Configurar GitHub Pages
5. Testar site publicado

---

**Status**: Estrutura completa criada ✅  
**Pronto para**: Configuração final e deploy 🚀
