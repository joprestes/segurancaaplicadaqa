# Troubleshooting - Resolução de Problemas Comuns

Este documento contém soluções para problemas comuns encontrados durante o desenvolvimento e manutenção do projeto.

---

## 📋 Índice

1. [Problemas de Compilação SCSS](#problemas-de-compilação-scss)
2. [Problemas com Jekyll](#problemas-com-jekyll)
3. [Problemas de Layout e CSS](#problemas-de-layout-e-css)
4. [Problemas com Git](#problemas-com-git)
5. [Problemas de Dependências](#problemas-de-dependências)

---

## 🎨 Problemas de Compilação SCSS

### ❌ Erro: `expected "{"` ao compilar SCSS

**Sintoma:**
```
Error: expected "{".
  ╷
3 │ @import "main";
  │               ^
```

**Causas possíveis:**
1. Front-matter YAML malformado no arquivo `assets/main.scss`
2. Import recursivo ou circular
3. Arquivo SCSS com sintaxe incorreta

**Solução:**

1. **Verificar front-matter:** O arquivo `assets/main.scss` deve começar com:
   ```scss
   ---
   ---
   ```
   (Duas linhas com `---`, não tudo em uma linha)

2. **Verificar imports recursivos:** Se o erro persistir, o problema pode ser import circular. Neste caso, copie o conteúdo diretamente:
   ```bash
   cat _sass/main.scss > /tmp/main_sass_content.scss && \
   printf '---\n---\n' > assets/main.scss && \
   cat /tmp/main_sass_content.scss >> assets/main.scss
   ```

3. **Limpar cache:** Às vezes ajuda limpar o cache do Jekyll:
   ```bash
   rm -rf _site .jekyll-cache .sass-cache
   bundle exec jekyll build
   ```

### ⚠️ Warnings de Deprecação do Dart Sass

**Sintoma:**
```
DEPRECATION WARNING [import]: Sass @import rules are deprecated
DEPRECATION WARNING [global-builtin]: Global built-in functions are deprecated
```

**Solução:**
- Estes são apenas **avisos**, não erros bloqueantes
- O site vai compilar e funcionar normalmente
- Para corrigir futuramente, migrar de `@import` para `@use`/`@forward` e usar módulos SASS modernos

---

## 🏗️ Problemas com Jekyll

### ❌ Jekyll não compila após mudanças

**Sintoma:**
- Servidor Jekyll não reflete mudanças
- Páginas não são geradas

**Soluções:**

1. **Forçar rebuild completo:**
   ```bash
   rm -rf _site .jekyll-cache
   bundle exec jekyll serve --force_polling
   ```

2. **Verificar _config.yml:**
   - Mudanças no `_config.yml` exigem restart do servidor
   - Pare o servidor (Ctrl+C) e inicie novamente

3. **Usar force_polling:**
   ```bash
   bundle exec jekyll serve --force_polling --livereload
   ```

### ❌ Erro: "Could not find gem"

**Sintoma:**
```
Could not find gem 'jekyll-feed' in locally installed gems
```

**Solução:**
```bash
bundle install
```

### ❌ Porta 4000 já em uso

**Sintoma:**
```
Address already in use - bind(2) for 127.0.0.1:4000
```

**Soluções:**

1. **Usar outra porta:**
   ```bash
   bundle exec jekyll serve --port 4001
   ```

2. **Matar processo na porta 4000:**
   ```bash
   lsof -ti:4000 | xargs kill -9
   ```

---

## 🎭 Problemas de Layout e CSS

### ❌ CSS não carrega ou layout quebrado

**Sintoma:**
- Página aparece sem estilo
- Logo gigante, layout desalinhado
- CSS não aplicado

**Soluções:**

1. **Verificar assets/main.scss:**
   - Confirmar que o arquivo existe
   - Verificar front-matter correto (---\n---)
   - Verificar imports dos componentes

2. **Limpar cache do navegador:**
   - Apertar `Cmd+Shift+R` (Mac) ou `Ctrl+Shift+R` (Windows/Linux)
   - Ou abrir DevTools e clicar com botão direito no refresh → "Empty Cache and Hard Reload"

3. **Verificar caminho do CSS no HTML:**
   - Abrir `_layouts/default.html`
   - Confirmar que existe link para `/assets/main.css`

4. **Rebuildar Jekyll:**
   ```bash
   rm -rf _site .jekyll-cache .sass-cache
   bundle exec jekyll serve --force_polling
   ```

### ❌ Dark mode não funciona

**Sintoma:**
- Botão de tema não alterna cores
- Tema fica preso em light/dark

**Soluções:**

1. **Verificar JavaScript:**
   - Confirmar que `assets/js/theme-toggle.js` está carregado
   - Abrir DevTools → Console para ver erros

2. **Limpar localStorage:**
   ```javascript
   // Cole no Console do navegador:
   localStorage.removeItem('theme');
   location.reload();
   ```

3. **Verificar CSS variables:**
   - Abrir DevTools → Elements → Computed
   - Verificar se as variáveis `--color-*` estão definidas

---

## 🔄 Problemas com Git

### ❌ Reverter último commit

**Para reverter o último commit de forma segura:**

```bash
git revert HEAD --no-edit
```

**Se houver alterações locais não commitadas:**

```bash
# Opção 1: Descartar todas as alterações
git reset --hard HEAD
git clean -fd
git revert HEAD --no-edit

# Opção 2: Salvar alterações temporariamente
git stash
git revert HEAD --no-edit
git stash pop
```

### ❌ Branch sem tracking

**Sintoma:**
```
There is no tracking information for the current branch.
```

**Solução:**
```bash
git branch --set-upstream-to=origin/nome-da-branch nome-da-branch
```

---

## 📦 Problemas de Dependências

### ❌ Bundler desatualizado

**Sintoma:**
```
Bundler version mismatch
```

**Solução:**
```bash
gem install bundler
bundle update --bundler
bundle install
```

### ❌ Ruby version incorreta

**Sintoma:**
```
Your Ruby version is X.X.X, but your Gemfile specified Y.Y.Y
```

**Soluções:**

1. **Verificar versão instalada:**
   ```bash
   ruby -v
   ```

2. **Instalar versão correta (usando rbenv):**
   ```bash
   rbenv install 3.3.0
   rbenv local 3.3.0
   ```

3. **Atualizar Gemfile:**
   - Editar `Gemfile` e ajustar versão do Ruby

---

## 🚀 Comandos Úteis de Diagnóstico

### Verificar status geral do projeto

```bash
# Status do Git
git status

# Verificar dependências
bundle list

# Verificar versões
ruby -v
bundle -v
jekyll -v

# Testar compilação sem servidor
bundle exec jekyll build --verbose

# Ver logs completos
bundle exec jekyll serve --trace
```

### Resetar projeto completamente

```bash
# CUIDADO: Isso remove TODAS as alterações locais!
git reset --hard HEAD
git clean -fd
rm -rf _site .jekyll-cache .sass-cache node_modules
bundle install
bundle exec jekyll serve --force_polling
```

---

## 📞 Quando Pedir Ajuda

Se nenhuma solução acima funcionar:

1. **Copiar mensagem de erro completa**
2. **Anotar o que estava fazendo quando o erro ocorreu**
3. **Verificar se o problema é reproduzível**
4. **Executar com `--trace` para ver stack trace completo:**
   ```bash
   bundle exec jekyll serve --trace
   ```

---

## 📝 Histórico de Problemas Resolvidos

### 2026-01-12: Erro de import recursivo no SCSS
- **Problema:** `expected "{"` ao compilar `assets/main.scss`
- **Causa:** Import recursivo de `@import "main"` causando loop infinito
- **Solução:** Copiar conteúdo de `_sass/main.scss` inline para `assets/main.scss`
- **Status:** ✅ Resolvido

---

## 📚 Recursos Adicionais

- [Documentação Jekyll](https://jekyllrb.com/docs/)
- [Sass Documentation](https://sass-lang.com/documentation)
- [Troubleshooting Jekyll Build Errors](https://jekyllrb.com/docs/troubleshooting/)
- [Git Documentation](https://git-scm.com/doc)
