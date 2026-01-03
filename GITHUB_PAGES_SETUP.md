# 🚀 Guia de Configuração do GitHub Pages

Este guia vai te ajudar a configurar o GitHub Pages para o repositório `angular-expert-5-days-site`.

## 📋 Pré-requisitos

- ✅ Repositório criado no GitHub: `https://github.com/OnoSendae/angular.git`
- ✅ Código commitado e pronto para push
- ✅ Acesso de escrita ao repositório

---

## 🔧 Passo a Passo

### 1️⃣ Atualizar URLs no `_config.yml`

O arquivo `_config.yml` já está configurado com:
```yaml
url: "https://onosendae.github.io"
baseurl: "/angular"
```

✅ **Já está correto!** Não precisa alterar nada.

---

### 2️⃣ Fazer Push do Código para o GitHub

Se ainda não fez o push inicial:

```bash
cd angular-expert-5-days-site

# Inicializar git (se ainda não foi feito)
git init

# Adicionar todos os arquivos
git add .

# Fazer commit inicial
git commit -m "Initial commit: Angular Expert 5 Dias site"

# Adicionar remote (se ainda não foi adicionado)
git remote add origin https://github.com/OnoSendae/angular.git

# Fazer push para a branch main
git branch -M main
git push -u origin main
```

---

### 3️⃣ Configurar GitHub Pages no Repositório

1. **Acesse o repositório no GitHub**: `https://github.com/OnoSendae/angular`

2. **Vá em Settings** (Configurações):
   - Clique na aba **Settings** no topo do repositório

3. **Navegue até Pages**:
   - No menu lateral esquerdo, role até encontrar **Pages**
   - Ou acesse diretamente: `https://github.com/OnoSendae/angular/settings/pages`

4. **Configure a Source**:
   - Em **Source**, selecione: **GitHub Actions**
   - ⚠️ **NÃO selecione** "Deploy from a branch"
   - O GitHub Actions vai fazer o deploy automaticamente

5. **Salve as configurações**:
   - Clique em **Save** (se necessário)

---

### 4️⃣ Verificar o Workflow do GitHub Actions

O arquivo `.github/workflows/deploy.yml` já está configurado corretamente:

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches:
      - main
  workflow_dispatch:

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      
      - name: Setup Ruby
        uses: ruby/setup-ruby@v1
        with:
          ruby-version: '3.1'
          bundler-cache: true
      
      - name: Install dependencies
        run: bundle install
      
      - name: Build site
        run: bundle exec jekyll build
      
      - name: Deploy to GitHub Pages
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./_site
```

✅ **Já está correto!** Não precisa alterar nada.

---

### 5️⃣ Ativar o GitHub Actions

1. **Vá para a aba Actions**:
   - No repositório, clique na aba **Actions**

2. **Verifique se os workflows estão habilitados**:
   - Se aparecer uma mensagem sobre habilitar workflows, clique em **"I understand my workflows, enable them"**

3. **Disparar o primeiro deploy**:
   - Após fazer push, o workflow deve executar automaticamente
   - Ou você pode executar manualmente:
     - Vá em **Actions** > **Deploy to GitHub Pages**
     - Clique em **Run workflow** > **Run workflow**

---

### 6️⃣ Aguardar o Deploy

1. **Monitore o progresso**:
   - Vá para a aba **Actions**
   - Clique no workflow em execução
   - Acompanhe os logs de cada step

2. **Verificar se concluiu com sucesso**:
   - ✅ Todos os steps devem ter check verde
   - ⚠️ Se algum step falhar, verifique os logs

---

### 7️⃣ Acessar o Site

Após o deploy concluir com sucesso:

1. **URL do site**: `https://onosendae.github.io/angular/`

2. **Primeira publicação pode levar alguns minutos**:
   - Geralmente 1-2 minutos após o workflow concluir
   - Pode levar até 10 minutos na primeira vez

3. **Verificar se está funcionando**:
   - Acesse a URL acima
   - Verifique se o conteúdo está carregando corretamente

---

## 🔍 Troubleshooting (Solução de Problemas)

### ❌ Workflow não está executando

**Problema**: O workflow não executa após push

**Solução**:
1. Verifique se o arquivo `.github/workflows/deploy.yml` existe
2. Verifique se está na branch `main`
3. Verifique se os workflows estão habilitados em Settings > Actions

---

### ❌ Build falha

**Problema**: O step "Build site" falha

**Solução**:
1. Verifique os logs do workflow
2. Verifique se o `Gemfile` está correto
3. Verifique se há erros de sintaxe nos arquivos Markdown/YAML

---

### ❌ Deploy falha

**Problema**: O step "Deploy to GitHub Pages" falha

**Solução**:
1. Verifique se o GitHub Pages está configurado para usar GitHub Actions
2. Verifique se há permissões suficientes no repositório
3. Verifique os logs do workflow para mais detalhes

---

### ❌ Site não carrega

**Problema**: O site retorna 404 ou não carrega

**Solução**:
1. Aguarde alguns minutos (primeira publicação pode demorar)
2. Verifique se o `baseurl` no `_config.yml` está correto: `/angular`
3. Verifique se o workflow concluiu com sucesso
4. Limpe o cache do navegador (Ctrl+Shift+R ou Cmd+Shift+R)

---

### ❌ Assets não carregam (CSS, JS, imagens)

**Problema**: CSS/JS/imagens não aparecem

**Solução**:
1. Verifique se os caminhos estão usando `relative_url` nos templates
2. Verifique se o `baseurl` está correto no `_config.yml`
3. Verifique se os arquivos estão na pasta `assets/`

---

## ✅ Checklist Final

Antes de considerar tudo pronto, verifique:

- [ ] Código foi feito push para o GitHub
- [ ] GitHub Pages está configurado para usar GitHub Actions
- [ ] Workflow executou com sucesso
- [ ] Site está acessível em `https://onosendae.github.io/angular/`
- [ ] Navegação entre páginas funciona
- [ ] CSS e JavaScript carregam corretamente
- [ ] Player de podcast funciona
- [ ] Sistema de progresso funciona

---

## 🔄 Atualizações Futuras

Para atualizar o site:

1. **Faça suas alterações** localmente
2. **Commit e push**:
   ```bash
   git add .
   git commit -m "Descrição das alterações"
   git push origin main
   ```
3. **O GitHub Actions vai fazer o deploy automaticamente** 🚀

---

## 📝 Configurações Adicionais

### Google Analytics

Para ativar o Google Analytics:

1. Edite `_config.yml`:
   ```yaml
   google_analytics:
     id: "G-SEU-ID-AQUI"
     enabled: true
   ```

2. Faça commit e push

### Custom Domain (Opcional)

Se quiser usar um domínio customizado:

1. Configure o domínio em Settings > Pages > Custom domain
2. Adicione o arquivo `CNAME` na raiz do repositório
3. Atualize o `url` no `_config.yml`

---

## 🎉 Pronto!

Seu site Angular Expert 5 Dias está no ar! 🚀

**URL**: https://onosendae.github.io/angular/

---

## 📞 Suporte

Se tiver problemas:

1. Verifique os logs do GitHub Actions
2. Consulte a [documentação do GitHub Pages](https://docs.github.com/en/pages)
3. Consulte a [documentação do Jekyll](https://jekyllrb.com/docs/)

---

**Última atualização**: Janeiro 2026

