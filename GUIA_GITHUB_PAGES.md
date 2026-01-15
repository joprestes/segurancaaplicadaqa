# Guia Rápido: Deploy no GitHub Pages

## ✅ Boa Notícia!

Você **já tem** a configuração do GitHub Pages pronta!

## 🚀 Passo a Passo (5 minutos)

### 1. Ativar GitHub Pages no Repositório

1. Acesse: https://github.com/joprestes/segurancaaplicadaqa/settings/pages
2. Em **Source**, selecione: **GitHub Actions**
3. Clique em **Save**

### 2. Fazer Push para Main

```bash
git add _config.yml
git commit -m "fix: ajusta URL do GitHub Pages no _config.yml"
git push origin main
```

### 3. Aguardar Deploy Automático

- O GitHub Actions vai fazer o deploy automaticamente
- Acompanhe em: https://github.com/joprestes/segurancaaplicadaqa/actions
- Quando terminar, o site estará em: **https://joprestes.github.io/segurancaaplicadaqa**

## 📋 O que já está configurado

✅ Workflow do GitHub Actions (`.github/workflows/deploy.yml`)
- Deploy automático quando você faz push na `main`
- Build do Jekyll
- Deploy para GitHub Pages

✅ Configuração do Jekyll (`_config.yml`)
- URL configurada para GitHub Pages
- Baseurl configurado

## 🎯 Vantagens do GitHub Pages

- ✅ **Grátis** (para repositórios públicos)
- ✅ **Simples** - só fazer push
- ✅ **Automático** - deploy a cada push
- ✅ **Sem configuração de servidor**
- ✅ **HTTPS automático**
- ✅ **CDN global**

## 🔧 Se precisar ajustar a URL

Se você quiser usar um domínio customizado ou mudar o baseurl:

1. Edite `_config.yml`:
   ```yaml
   url: "https://seu-dominio.com"  # ou deixe como está
   baseurl: ""  # vazio para servir na raiz, ou "/caminho"
   ```

2. Faça commit e push:
   ```bash
   git add _config.yml
   git commit -m "ajusta URL do GitHub Pages"
   git push origin main
   ```

## 📊 Monitorar Deploy

- **Actions**: https://github.com/joprestes/segurancaaplicadaqa/actions
- **Settings**: https://github.com/joprestes/segurancaaplicadaqa/settings/pages


## 🎉 Pronto!

Depois de ativar o GitHub Pages e fazer push, seu site estará online em:
**https://joprestes.github.io/segurancaaplicadaqa** 🚀
