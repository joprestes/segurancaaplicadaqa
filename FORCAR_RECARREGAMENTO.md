# 🔄 Forçar Recarregamento das Alterações

## ⚠️ Problema: Alterações não aparecem

As alterações estão no código, mas o Jekyll e o navegador precisam ser atualizados.

## ✅ Solução Passo a Passo

### 1. Parar o Jekyll (se estiver rodando)
No terminal onde o Jekyll está rodando, pressione: `Ctrl+C`

### 2. Limpar TUDO e Recompilar

Execute estes comandos:

```bash
cd "/Users/joelmadeoliveiraprestesferreira/Desktop/POC 3/poc3/crescidos-qualidade"

# Limpar todos os caches
rm -rf _site
rm -rf .jekyll-cache
rm -rf .sass-cache
rm -rf .sass-cache

# Recompilar do zero
bundle exec jekyll build --trace
```

### 3. Reiniciar o Servidor

```bash
bundle exec jekyll serve --force_polling --livereload
```

O flag `--force_polling` força o Jekyll a detectar mudanças.
O flag `--livereload` recarrega o navegador automaticamente.

### 4. Limpar Cache do Navegador

**IMPORTANTE:** Faça um Hard Refresh:

- **Chrome/Edge**: `Ctrl+Shift+R` (Windows) ou `Cmd+Shift+R` (Mac)
- **Firefox**: `Ctrl+F5` (Windows) ou `Cmd+Shift+R` (Mac)
- **Safari**: `Cmd+Option+R`

**OU** abra DevTools (F12) → Network → marque "Disable cache" → recarregue

### 5. Verificar se Funcionou

Após fazer tudo acima, verifique:

- ✅ **Footer**: Deve ter design melhorado (títulos maiores, melhor espaçamento)
- ✅ **Empty State**: Na página de resumo, quando não há quizzes, deve mostrar componente bonito com ícone e botão
- ✅ **Navegação**: Links "← Anterior" e "Próximo →" devem ter espaçamento adequado (não colados)
- ✅ **Exercícios**: Devem abrir sem erro 404

## 🔍 Verificação Rápida no Console

Abra o Console do navegador (F12 → Console) e verifique:

1. **Erros JavaScript?** Se houver erros, o `module-summary.js` pode não estar executando
2. **CSS carregado?** Verifique se `main.css` foi atualizado (Network tab → veja timestamp)

## 🐛 Se Ainda Não Funcionar

### Verificar se arquivos existem:

```bash
# Verificar se footer.scss existe
ls -la _sass/components/_footer.scss

# Verificar se está sendo importado
grep "footer" _sass/main.scss

# Verificar se module-summary.js tem createEmptyState
grep "createEmptyState" assets/js/module-summary.js
```

### Verificar erros de compilação:

```bash
bundle exec jekyll build --trace 2>&1 | grep -i error
```

### Verificar se JavaScript está sendo carregado:

No Console do navegador, digite:
```javascript
// Verificar se ModuleSummary existe
typeof ModuleSummary

// Verificar se empty-state styles estão carregados
document.querySelector('.empty-state')
```

## 📝 Checklist Final

- [ ] Jekyll foi **parado** e **reiniciado**?
- [ ] Cache foi **limpo** (`rm -rf _site .jekyll-cache .sass-cache`)?
- [ ] Site foi **recompilado** (`bundle exec jekyll build`)?
- [ ] Servidor foi **reiniciado** com `--force_polling`?
- [ ] Cache do **navegador** foi limpo (Hard Refresh)?
- [ ] DevTools está com **"Disable cache"** marcado?

## 🚀 Comando Tudo-em-Um

Execute este comando para fazer tudo de uma vez:

```bash
cd "/Users/joelmadeoliveiraprestesferreira/Desktop/POC 3/poc3/crescidos-qualidade" && \
rm -rf _site .jekyll-cache .sass-cache && \
bundle exec jekyll build && \
echo "✅ Pronto! Agora rode: bundle exec jekyll serve --force_polling"
```

Depois, no navegador, faça **Hard Refresh** (`Cmd+Shift+R` ou `Ctrl+Shift+R`).
