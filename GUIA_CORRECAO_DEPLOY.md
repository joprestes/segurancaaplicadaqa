# Guia de Correção: Problemas de Deploy no Fly.io

## 🔍 Problemas Identificados

1. **Gemfile.lock com plataforma macOS** - Gems compiladas para macOS não funcionam no Linux
2. **Alpine Linux incompatível** - Problemas com extensões nativas (sass-embedded, google-protobuf)
3. **Health checks muito curtos** - Jekyll demora para iniciar
4. **Jekyll serve em produção** - Não é ideal, usa muita memória

## ✅ Solução Rápida (Correção Imediata)

### Passo 1: Regenerar Gemfile.lock

**Opção A: Usar script (recomendado)**
```bash
./regenerar-gemfile-lock.sh
```

**Opção B: Manual**
```bash
# Remover Gemfile.lock
rm Gemfile.lock

# Fazer commit
git add Gemfile.lock
git commit -m "chore: remove Gemfile.lock para regenerar no build Linux"
git push
```

O Dockerfile atualizado já está configurado para regenerar o lock automaticamente se não existir.

### Passo 2: Dockerfile já foi atualizado ✅

O Dockerfile foi atualizado para:
- ✅ Usar Debian-based (`ruby:3.1-slim`) em vez de Alpine
- ✅ Regenerar Gemfile.lock automaticamente se necessário
- ✅ Melhor compatibilidade com gems Ruby

### Passo 3: fly.toml já foi atualizado ✅

O `fly.toml` foi atualizado com:
- ✅ Health checks mais longos (timeout: 10s, grace_period: 15s)
- ✅ Melhor tolerância a startup lento

### Passo 4: Fazer Deploy

```bash
fly deploy
```

## 🚀 Solução Ideal (Recomendada para Produção)

### Migrar para Multi-Stage Build com Nginx

**Vantagens:**
- ⚡ Muito mais rápido
- 💾 Usa menos memória (128MB vs 256MB)
- 🎯 Otimizado para produção
- 📦 Imagem final menor

### Passo 1: Usar Dockerfile.nginx

```bash
# Renomear arquivos
mv Dockerfile Dockerfile.old
mv Dockerfile.nginx Dockerfile

mv fly.toml fly.toml.old
mv fly.toml.nginx fly.toml
```

### Passo 2: Fazer Deploy

```bash
fly deploy
```

### Passo 3: Verificar

```bash
# Ver status
fly status

# Ver logs
fly logs

# Abrir no navegador
fly open
```

## 📊 Comparação

| Aspecto | Atual (Jekyll Serve) | Nginx (Recomendado) |
|---------|---------------------|---------------------|
| Memória | 256MB | 128MB |
| Tempo de Resposta | ~50-100ms | ~5-10ms |
| Concorrência | Limitada | Alta |
| Cache | Não | Sim |
| Produção Ready | ⚠️ | ✅ |

## 🔧 Troubleshooting

### Problema: Build ainda falha

**Solução:**
1. Verificar logs: `fly logs`
2. Testar build local: `docker build -t test .`
3. Verificar se todas as dependências estão no Gemfile

### Problema: Health checks falham

**Solução:**
1. Aumentar `grace_period` no fly.toml
2. Verificar se o app está respondendo na porta correta
3. Testar localmente: `docker run -p 8080:8080 test`

### Problema: Memória insuficiente

**Solução:**
1. Aumentar memória: `fly scale memory 512`
2. Ou migrar para Nginx (usa menos memória)

## 📝 Checklist

- [ ] Regenerar Gemfile.lock (ou remover)
- [ ] Verificar Dockerfile atualizado (Debian-based)
- [ ] Verificar fly.toml atualizado (health checks)
- [ ] Fazer deploy
- [ ] Verificar logs
- [ ] (Opcional) Migrar para Nginx

## 🎯 Próximos Passos

1. **Imediato**: Fazer deploy com correções atuais
2. **Esta semana**: Migrar para Nginx (melhor performance)
3. **Futuro**: Configurar domínio customizado

---

**Última atualização**: Janeiro 2026