# Análise de Compatibilidade: Stack Jekyll + Fly.io

## 🔴 Problemas Identificados

### 1. **Gemfile.lock com Plataforma macOS** (CRÍTICO)
**Problema:**
- O `Gemfile.lock` está configurado para `arm64-darwin` (macOS)
- Contém gems específicas para macOS:
  - `ffi (1.17.3-arm64-darwin)`
  - `google-protobuf (4.33.2-arm64-darwin)`
  - `sass-embedded (1.97.2-arm64-darwin)`

**Impacto:**
- Build falha no Fly.io (Linux) porque tenta usar gems compiladas para macOS
- Extensões nativas não funcionam

**Solução:**
- Regenerar `Gemfile.lock` para Linux
- Ou remover e deixar o Bundler gerar durante o build

### 2. **Alpine Linux + Extensões Nativas** (ALTO)
**Problema:**
- Alpine usa `musl` libc (não `glibc`)
- `sass-embedded` e `google-protobuf` podem ter problemas
- Dependências nativas podem falhar na compilação

**Impacto:**
- Build pode falhar ao compilar extensões nativas
- Runtime errors com gems que dependem de bibliotecas C

**Solução:**
- Usar imagem Debian-based (`ruby:3.1-slim`) em vez de Alpine
- Mais compatível com gems Ruby

### 3. **Jekyll Serve em Produção** (MÉDIO)
**Problema:**
- `jekyll serve` não é otimizado para produção
- Usa mais memória que necessário
- Não é tão rápido quanto servidor estático
- Pode ter problemas com health checks

**Impacto:**
- Maior uso de memória
- Slower response times
- Possíveis timeouts em health checks

**Solução:**
- Usar multi-stage build: build Jekyll + servir com Nginx
- Muito mais eficiente para sites estáticos

### 4. **Health Checks Muito Curtos** (MÉDIO)
**Problema:**
- `timeout = "2s"` pode ser muito curto
- Jekyll pode demorar para iniciar
- Grace period de 5s pode não ser suficiente

**Impacto:**
- Health checks falham prematuramente
- App reinicia constantemente

**Solução:**
- Aumentar `timeout` para 5-10s
- Aumentar `grace_period` para 10-15s

### 5. **Memória Potencialmente Insuficiente** (BAIXO)
**Problema:**
- 256MB pode ser pouco para Jekyll serve
- Especialmente com muitos plugins e conteúdo

**Impacto:**
- OOM (Out of Memory) errors
- Crashes durante build ou runtime

**Solução:**
- Aumentar para 512MB se necessário
- Ou usar build estático (usa menos memória)

---

## ✅ Soluções Propostas

### Solução 1: Dockerfile Corrigido (Debian-based)

**Vantagens:**
- Mais compatível com gems Ruby
- Menos problemas com extensões nativas
- Ainda usa Jekyll serve (simples)

**Desvantagens:**
- Imagem um pouco maior
- Ainda não é ideal para produção

### Solução 2: Multi-Stage Build com Nginx (RECOMENDADO)

**Vantagens:**
- Muito mais rápido
- Usa menos memória
- Melhor para produção
- Imagem final menor

**Desvantagens:**
- Configuração um pouco mais complexa
- Precisa configurar Nginx

---

## 📊 Comparação de Compatibilidade

| Aspecto | Alpine (Atual) | Debian | Multi-Stage Nginx |
|--------|----------------|--------|-------------------|
| Compatibilidade Gems | ⚠️ Média | ✅ Alta | ✅ Alta |
| Tamanho Imagem | ✅ Pequeno | ⚠️ Médio | ✅ Pequeno |
| Performance | ⚠️ Média | ⚠️ Média | ✅ Excelente |
| Memória Usada | ⚠️ Alta | ⚠️ Alta | ✅ Baixa |
| Facilidade Setup | ✅ Fácil | ✅ Fácil | ⚠️ Média |
| Produção Ready | ❌ Não | ⚠️ Parcial | ✅ Sim |

---

## 🎯 Recomendação Final

**Para resolver os problemas de deploy:**

1. **Imediato**: Usar Debian-based image (Solução 1)
2. **Ideal**: Migrar para multi-stage com Nginx (Solução 2)

**Ordem de prioridade:**
1. ✅ Regenerar Gemfile.lock para Linux
2. ✅ Mudar para Debian-based image
3. ✅ Ajustar health checks no fly.toml
4. ✅ (Opcional) Migrar para Nginx

---

## 🔧 Checklist de Correção

- [ ] Regenerar Gemfile.lock para Linux
- [ ] Atualizar Dockerfile para Debian
- [ ] Ajustar timeouts no fly.toml
- [ ] Testar build localmente
- [ ] Fazer deploy no Fly.io
- [ ] Monitorar logs após deploy
- [ ] (Opcional) Implementar multi-stage build

---

## 📝 Notas Técnicas

### Por que Alpine pode falhar?

1. **musl vs glibc**: Muitas gems são testadas apenas com glibc
2. **Bibliotecas ausentes**: Alpine é minimalista, pode faltar libs
3. **Compilação**: Extensões nativas podem precisar de libs específicas

### Por que Debian é melhor?

1. **glibc**: Padrão da indústria, melhor suporte
2. **Pacotes**: Mais bibliotecas disponíveis
3. **Testado**: Maioria das gems testadas em Debian/Ubuntu

### Por que Nginx é melhor?

1. **Performance**: Servidor web otimizado
2. **Memória**: Usa ~10-20MB vs ~100-200MB do Jekyll serve
3. **Concorrência**: Lida melhor com múltiplas requisições
4. **Cache**: Pode cachear arquivos estáticos

---

**Última atualização**: Janeiro 2026