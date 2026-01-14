# Deploy Após Remover Máquinas

## Status Atual
✅ Máquinas removidas  
✅ Dockerfile configurado  
✅ Script de inicialização (start.sh) pronto  
✅ fly.toml configurado  

## Próximos Passos

### 1. Verificar se não há máquinas restantes

```bash
flyctl machine list -a segurancaaplicadaqa-tnnq1a
```

Deve retornar vazio ou mostrar apenas máquinas removidas.

### 2. Fazer Deploy

```bash
cd crescidos-qualidade
flyctl deploy -a segurancaaplicadaqa-tnnq1a
```

Isso vai:
- Fazer build da imagem Docker
- Criar novas máquinas
- Fazer deploy da aplicação

### 3. Monitorar o Deploy

Durante o deploy, você verá:
- Build da imagem
- Push para o registry
- Criação de novas máquinas
- Inicialização do app

### 4. Verificar Status

```bash
# Ver status do app
flyctl status -a segurancaaplicadaqa-tnnq1a

# Ver logs em tempo real
flyctl logs -a segurancaaplicadaqa-tnnq1a

# Ver máquinas criadas
flyctl machine list -a segurancaaplicadaqa-tnnq1a
```

### 5. Abrir o App

```bash
flyctl open -a segurancaaplicadaqa-tnnq1a
```

## O que Esperar

### Durante o Build
- Instalação de dependências do sistema
- Instalação de gems Ruby
- Build do site Jekyll
- Criação da imagem Docker

### Durante o Deploy
- Upload da imagem
- Criação de novas máquinas
- Inicialização do servidor Jekyll
- Health checks

### Tempo Estimado
- Build: 3-5 minutos
- Deploy: 1-2 minutos
- Total: ~5-7 minutos

## Troubleshooting

### Problema: "App not found"

**Solução:**
```bash
# Verificar se o app existe
flyctl apps list

# Se não existir, criar
flyctl launch
```

### Problema: "Build failed"

**Solução:**
- Verificar logs: `flyctl logs -a segurancaaplicadaqa-tnnq1a`
- Verificar se o Dockerfile está correto
- Tentar build local primeiro: `docker build -t test .`

### Problema: "Machine creation failed"

**Solução:**
```bash
# Verificar status
flyctl status -a segurancaaplicadaqa-tnnq1a

# Ver logs
flyctl logs -a segurancaaplicadaqa-tnnq1a

# Tentar novamente
flyctl deploy -a segurancaaplicadaqa-tnnq1a --no-cache
```

### Problema: App não inicia

**Solução:**
```bash
# Ver logs detalhados
flyctl logs -a segurancaaplicadaqa-tnnq1a

# Verificar máquinas
flyctl machine list -a segurancaaplicadaqa-tnnq1a

# Reiniciar
flyctl apps restart -a segurancaaplicadaqa-tnnq1a
```

## Comandos Úteis

```bash
# Status completo
flyctl status -a segurancaaplicadaqa-tnnq1a

# Logs em tempo real
flyctl logs -a segurancaaplicadaqa-tnnq1a

# Abrir no navegador
flyctl open -a segurancaaplicadaqa-tnnq1a

# SSH no container
flyctl ssh console -a segurancaaplicadaqa-tnnq1a

# Ver métricas
flyctl metrics -a segurancaaplicadaqa-tnnq1a
```

## Checklist Final

- [ ] Máquinas antigas removidas
- [ ] Deploy executado com sucesso
- [ ] Máquinas novas criadas
- [ ] App iniciado corretamente
- [ ] Health checks passando
- [ ] Site acessível via `flyctl open`

## Próximos Passos Após Deploy Bem-Sucedido

1. Verificar se o site está acessível
2. Testar funcionalidades principais
3. Monitorar logs por alguns minutos
4. Verificar métricas de performance
5. Configurar domínio customizado (opcional)
