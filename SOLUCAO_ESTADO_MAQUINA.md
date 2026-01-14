# Solução: Erro de Estado da Máquina no Fly.io

## Erro
```
[PM07] failed to change machine state: machine still active, refusing to start
```

## Causa
Há uma máquina que ainda está ativa e o Fly.io está recusando iniciar uma nova instância. Isso geralmente acontece quando:
- Uma máquina não foi parada corretamente
- Há um conflito de estado entre máquinas
- A máquina está em um estado inconsistente

## Solução Passo a Passo

### 1. Verificar Estado das Máquinas

```bash
# Listar todas as máquinas do app
flyctl machine list -a segurancaaplicadaqa-tnnq1a

# Ou se o app for outro nome
flyctl machine list -a crescidos-qualidade
```

Isso vai mostrar:
- ID da máquina
- Estado atual (started, stopped, etc.)
- Região
- Última atualização

### 2. Parar Todas as Máquinas Ativas

```bash
# Parar todas as máquinas do app
flyctl machine stop -a segurancaaplicadaqa-tnnq1a --all

# Ou parar uma máquina específica
flyctl machine stop -a segurancaaplicadaqa-tnnq1a <machine-id>
```

### 3. Verificar se as Máquinas Foram Paradas

```bash
flyctl machine list -a segurancaaplicadaqa-tnnq1a
```

Todas as máquinas devem estar com estado "stopped".

### 4. Remover Máquinas Problemáticas (se necessário)

Se uma máquina estiver em estado inconsistente e não conseguir parar:

```bash
# Remover uma máquina específica (CUIDADO: isso remove permanentemente)
flyctl machine remove <machine-id> -a segurancaaplicadaqa-tnnq1a --force

# Ou remover todas as máquinas paradas
flyctl machine remove -a segurancaaplicadaqa-tnnq1a --all --force
```

**⚠️ ATENÇÃO**: Só use `--force` se tiver certeza. Isso remove a máquina permanentemente.

### 5. Reiniciar o App

Depois de parar/remover as máquinas problemáticas:

```bash
# Fazer deploy novamente (isso criará novas máquinas)
flyctl deploy -a segurancaaplicadaqa-tnnq1a

# Ou iniciar manualmente
flyctl apps restart -a segurancaaplicadaqa-tnnq1a
```

### 6. Verificar Status

```bash
# Ver status do app
flyctl status -a segurancaaplicadaqa-tnnq1a

# Ver logs
flyctl logs -a segurancaaplicadaqa-tnnq1a
```

## Solução Alternativa: Usar o Dashboard Web

Se os comandos CLI não funcionarem:

1. Acesse: https://fly.io/apps/segurancaaplicadaqa-tnnq1a
2. Vá em **Machines**
3. Para cada máquina ativa:
   - Clique nos três pontos (...)
   - Selecione **Stop**
4. Depois de parar todas:
   - Clique em **Deploy** ou **Restart**

## Comandos Úteis

```bash
# Listar máquinas
flyctl machine list -a segurancaaplicadaqa-tnnq1a

# Ver detalhes de uma máquina específica
flyctl machine status <machine-id> -a segurancaaplicadaqa-tnnq1a

# Parar uma máquina
flyctl machine stop <machine-id> -a segurancaaplicadaqa-tnnq1a

# Parar todas as máquinas
flyctl machine stop --all -a segurancaaplicadaqa-tnnq1a

# Remover uma máquina (permanente)
flyctl machine remove <machine-id> -a segurancaaplicadaqa-tnnq1a

# Reiniciar app
flyctl apps restart -a segurancaaplicadaqa-tnnq1a

# Ver status geral
flyctl status -a segurancaaplicadaqa-tnnq1a
```

## Troubleshooting

### Problema: Máquina não para

**Solução:**
```bash
# Forçar parada
flyctl machine stop <machine-id> -a segurancaaplicadaqa-tnnq1a --force

# Se ainda não funcionar, remover
flyctl machine remove <machine-id> -a segurancaaplicadaqa-tnnq1a --force
```

### Problema: Múltiplas máquinas ativas

**Solução:**
```bash
# Parar todas de uma vez
flyctl machine stop --all -a segurancaaplicadaqa-tnnq1a

# Verificar
flyctl machine list -a segurancaaplicadaqa-tnnq1a
```

### Problema: Erro persiste após parar máquinas

**Solução:**
1. Aguarde alguns minutos (pode levar tempo para o estado sincronizar)
2. Verifique novamente: `flyctl machine list`
3. Se ainda houver máquinas ativas, remova-as: `flyctl machine remove <id> --force`
4. Faça deploy novamente: `flyctl deploy`

## Prevenção

Para evitar esse problema no futuro:

1. **Sempre pare máquinas antes de fazer deploy:**
   ```bash
   flyctl machine stop --all -a segurancaaplicadaqa-tnnq1a
   flyctl deploy -a segurancaaplicadaqa-tnnq1a
   ```

2. **Use auto_stop_machines no fly.toml:**
   ```toml
   [http_service]
     auto_stop_machines = true
     auto_start_machines = true
     min_machines_running = 0
   ```
   Isso já está configurado no seu `fly.toml`.

3. **Monitore o estado das máquinas regularmente:**
   ```bash
   flyctl machine list -a segurancaaplicadaqa-tnnq1a
   ```

## Próximos Passos

Depois de resolver o problema:

1. Verificar se o app está funcionando:
   ```bash
   flyctl status -a segurancaaplicadaqa-tnnq1a
   flyctl open -a segurancaaplicadaqa-tnnq1a
   ```

2. Monitorar logs:
   ```bash
   flyctl logs -a segurancaaplicadaqa-tnnq1a
   ```

3. Se tudo estiver OK, o app deve estar acessível e funcionando normalmente.
