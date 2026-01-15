# 🔧 Scripts Utilitários

Esta pasta contém scripts utilitários para desenvolvimento e manutenção do projeto.

## 📁 Scripts Disponíveis

### `fix-all-liquid.py`
Script Python para corrigir sintaxe Liquid em arquivos Markdown.
- **Uso**: `python3 scripts/fix-all-liquid.py`
- **Função**: Protege blocos de código que contêm sintaxe Liquid problemática

### `force-rebuild.sh`
Script para forçar recompilação completa do Jekyll.
- **Uso**: `./scripts/force-rebuild.sh`
- **Função**: Limpa todos os caches e recompila o site do zero

### `rebuild.sh`
Script para limpar cache e recompilar o Jekyll.
- **Uso**: `./scripts/rebuild.sh`
- **Função**: Limpa cache e faz rebuild rápido

### `regenerar-gemfile-lock.sh`
Script para regenerar Gemfile.lock (útil para builds Docker).
- **Uso**: `./scripts/regenerar-gemfile-lock.sh`
- **Função**: Remove Gemfile.lock para regeneração durante build

### `start.sh`
Script para iniciar servidor Jekyll (usado em Docker).
- **Uso**: `./scripts/start.sh`
- **Função**: Inicia servidor Jekyll com configurações adequadas para Docker

## 📝 Notas

- Todos os scripts estão configurados para funcionar a partir da raiz do projeto
- Scripts bash usam `cd "$(dirname "$0")/.."` para garantir execução no diretório correto
- Script Python usa `Path(__file__).parent.parent` para encontrar o diretório raiz

---

**Última atualização**: Janeiro/2026
