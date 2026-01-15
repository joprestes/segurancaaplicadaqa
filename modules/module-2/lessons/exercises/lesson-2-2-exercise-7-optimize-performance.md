---
layout: exercise
title: "Exercício 2.2.7: Otimizar Performance de Scans DAST"
slug: "optimize-performance"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-2-exercise-7-optimize-performance/
lesson_url: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

> **⭐ Exercício Opcional**: Este exercício é focado em otimização de performance de scans DAST. Se seus scans já são rápidos (< 10 minutos) ou você não precisa otimizar performance, pode pular este exercício sem perder conteúdo essencial. Os exercícios 1-5 cobrem os conceitos fundamentais de DAST.

## Objetivo

Este exercício tem como objetivo **otimizar performance de scans DAST**, reduzindo tempo de execução sem comprometer cobertura de segurança.

Ao completar este exercício, você será capaz de:

- Identificar gargalos em scans DAST lentos
- Otimizar configurações para reduzir tempo de execução
- Balancear performance e cobertura de segurança
- Medir e documentar melhorias de performance
- Aplicar otimizações em diferentes contextos

---

## Descrição

Você vai identificar por que um scan DAST está lento, aplicar otimizações, e medir o impacto. O objetivo é reduzir tempo de execução mantendo cobertura de segurança adequada.

### Contexto

Scans DAST podem ser lentos (30+ minutos), especialmente em aplicações grandes. Isso pode bloquear pipelines ou desencorajar uso. Otimizar performance é essencial para adoção de DAST no dia a dia.

### Tarefa Principal

1. Identificar por que scan está lento
2. Aplicar otimizações (escopo, políticas, paralelização)
3. Medir impacto das otimizações
4. Validar que cobertura não foi comprometida
5. Documentar otimizações aplicadas

---

## Requisitos

### Passo 1: Identificar Gargalos

**1.1. Executar Scan e Medir Tempo**

```bash
# Executar scan completo e medir tempo
time docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -J zap-slow-scan.json \
  -r zap-slow-scan.html

# Anotar tempo de execução
# Exemplo: 45 minutos
```

**1.2. Analisar Onde Tempo é Gasto**

Criar arquivo `analysis/performance-analysis.md`:

```markdown
# Análise de Performance - Scan DAST

**Data**: 2026-01-14
**Aplicação**: http://localhost:3000
**Tempo Total**: 45 minutos

## Onde Tempo é Gasto?

### Fase 1: Crawling (Rastreamento)
- **Tempo**: 15 minutos (33%)
- **URLs descobertas**: 1,247
- **Gargalo**: Aplicação tem muitas rotas, crawler explora todas

### Fase 2: Passive Scanning
- **Tempo**: 5 minutos (11%)
- **Gargalo**: Normal, não é problema

### Fase 3: Active Scanning
- **Tempo**: 25 minutos (56%)
- **Requisições enviadas**: 12,543
- **Gargalo**: Muitas URLs × Muitos payloads = Muitas requisições

## Identificação de Gargalos

1. **Crawling muito abrangente**: Descobre rotas não críticas
2. **Active scanning em todas as URLs**: Testa até rotas Low priority
3. **Políticas muito agressivas**: Muitos payloads por URL
4. **Sem paralelização**: Scan sequencial

## Possíveis Otimizações

1. Limitar escopo (apenas URLs críticas)
2. Reduzir profundidade de crawling
3. Usar políticas menos agressivas
4. Paralelizar scans
5. Separar scan passivo (rápido) de ativo (lento)
```

### Passo 2: Aplicar Otimização 1: Limitar Escopo

**2.1. Identificar URLs Críticas**

Criar arquivo `config/critical-urls.txt`:

```
# URLs críticas que DEVEM ser testadas
http://app.com/api/users
http://app.com/api/orders
http://app.com/api/payments
http://app.com/api/auth
http://app.com/admin
http://app.com/checkout
```

**2.2. Executar Scan Apenas em URLs Críticas**

```bash
# Scan apenas em URLs críticas
time docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -I ".*api.*|.*admin.*|.*checkout.*" \
  -J zap-optimized-1.json \
  -r zap-optimized-1.html

# Medir tempo
# Exemplo: 12 minutos (redução de 73%)
```

**2.3. Validar Cobertura**

```bash
# Comparar número de vulnerabilidades encontradas
# Scan completo: 45 min, 28 vulnerabilidades
# Scan otimizado: 12 min, 24 vulnerabilidades (86% de cobertura)
```

### Passo 3: Aplicar Otimização 2: Reduzir Profundidade de Crawling

**3.1. Limitar Profundidade**

```bash
# Limitar profundidade de crawling (máximo 3 níveis)
time docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -I ".*api.*|.*admin.*|.*checkout.*" \
  -m 3 \
  -J zap-optimized-2.json \
  -r zap-optimized-2.html

# Medir tempo
# Exemplo: 8 minutos (redução adicional de 33%)
```

**3.2. Explicação**

- `-m 3`: Máximo 3 níveis de profundidade
- Evita explorar rotas muito profundas (ex: `/api/users/123/orders/456/items/789`)
- Foca em rotas principais

### Passo 4: Aplicar Otimização 3: Políticas Menos Agressivas

**4.1. Usar Scan Passivo para Validação Rápida**

```bash
# Scan passivo (rápido, sem payloads)
time docker exec zap zap-baseline.py \
  -t http://localhost:3000 \
  -I ".*api.*|.*admin.*|.*checkout.*" \
  -J zap-passive.json \
  -r zap-passive.html

# Medir tempo
# Exemplo: 2 minutos (muito rápido!)
```

**4.2. Usar Scan Ativo Apenas em URLs Críticas**

```bash
# Scan ativo apenas em URLs mais críticas
time docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -I ".*api/payments.*|.*api/auth.*|.*checkout.*" \
  -m 2 \
  -J zap-active-critical.json \
  -r zap-active-critical.html

# Medir tempo
# Exemplo: 5 minutos
```

**4.3. Estratégia Combinada**

```bash
# 1. Scan passivo em todas as URLs (rápido)
docker exec zap zap-baseline.py -t http://localhost:3000 -J passive.json

# 2. Scan ativo apenas em URLs críticas (mais lento, mas focado)
docker exec zap zap-full-scan.py -t http://localhost:3000 -I ".*critical.*" -J active.json

# Tempo total: 2 + 5 = 7 minutos (vs 45 minutos original)
```

### Passo 5: Aplicar Otimização 4: Paralelização

**5.1. Paralelizar Scans de Múltiplos Serviços**

Se aplicação tem múltiplos serviços, scan cada um em paralelo:

```bash
# Scan paralelo de múltiplos serviços
docker exec zap zap-full-scan.py -t http://users-service:3001 -J users.json &
docker exec zap zap-full-scan.py -t http://orders-service:3002 -J orders.json &
docker exec zap zap-full-scan.py -t http://payments-service:3003 -J payments.json &

# Aguardar todos completarem
wait

# Tempo: Tempo do scan mais lento (ex: 5 min) vs sequencial (15 min)
```

**5.2. Usar Múltiplas Instâncias do ZAP**

```bash
# Iniciar múltiplas instâncias do ZAP
docker run -d --name zap1 -p 8080:8080 owasp/zap2docker-stable zap-webswing.sh
docker run -d --name zap2 -p 8081:8080 owasp/zap2docker-stable zap-webswing.sh
docker run -d --name zap3 -p 8082:8080 owasp/zap2docker-stable zap-webswing.sh

# Distribuir URLs entre instâncias
# (Requer script customizado ou uso da API do ZAP)
```

### Passo 6: Medir e Documentar Melhorias

**6.1. Criar Tabela Comparativa**

Criar arquivo `results/performance-comparison.md`:

```markdown
# Comparação de Performance - Otimizações Aplicadas

## Configurações Testadas

| Configuração | Tempo | Vulnerabilidades | Cobertura | Observações |
|--------------|-------|------------------|-----------|-------------|
| **Original (completo)** | 45 min | 28 | 100% | Muito lento |
| **Otimização 1: Escopo limitado** | 12 min | 24 | 86% | Boa redução |
| **Otimização 2: + Profundidade limitada** | 8 min | 22 | 79% | Aceitável |
| **Otimização 3: Passivo + Ativo crítico** | 7 min | 20 | 71% | Balance bom |
| **Otimização 4: Paralelização** | 5 min | 20 | 71% | Melhor performance |

## Análise

### Tempo vs Cobertura

```
Tempo (minutos)
50 |                                    *
    |                                *
40 |                            *
    |                        *
30 |                    *
    |                *
20 |            *
    |        *
10 |    *
    |*
 0 +----+----+----+----+----+----+----+----+
   50%  60%  70%  80%  90%  100%
              Cobertura (%)
```

### Recomendação

**Configuração Recomendada**: Otimização 3 (Passivo + Ativo crítico)
- **Tempo**: 7 minutos (redução de 84%)
- **Cobertura**: 71% (aceitável para CI/CD)
- **Balance**: Bom balance entre performance e cobertura

**Para Scans Completos**: Usar configuração original semanalmente
- **Tempo**: 45 minutos (aceitável para scan semanal)
- **Cobertura**: 100%
```

**6.2. Documentar Otimizações Aplicadas**

Criar arquivo `docs/optimizations-applied.md`:

```markdown
# Otimizações de Performance Aplicadas

## 1. Limitação de Escopo

**O que foi feito**: Scan apenas em URLs críticas
**Impacto**: Redução de 73% no tempo (45 min → 12 min)
**Cobertura**: 86% das vulnerabilidades encontradas
**Risco**: Pode perder vulnerabilidades em URLs não críticas
**Mitigação**: Scan completo semanalmente

## 2. Limitação de Profundidade

**O que foi feito**: Máximo 3 níveis de profundidade
**Impacto**: Redução adicional de 33% (12 min → 8 min)
**Cobertura**: 79% das vulnerabilidades encontradas
**Risco**: Pode perder vulnerabilidades em rotas profundas
**Mitigação**: Scan completo mensalmente

## 3. Estratégia Passivo + Ativo

**O que foi feito**: Scan passivo em todas URLs, ativo apenas em críticas
**Impacto**: Redução de 84% (45 min → 7 min)
**Cobertura**: 71% das vulnerabilidades encontradas
**Risco**: Scan ativo não cobre todas as URLs
**Mitigação**: Scan ativo completo semanalmente

## 4. Paralelização

**O que foi feito**: Scans paralelos de múltiplos serviços
**Impacto**: Redução de 89% (45 min → 5 min) para múltiplos serviços
**Cobertura**: 71% das vulnerabilidades encontradas
**Risco**: Requer múltiplas instâncias do ZAP
**Mitigação**: Usar em CI/CD com recursos adequados
```

### Passo 7: Validar que Cobertura Não Foi Comprometida

**7.1. Comparar Vulnerabilidades Encontradas**

```bash
# Comparar vulnerabilidades críticas encontradas
# Scan completo: 28 vulnerabilidades (8 Critical, 12 High)
# Scan otimizado: 20 vulnerabilidades (7 Critical, 10 High)

# Análise:
# - Critical: 7/8 encontradas (87.5%) ✅
# - High: 10/12 encontradas (83.3%) ✅
# - Medium: 3/8 encontradas (37.5%) ⚠️
```

**7.2. Decisão sobre Cobertura**

```markdown
## Decisão sobre Cobertura

### Vulnerabilidades Críticas e High
- **Cobertura**: 85%+ ✅
- **Decisão**: Aceitável para CI/CD
- **Justificativa**: Prioridade é encontrar vulnerabilidades críticas

### Vulnerabilidades Medium e Low
- **Cobertura**: 40-60% ⚠️
- **Decisão**: Aceitável, mas scan completo semanalmente
- **Justificativa**: Medium/Low podem ser encontradas em scans completos

### Estratégia Final
- **CI/CD (cada PR)**: Scan otimizado (7 min, 71% cobertura)
- **Semanal**: Scan completo (45 min, 100% cobertura)
- **Mensal**: Scan completo profundo (60 min, 100% cobertura + fuzzing)
```

---

## Dicas

1. **Meça antes de otimizar**: Sempre meça tempo atual antes de aplicar otimizações
2. **Valide cobertura**: Certifique-se que otimizações não comprometem cobertura crítica
3. **Balance performance e segurança**: Não sacrifique segurança por performance
4. **Documente decisões**: Documente por que otimizações foram aplicadas
5. **Reavalie periodicamente**: Otimizações podem precisar ajuste conforme aplicação cresce

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] Gargalos identificados e documentados
- [ ] Pelo menos 3 otimizações aplicadas
- [ ] Tempo de execução reduzido em pelo menos 50%
- [ ] Cobertura de vulnerabilidades críticas mantida (>80%)
- [ ] Melhorias medidas e documentadas
- [ ] Estratégia de balance performance/cobertura definida

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Otimizar scans em projetos reais
- Aplicar otimizações em diferentes contextos
- Balancear performance e cobertura conforme necessário

---

## 💼 Contexto CWI (Exemplo Hipotético)

**Cenário**: Pipeline de CI/CD que precisa completar em < 10 minutos

- **Requisito**: Scan deve completar em < 10 minutos
- **Cobertura mínima**: 80% das vulnerabilidades críticas
- **Estratégia**: Scan otimizado em cada PR, scan completo semanalmente

Aplique otimizações para atender esses requisitos.

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Análise de gargalos identificados
2. Otimizações aplicadas e impacto medido
3. Comparação de performance (antes/depois)
4. Validação de cobertura mantida
5. Estratégia final de balance performance/cobertura

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 60-90 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Aula 2.2 (DAST), Exercício 2.2.1 (OWASP ZAP)
