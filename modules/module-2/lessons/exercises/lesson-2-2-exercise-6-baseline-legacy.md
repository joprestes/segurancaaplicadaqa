---
layout: exercise
title: "Exercício 2.2.6: Gerenciar Baseline em Projeto Legado"
slug: "baseline-legacy"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Intermediário"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-2-exercise-6-baseline-legacy/
lesson_url: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

> **⭐ Exercício Opcional**: Este exercício é focado em cenários específicos de projetos legados com muitas vulnerabilidades acumuladas. Se você não trabalha com projetos legados ou não precisa gerenciar baseline de vulnerabilidades, pode pular este exercício sem perder conteúdo essencial. Os exercícios 1-5 cobrem os conceitos fundamentais de DAST.

## Objetivo

Este exercício tem como objetivo **criar e gerenciar baseline de vulnerabilidades em projeto legado**, permitindo que o time continue desenvolvendo enquanto trabalha na redução gradual de vulnerabilidades existentes.

Ao completar este exercício, você será capaz de:

- Criar baseline de vulnerabilidades aceitas
- Configurar Quality Gate que permite baseline mas bloqueia novas vulnerabilidades
- Criar estratégia de redução gradual
- Documentar processo de triagem para novas vulnerabilidades
- Comunicar baseline para stakeholders

---

## Descrição

Você vai simular um cenário real: projeto legado com muitas vulnerabilidades existentes. Em vez de tentar corrigir tudo de uma vez (impossível), você vai criar um baseline aceito e focar em prevenir novas vulnerabilidades enquanto trabalha na redução gradual das existentes.

### Contexto

Projetos legados frequentemente têm muitas vulnerabilidades acumuladas. Tentar corrigir tudo de uma vez bloqueia desenvolvimento. A solução é criar um baseline (aceitar o que existe hoje) e focar em não adicionar novas vulnerabilidades.

### Tarefa Principal

1. Executar DAST em aplicação legada (ou simular com aplicação vulnerável)
2. Criar baseline de vulnerabilidades existentes
3. Configurar Quality Gate que permite baseline mas bloqueia novas
4. Criar estratégia de redução gradual
5. Documentar processo de triagem
6. Comunicar baseline para stakeholders

---

## Requisitos

### Passo 1: Preparar Cenário de Projeto Legado

**1.1. Escolher Aplicação**

- **Opção A**: Usar aplicação vulnerável de exemplo (OWASP Juice Shop)
  ```bash
  docker run -d -p 3000:3000 bkimminich/juice-shop
  ```

- **Opção B**: Usar aplicação própria que já tem vulnerabilidades conhecidas

**1.2. Executar DAST Inicial**

```bash
# Executar scan completo
docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -J zap-initial-scan.json \
  -r zap-initial-scan.html
```

**1.3. Documentar Estado Inicial**

Criar arquivo `baseline/initial-state.md`:

```markdown
# Estado Inicial - Baseline de Vulnerabilidades

**Data**: 2026-01-14
**Aplicação**: [Nome da aplicação]
**Ferramenta**: OWASP ZAP

## Resumo
- **Total de Vulnerabilidades**: 347
- **Critical**: 28
- **High**: 89
- **Medium**: 156
- **Low**: 74

## Observações
- Projeto legado, vulnerabilidades acumuladas ao longo dos anos
- Time pequeno, não é viável corrigir tudo de uma vez
- Estratégia: Baseline + Redução gradual
```

### Passo 2: Criar Baseline Aceito

**2.1. Decidir Critérios de Baseline**

Baseline = "Aceitar todas as vulnerabilidades que existem hoje, focar em não adicionar novas"

**Critérios para Baseline**:
- Todas as vulnerabilidades encontradas na data X são aceitas
- Novas vulnerabilidades (após data X) devem ser corrigidas
- Critical novas: Bloquear deploy
- High novas: Corrigir neste sprint
- Medium/Low novas: Corrigir quando possível

**2.2. Documentar Baseline**

Criar arquivo `baseline/baseline-accepted.md`:

```markdown
# Baseline de Vulnerabilidades Aceitas

**Data de Baseline**: 2026-01-14
**Aprovado por**: [Tech Lead / Security Team]

## Vulnerabilidades Aceitas no Baseline

### Critical (28 vulnerabilidades)
- Todas as 28 vulnerabilidades críticas encontradas em 2026-01-14 são aceitas no baseline
- **Justificativa**: Projeto legado, correção requer refatoração significativa
- **Estratégia**: Redução gradual (meta: 0 Critical em 6 meses)

### High (89 vulnerabilidades)
- Todas as 89 vulnerabilidades High encontradas em 2026-01-14 são aceitas no baseline
- **Justificativa**: Volume alto, não é viável corrigir tudo de uma vez
- **Estratégia**: Redução gradual (meta: < 20 High em 6 meses)

### Medium (156 vulnerabilidades)
- Todas as 156 vulnerabilidades Medium encontradas em 2026-01-14 são aceitas no baseline
- **Estratégia**: Redução gradual (meta: < 50 Medium em 6 meses)

### Low (74 vulnerabilidades)
- Todas as 74 vulnerabilidades Low encontradas em 2026-01-14 são aceitas no baseline
- **Estratégia**: Endereçar quando possível

## Regras para Novas Vulnerabilidades

### Após 2026-01-14, novas vulnerabilidades devem ser tratadas:

**Critical novas**:
- ❌ Bloquear deploy
- ✅ Corrigir antes de merge
- ✅ Validação obrigatória

**High novas**:
- ⚠️ Corrigir neste sprint
- ✅ Não bloquear deploy inicialmente (período de transição)
- ✅ Após 1 mês: Bloquear deploy se > 5 High novas

**Medium novas**:
- ✅ Corrigir no próximo sprint
- ✅ Não bloquear deploy

**Low novas**:
- ✅ Endereçar quando possível
- ✅ Não bloquear deploy
```

### Passo 3: Configurar Quality Gate com Baseline

**3.1. Criar Script de Validação com Baseline**

Criar arquivo `scripts/check_baseline.py`:

```python
#!/usr/bin/env python3
"""
Script para validar findings DAST considerando baseline.
Bloqueia apenas novas vulnerabilidades, permite baseline.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Baseline: vulnerabilidades aceitas
BASELINE_DATE = "2026-01-14"
BASELINE_FILE = "baseline/baseline-vulnerabilities.json"

def load_baseline():
    """Carrega baseline de vulnerabilidades aceitas."""
    if not Path(BASELINE_FILE).exists():
        print(f"⚠️ Baseline file not found: {BASELINE_FILE}")
        print("💡 Criando baseline vazio. Execute scan inicial primeiro.")
        return {
            "baseline_date": BASELINE_DATE,
            "vulnerabilities": []
        }
    
    with open(BASELINE_FILE) as f:
        return json.load(f)

def extract_vulnerability_id(alert):
    """Extrai ID único da vulnerabilidade."""
    # Usar combinação de URL + parâmetro + tipo de alerta
    url = alert.get('url', '')
    param = alert.get('param', '')
    alert_name = alert.get('alert', '')
    return f"{url}|{param}|{alert_name}"

def check_zap_results(zap_file='zap-full.json'):
    """Verifica resultados do OWASP ZAP."""
    if not Path(zap_file).exists():
        print(f"⚠️ {zap_file} not found.")
        return 0, 0
    
    with open(zap_file) as f:
        data = json.load(f)
    
    baseline = load_baseline()
    baseline_ids = {extract_vulnerability_id(v) for v in baseline.get('vulnerabilities', [])}
    
    new_critical = 0
    new_high = 0
    
    # OWASP ZAP estrutura
    alerts = data.get('site', [{}])[0].get('alerts', [])
    
    for alert in alerts:
        risk = alert.get('risk', '').upper()
        vuln_id = extract_vulnerability_id(alert)
        
        # Verificar se é nova (não está no baseline)
        is_new = vuln_id not in baseline_ids
        
        if is_new:
            if risk == 'HIGH':
                new_critical += 1
            elif risk == 'MEDIUM':
                new_high += 1
    
    print(f"📊 OWASP ZAP Results:")
    print(f"   New Critical/High: {new_critical}")
    print(f"   New Medium: {new_high}")
    print(f"   Baseline vulnerabilities: {len(baseline_ids)} (aceitas)")
    
    return new_critical, new_high

def main():
    """Valida findings e falha pipeline se novas Critical encontradas."""
    print("🔍 Checking DAST results against baseline...")
    print(f"📅 Baseline date: {BASELINE_DATE}")
    
    new_critical, new_high = check_zap_results('zap-full.json')
    
    # Quality Gate: Bloquear apenas novas Critical
    if new_critical > 0:
        print(f"\n❌ FAILED: Found {new_critical} NEW Critical vulnerabilities!")
        print("Pipeline blocked. Please fix NEW Critical vulnerabilities before merging.")
        print("💡 Baseline vulnerabilities are accepted, but NEW ones must be fixed.")
        sys.exit(1)
    else:
        print("\n✅ SUCCESS: No NEW Critical vulnerabilities found.")
        print("💡 Baseline vulnerabilities are accepted (reduction in progress).")
        sys.exit(0)

if __name__ == '__main__':
    main()
```

**3.2. Atualizar Pipeline CI/CD**

Atualizar `.github/workflows/dast.yml`:

```yaml
      - name: Check against baseline
        run: |
          python3 scripts/check_baseline.py zap-full.json || exit 1
```

### Passo 4: Criar Estratégia de Redução Gradual

**4.1. Definir Metas por Trimestre**

Criar arquivo `baseline/reduction-strategy.md`:

```markdown
# Estratégia de Redução Gradual de Vulnerabilidades

## Metas por Trimestre

### Q1 2026 (Jan-Mar)
**Objetivo**: Estabilizar baseline, focar em não adicionar novas

- ✅ Baseline criado e documentado
- ✅ Quality Gate configurado (bloqueia novas Critical)
- ✅ Processo de triagem documentado
- **Meta**: 0 novas Critical, reduzir 10% das High existentes

### Q2 2026 (Abr-Jun)
**Objetivo**: Reduzir vulnerabilidades críticas

- **Meta Critical**: 28 → 15 (-46%)
- **Meta High**: 89 → 70 (-21%)
- **Meta Medium**: 156 → 140 (-10%)

### Q3 2026 (Jul-Set)
**Objetivo**: Reduzir vulnerabilidades High

- **Meta Critical**: 15 → 5 (-67%)
- **Meta High**: 70 → 40 (-43%)
- **Meta Medium**: 140 → 100 (-29%)

### Q4 2026 (Out-Dez)
**Objetivo**: Reduzir vulnerabilidades Medium

- **Meta Critical**: 5 → 0 (-100%)
- **Meta High**: 40 → 20 (-50%)
- **Meta Medium**: 100 → 50 (-50%)

## Como Reduzir

### Priorização
1. **Critical em áreas críticas** (pagamentos, autenticação, dados sensíveis)
2. **High em produção** (acessíveis por usuários)
3. **Medium com alta exploitability**
4. **Low gradualmente**

### Alocação de Recursos
- **1 desenvolvedor dedicado**: 20% do tempo para correções de segurança
- **Sprint dedicado**: 1 sprint por trimestre focado em segurança
- **Code review**: Incluir verificação de segurança em cada PR
```

**4.2. Criar Dashboard de Progresso**

Criar arquivo `baseline/dashboard.md`:

```markdown
# Dashboard de Redução de Vulnerabilidades

**Última atualização**: 2026-01-14

## Progresso Geral

| Trimestre | Critical | High | Medium | Low | Status |
|-----------|----------|------|--------|-----|--------|
| **Baseline (Q1)** | 28 | 89 | 156 | 74 | ✅ Estabelecido |
| **Q2 (Meta)** | 15 | 70 | 140 | 70 | 🔄 Em andamento |
| **Q3 (Meta)** | 5 | 40 | 100 | 50 | ⏳ Planejado |
| **Q4 (Meta)** | 0 | 20 | 50 | 30 | ⏳ Planejado |

## Vulnerabilidades por Categoria

### Critical (28)
- SQL Injection: 8
- Broken Access Control: 12
- Remote Code Execution: 3
- Autenticação Bypass: 5

### High (89)
- XSS: 25
- Path Traversal: 15
- Information Disclosure: 20
- Insecure Deserialization: 10
- Outras: 19
```

### Passo 5: Documentar Processo de Triagem

**5.1. Criar Processo de Triagem**

Criar arquivo `docs/triagem-processo-baseline.md`:

```markdown
# Processo de Triagem com Baseline

## Quando uma Nova Vulnerabilidade é Encontrada

### 1. Verificar se é Nova ou Baseline

**É Baseline?** (existe desde antes de 2026-01-14)
- ✅ Aceitar (já documentada no baseline)
- ✅ Não bloquear deploy
- ✅ Adicionar à estratégia de redução gradual

**É Nova?** (encontrada após 2026-01-14)
- ⚠️ Continuar para validação

### 2. Validar Vulnerabilidade Nova

Seguir processo normal de validação:
- Reproduzir manualmente
- Verificar se é True Positive
- Analisar contexto e impacto

### 3. Priorizar Vulnerabilidade Nova

**Critical nova**:
- ❌ Bloquear deploy
- ✅ Corrigir antes de merge
- ✅ Validação obrigatória

**High nova**:
- ⚠️ Corrigir neste sprint
- ⚠️ Não bloquear deploy inicialmente (período de transição de 1 mês)
- ✅ Após 1 mês: Bloquear deploy se > 5 High novas

**Medium/Low nova**:
- ✅ Corrigir quando possível
- ✅ Não bloquear deploy

### 4. Documentar Decisão

- Adicionar à lista de vulnerabilidades novas
- Criar issue de tracking
- Atualizar dashboard
```

### Passo 6: Comunicar Baseline para Stakeholders

**6.1. Criar Relatório Executivo**

Criar arquivo `reports/baseline-communication.md`:

```markdown
# Comunicação: Baseline de Vulnerabilidades

**Para**: Tech Lead, Product Owner, Management
**Data**: 2026-01-14

## Situação Atual

Projeto legado tem 347 vulnerabilidades acumuladas ao longo dos anos:
- 28 Critical
- 89 High
- 156 Medium
- 74 Low

## Problema

Tentar corrigir tudo de uma vez:
- ❌ Bloquearia desenvolvimento por meses
- ❌ Não é viável com time atual
- ❌ Novas features não podem ser desenvolvidas

## Solução: Baseline + Redução Gradual

### O que é Baseline?
- Aceitar vulnerabilidades que existem hoje
- Focar em não adicionar novas vulnerabilidades
- Reduzir vulnerabilidades existentes gradualmente

### Benefícios
- ✅ Desenvolvimento continua normalmente
- ✅ Novas vulnerabilidades são bloqueadas
- ✅ Redução gradual e sustentável
- ✅ Metas claras e mensuráveis

### Metas
- **Q2**: Reduzir 46% das Critical
- **Q3**: Reduzir 67% das Critical restantes
- **Q4**: Eliminar todas as Critical

### Investimento Necessário
- 1 desenvolvedor: 20% do tempo
- 1 sprint por trimestre: focado em segurança
- Total: ~15% da capacidade do time

## Recomendação

Aprovar baseline e estratégia de redução gradual para permitir desenvolvimento contínuo enquanto melhoramos segurança.
```

---

## Dicas

1. **Comunique baseline claramente**: Stakeholders precisam entender por que vulnerabilidades são aceitas
2. **Documente tudo**: Baseline deve ser rastreável e auditável
3. **Seja realista com metas**: Metas muito agressivas podem falhar e desmotivar
4. **Celebre progresso**: Redução gradual é melhor que nenhuma redução
5. **Reavalie periodicamente**: Ajuste metas se necessário

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] DAST executado em aplicação legada
- [ ] Baseline de vulnerabilidades criado e documentado
- [ ] Quality Gate configurado (permite baseline, bloqueia novas)
- [ ] Estratégia de redução gradual criada
- [ ] Processo de triagem documentado
- [ ] Relatório de comunicação para stakeholders criado
- [ ] Script de validação com baseline funcionando

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Implementar baseline em projeto real
- Gerenciar redução gradual de vulnerabilidades
- Comunicar estratégia de segurança para stakeholders

---

## 💼 Contexto CWI (Exemplo Hipotético)

**Cenário**: Projeto financeiro legado com 500+ vulnerabilidades

- **Baseline rigoroso**: Apenas vulnerabilidades não relacionadas a dados de cartão podem ser aceitas
- **Critical relacionadas a pagamentos**: Devem ser corrigidas imediatamente, mesmo no baseline
- **Compliance**: Baseline deve ser aprovado por equipe de compliance

Aplique os mesmos passos com esses critérios mais rigorosos.

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Baseline de vulnerabilidades documentado
2. Estratégia de redução gradual
3. Script de validação com baseline
4. Relatório de comunicação para stakeholders
5. Dúvidas ou desafios encontrados

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Intermediário  
**Pré-requisitos**: Aula 2.2 (DAST), Exercício 2.2.1 (OWASP ZAP), Conhecimento básico de Python
