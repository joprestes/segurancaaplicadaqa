---
layout: exercise
title: "Exercício 2.1.5: Comparar Ferramentas SAST"
slug: "compare-sast-tools"
lesson_id: "lesson-2-1"
module: "module-2"
difficulty: "Avançado"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-1-exercise-5-compare-sast-tools/
lesson_url: /modules/testes-seguranca-pratica/lessons/sast-testes-estaticos/
---

## Objetivo

Este exercício tem como objetivo **comparar diferentes ferramentas SAST** no mesmo projeto, analisar resultados, e criar relatório comparativo com recomendação.

Ao completar este exercício, você será capaz de:

- Executar múltiplas ferramentas SAST no mesmo projeto
- Comparar resultados (findings, false positives, tempo de execução)
- Avaliar precisão de cada ferramenta
- Analisar custo-benefício
- Criar relatório comparativo com recomendação

---

## Descrição

Você vai executar 2-3 ferramentas SAST diferentes no mesmo projeto, comparar resultados detalhadamente, validar findings manualmente, e criar relatório comparativo com recomendação de qual ferramenta usar.

### Contexto

Cada ferramenta SAST tem pontos fortes diferentes. Comparar ferramentas ajuda a escolher a melhor opção para seu contexto, orçamento e necessidades.

### Tarefa Principal

1. Escolher projeto para análise
2. Executar 2-3 ferramentas SAST diferentes no mesmo projeto
3. Comparar resultados (número de findings, false positives, tempo)
4. Validar manualmente amostra de findings
5. Analisar custo, facilidade de uso, integração
6. Criar relatório comparativo com recomendação

---

## Requisitos

### Passo 1: Preparar Ambiente

**1.1. Escolher Projeto**

- Projeto próprio (preferido)
- Ou projeto de exemplo (OWASP Juice Shop, WebGoat)

**1.2. Instalar Ferramentas SAST**

Instalar 2-3 ferramentas SAST:

**Opção A: Open Source (Gratuito)**
- Semgrep
- Bandit (Python) ou ESLint Security (JavaScript)
- SonarQube Community Edition

**Opção B: Open Source + Trial Comercial**
- Semgrep (gratuito)
- SonarQube (gratuito Community)
- Checkmarx Trial (se disponível)

**1.3. Verificar Instalação**

```bash
# Verificar Semgrep
semgrep --version

# Verificar Bandit (Python)
bandit --version

# Verificar SonarQube
docker ps | grep sonarqube
```

### Passo 2: Executar Ferramentas SAST

**2.1. Executar Semgrep**

```bash
# Executar Semgrep com múltiplas configurações
semgrep --config=auto \
        --config=p/security-audit \
        --config=p/owasp-top-ten \
        --json \
        --output=semgrep-results.json \
        .

# Tempo de execução
time semgrep --config=auto . > semgrep-time.txt 2>&1
```

**2.2. Executar Bandit (se Python)**

```bash
# Executar Bandit
bandit -r . \
       -f json \
       -o bandit-results.json

bandit -r . \
       -f txt \
       -o bandit-results.txt

# Tempo de execução
time bandit -r . > bandit-time.txt 2>&1
```

**2.3. Executar ESLint Security (se JavaScript)**

```bash
# Instalar ESLint Security
npm install --save-dev eslint-plugin-security

# Executar
npm run lint:security > eslint-security-results.json 2>&1

# Tempo de execução
time npm run lint:security > eslint-security-time.txt 2>&1
```

**2.4. Executar SonarQube**

```bash
# Configurar e executar SonarQube
sonar-scanner \
  -Dsonar.projectKey=projeto-comparacao \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=$SONAR_TOKEN

# Tempo de execução
time sonar-scanner ... > sonarqube-time.txt 2>&1
```

**2.5. Registrar Métricas**

Criar arquivo `metrics/comparison-metrics.json`:

```json
{
  "project": "meu-projeto",
  "scan_date": "2026-01-14",
  "tools": {
    "semgrep": {
      "version": "1.45.0",
      "execution_time_seconds": 45,
      "total_findings": 32,
      "by_severity": {
        "error": 2,
        "warning": 8,
        "info": 22
      }
    },
    "bandit": {
      "version": "1.7.5",
      "execution_time_seconds": 120,
      "total_findings": 28,
      "by_severity": {
        "high": 1,
        "medium": 7,
        "low": 20
      }
    },
    "sonarqube": {
      "version": "10.2",
      "execution_time_seconds": 480,
      "total_findings": 45,
      "by_severity": {
        "critical": 2,
        "high": 8,
        "medium": 15,
        "low": 20
      }
    }
  }
}
```

### Passo 3: Comparar Número de Findings

**3.1. Criar Tabela Comparativa**

Criar arquivo `comparison/findings-comparison.md`:

```markdown
# Comparação de Findings por Ferramenta

## Total de Findings por Ferramenta

| Ferramenta | Total | Critical | High | Medium | Low |
|------------|-------|----------|------|--------|-----|
| Semgrep | 32 | 0 | 2 | 8 | 22 |
| Bandit | 28 | 0 | 1 | 7 | 20 |
| SonarQube | 45 | 2 | 8 | 15 | 20 |

## Overlap de Findings

| Finding | Semgrep | Bandit | SonarQube |
|---------|---------|--------|-----------|
| SQL Injection (auth.py:45) | ✅ | ✅ | ✅ |
| Hardcoded Secret (config.py:12) | ✅ | ❌ | ✅ |
| XSS (public.js:78) | ✅ | N/A | ✅ |

## Findings Únicos por Ferramenta

### Semgrep
- 3 findings únicos (não encontrados por outras ferramentas)

### Bandit
- 1 finding único (Python-specific)

### SonarQube
- 8 findings únicos (análise mais profunda)
```

**3.2. Analisar Overlap**

- Findings encontrados por todas as ferramentas = Vulnerabilidades mais evidentes
- Findings únicos de uma ferramenta = Ponto forte específico dessa ferramenta

### Passo 4: Validar Findings Manualmente

**4.1. Amostragem de Validação**

Selecionar amostra representativa de findings:
- 5 findings Critical/High de cada ferramenta
- 3 findings Medium de cada ferramenta
- Total: ~20-25 findings para validar

**4.2. Processo de Validação**

Para cada finding na amostra:

1. Ler código ao redor
2. Analisar contexto
3. Classificar como:
   - ✅ True Positive (vulnerabilidade real)
   - ❌ False Positive (não é vulnerabilidade)
   - ⚠️ Inconclusivo (precisa mais análise)

**4.3. Calcular Taxa de False Positives**

Criar arquivo `comparison/false-positive-analysis.md`:

```markdown
# Análise de False Positives

## Amostra Validada

| Ferramenta | Total Amostra | True Positives | False Positives | Taxa FP |
|------------|---------------|----------------|-----------------|---------|
| Semgrep | 8 | 6 | 2 | 25% |
| Bandit | 8 | 7 | 1 | 12.5% |
| SonarQube | 10 | 7 | 3 | 30% |

## Conclusões

- **Bandit**: Menor taxa de false positives (mais preciso)
- **Semgrep**: Taxa média de false positives (rápido e razoavelmente preciso)
- **SonarQube**: Maior taxa de false positives, mas encontra mais vulnerabilidades
```

### Passo 5: Comparar Outros Aspectos

**5.1. Tempo de Execução**

```markdown
## Tempo de Execução

| Ferramenta | Tempo (segundos) | Proporcional |
|------------|------------------|--------------|
| Semgrep | 45 | 1x (mais rápido) |
| Bandit | 120 | 2.7x |
| SonarQube | 480 | 10.7x (mais lento) |

**Conclusão**: Semgrep é muito mais rápido que SonarQube.
```

**5.2. Facilidade de Configuração**

```markdown
## Facilidade de Configuração

| Ferramenta | Configuração | Complexidade |
|------------|--------------|--------------|
| Semgrep | Muito fácil (apenas instalar) | ⭐ Simples |
| Bandit | Fácil (pip install) | ⭐ Simples |
| SonarQube | Média (requer Docker/servidor) | ⭐⭐ Média |

**Conclusão**: Semgrep e Bandit são mais fáceis de configurar.
```

**5.3. Custo**

```markdown
## Custo

| Ferramenta | Versão Testada | Custo |
|------------|----------------|-------|
| Semgrep | Community (gratuito) | $0 |
| Bandit | Open source (gratuito) | $0 |
| SonarQube | Community Edition (gratuito) | $0 |

**Nota**: Versões comerciais disponíveis para todas com custos variados.
```

**5.4. Integração CI/CD**

```markdown
## Integração CI/CD

| Ferramenta | GitHub Actions | GitLab CI | Jenkins |
|------------|----------------|-----------|---------|
| Semgrep | ✅ Nativo | ✅ Nativo | ✅ Nativo |
| Bandit | ✅ Script | ✅ Script | ✅ Script |
| SonarQube | ✅ Nativo | ✅ Nativo | ✅ Nativo |

**Conclusão**: Todas têm boa integração CI/CD.
```

**5.5. Cobertura de Linguagens**

```markdown
## Suporte de Linguagens

| Ferramenta | Python | JavaScript | Java | C# |
|------------|--------|------------|------|-----|
| Semgrep | ✅ | ✅ | ✅ | ✅ |
| Bandit | ✅ | ❌ | ❌ | ❌ |
| SonarQube | ✅ | ✅ | ✅ | ✅ |

**Conclusão**: Semgrep e SonarQube têm melhor cobertura multi-linguagem.
```

**5.6. Customização de Regras**

```markdown
## Customização de Regras

| Ferramenta | Facilidade | Formato |
|------------|------------|---------|
| Semgrep | ⭐⭐⭐ Muito fácil | YAML simples |
| Bandit | ⭐⭐ Média | Python/YAML |
| SonarQube | ⭐⭐ Média | XML/Web UI |

**Conclusão**: Semgrep é mais fácil para criar regras customizadas.
```

### Passo 6: Criar Relatório Comparativo

**6.1. Template de Relatório**

Criar arquivo `reports/sast-tools-comparison-report.md`:

```markdown
# Relatório Comparativo: Ferramentas SAST

**Data**: 2026-01-14  
**Projeto Analisado**: [Nome do Projeto]  
**Ferramentas Comparadas**: Semgrep, Bandit, SonarQube

## 1. Resumo Executivo

Este relatório compara 3 ferramentas SAST executadas no mesmo projeto:
- Semgrep (versão 1.45.0)
- Bandit (versão 1.7.5)
- SonarQube Community (versão 10.2)

**Recomendação**: [Ferramenta recomendada]

## 2. Métricas de Comparação

### 2.1. Número de Findings

[Gráfico/Tabela de findings por severidade]

### 2.2. Precisão (False Positive Rate)

[Taxa de false positives]

### 2.3. Tempo de Execução

[Tempo de cada ferramenta]

### 2.4. Custo

[Custo de cada ferramenta]

## 3. Análise Detalhada

### 3.1. Semgrep

**Pontos Fortes**:
- Muito rápido (45 segundos)
- Fácil de configurar
- Boa cobertura multi-linguagem
- Regras customizadas fáceis (YAML)

**Pontos Fracos**:
- Taxa de false positives média (25%)
- Alguns findings únicos não encontrados

**Melhor Para**:
- Scan rápido em CI/CD
- Projetos multi-linguagem
- Equipes que precisam de regras customizadas

### 3.2. Bandit

**Pontos Fortes**:
- Menor taxa de false positives (12.5%)
- Foco específico em Python
- Rápido para projetos Python
- Detecção precisa

**Pontos Fracos**:
- Apenas Python (não multi-linguagem)
- Menos findings encontrados (28 vs 45 do SonarQube)

**Melhor Para**:
- Projetos Python exclusivamente
- Quando precisão é prioridade

### 3.3. SonarQube

**Pontos Fortes**:
- Encontra mais findings (45 total)
- Análise mais profunda (data flow)
- Dashboard visual completo
- Boa integração com IDEs

**Pontos Fracos**:
- Mais lento (480 segundos)
- Taxa de false positives maior (30%)
- Configuração mais complexa
- Requer servidor/Docker

**Melhor Para**:
- Análise profunda de segurança
- Equipes grandes
- Projetos que precisam de dashboard centralizado

## 4. Recomendação

**Recomendação**: Usar **combinação de Semgrep + Bandit** (se projeto Python) ou **Semgrep + SonarQube** (se multi-linguagem)

**Justificativa**:
- Semgrep para scan rápido em CI/CD (velocidade)
- Bandit/SonarQube para análise profunda (cobertura)
- Combinar pontos fortes de cada ferramenta

**Implementação**:
1. Semgrep em pre-commit hooks (scan rápido)
2. Semgrep em CI/CD (scan em cada PR)
3. SonarQube em nightly scans (análise profunda)

## 5. Próximos Passos

1. Implementar Semgrep em pre-commit hooks
2. Configurar Semgrep no CI/CD
3. Configurar SonarQube para scans noturnos
4. Criar processo de triagem de findings
5. Reavaliar em 3 meses
```

**6.2. Criar Gráficos Comparativos**

Criar visualizações (usando ferramentas ou manualmente):

```markdown
## Gráficos Comparativos

### Findings por Severidade
```
Critical:  [Semgrep: 0] [Bandit: 0] [SonarQube: 2]
High:      [Semgrep: 2] [Bandit: 1] [SonarQube: 8]
Medium:    [Semgrep: 8] [Bandit: 7] [SonarQube: 15]
Low:       [Semgrep: 22] [Bandit: 20] [SonarQube: 20]
```

### Tempo de Execução
```
Semgrep:    ████░░░░░░░░░░░░░░░░ 45s (1x)
Bandit:     ████████░░░░░░░░░░░░ 120s (2.7x)
SonarQube:  ████████████████████ 480s (10.7x)
```

### Taxa de False Positives
```
Semgrep:    ████████░░░░░░░░░░░░ 25%
Bandit:     ████░░░░░░░░░░░░░░░░ 12.5% (melhor)
SonarQube:  ████████████░░░░░░░░ 30%
```
```

### Passo 7: Documentar Decisão Final

**7.1. Decisão de Ferramentas**

Documentar qual ferramenta será usada e por quê:

```markdown
## Decisão Final

**Ferramentas Escolhidas**:
1. **Semgrep**: Scan rápido em CI/CD e pre-commit
2. **SonarQube**: Análise profunda (nightly scans)

**Justificativa**:
- Semgrep: Velocidade e facilidade para feedback rápido
- SonarQube: Cobertura completa e análise profunda

**Implementação**:
- Semgrep: Pre-commit hook + CI/CD pipeline
- SonarQube: Scheduled scan diário às 2h da manhã

**Custo**:
- $0 (ambas ferramentas Community Edition)
```

**7.2. Plano de Implementação**

```markdown
## Plano de Implementação

### Semana 1
- [ ] Configurar Semgrep em pre-commit hooks
- [ ] Configurar Semgrep no CI/CD
- [ ] Testar pipeline com código vulnerável

### Semana 2
- [ ] Configurar SonarQube para scans noturnos
- [ ] Configurar notificações de findings
- [ ] Criar processo de triagem

### Semana 3
- [ ] Treinar equipe no uso das ferramentas
- [ ] Documentar processo
- [ ] Revisar e ajustar
```

---

## Dicas

1. **Use projeto real**: Comparação em projeto real é mais útil que projeto de exemplo
2. **Valide manualmente**: Validação manual de amostra é crucial para precisão
3. **Considere contexto**: Escolha ferramenta apropriada para seu contexto (orçamento, equipe, projeto)
4. **Combine ferramentas**: Não precisa escolher apenas uma - combine pontos fortes
5. **Reavalie periodicamente**: Ferramentas evoluem, reavalie a cada 6-12 meses

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] 2-3 ferramentas SAST executadas no mesmo projeto
- [ ] Métricas de comparação coletadas (findings, tempo, false positives)
- [ ] Validação manual de amostra realizada
- [ ] Taxa de false positives calculada para cada ferramenta
- [ ] Aspectos comparados (custo, facilidade, integração, etc.)
- [ ] Relatório comparativo criado
- [ ] Recomendação documentada com justificativa
- [ ] Plano de implementação criado

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Implementar ferramenta(s) SAST escolhida(s) em projeto real
- Criar processo de comparação periódica de ferramentas
- Avaliar ferramentas comerciais se necessário
- Contribuir comparações para a comunidade

---

## 💼 Contexto CWI (Exemplo Hipotético)

**Cenário**: Projeto multi-linguagem (Python + JavaScript) em contexto financeiro

- **Prioridades**: Precisão e cobertura (false positives são aceitáveis se encontrarem vulnerabilidades reais)
- **Orçamento**: Limitado (ferramentas open source preferidas)
- **Equipe**: Pequena (facilidade de uso importante)

Realize comparação considerando essas prioridades.

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Relatório comparativo completo
2. Métricas de cada ferramenta
3. Análise de false positives
4. Recomendação justificada
5. Plano de implementação

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Aula 2.1 (SAST), Exercícios 2.1.1-2.1.4 (recomendado mas não obrigatório)
