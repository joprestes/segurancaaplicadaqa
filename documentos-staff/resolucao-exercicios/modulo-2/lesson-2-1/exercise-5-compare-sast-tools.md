---
exercise_id: lesson-2-1-exercise-5-compare-sast-tools
title: "Exercício 2.1.5: Comparar Ferramentas SAST"
lesson_id: lesson-2-1
module: module-2
difficulty: "Avançado"
last_updated: 2025-01-15
---

# Exercício 2.1.5: Comparar Ferramentas SAST

## 📋 Enunciado Completo

Este exercício tem como objetivo **comparar diferentes ferramentas SAST** no mesmo projeto, analisar resultados, e criar relatório comparativo com recomendação.

### Tarefa Principal

1. Escolher projeto para análise
2. Executar 2-3 ferramentas SAST diferentes no mesmo projeto
3. Comparar resultados (número de findings, false positives, tempo)
4. Validar manualmente amostra de findings
5. Analisar custo, facilidade de uso, integração
6. Criar relatório comparativo com recomendação

---

## ✅ Soluções Detalhadas

### Passo 1: Preparar Ambiente

**Solução Esperada:**

**1.1. Ferramentas Escolhidas (Exemplo):**
- Semgrep (gratuito, rápido)
- Bandit (Python específico, gratuito)
- SonarQube Community (completo, gratuito)

**1.2. Projeto Escolhido:**
- Projeto próprio (preferido)
- Ou projeto de exemplo (OWASP Juice Shop, WebGoat)

### Passo 2: Executar Ferramentas SAST

**Solução Esperada:**

**2.1. Métricas Coletadas:**
```json
{
  "project": "meu-projeto",
  "scan_date": "2024-01-15",
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

**Solução Esperada:**

**3.1. Tabela Comparativa:**
```markdown
## Comparação de Findings

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

## Findings Únicos
- **Semgrep**: 3 findings únicos
- **Bandit**: 1 finding único (Python-specific)
- **SonarQube**: 8 findings únicos (análise mais profunda)
```

### Passo 4: Validar Findings Manualmente

**Solução Esperada:**

**4.1. Amostra Validada:**
- Total amostra: 20-25 findings
- Semgrep: 8 findings (6 TP, 2 FP)
- Bandit: 8 findings (7 TP, 1 FP)
- SonarQube: 10 findings (7 TP, 3 FP)

**4.2. Taxa de False Positives:**
```markdown
## Análise de False Positives

| Ferramenta | Total Amostra | True Positives | False Positives | Taxa FP |
|------------|---------------|----------------|-----------------|---------|
| Semgrep | 8 | 6 | 2 | 25% |
| Bandit | 8 | 7 | 1 | 12.5% |
| SonarQube | 10 | 7 | 3 | 30% |

**Conclusão**: Bandit tem menor taxa de false positives (mais preciso), mas Semgrep é mais rápido.
```

### Passo 5: Comparar Outros Aspectos

**Solução Esperada:**

**5.1. Tempo de Execução:**
| Ferramenta | Tempo (s) | Proporcional |
|------------|-----------|--------------|
| Semgrep | 45 | 1x (mais rápido) |
| Bandit | 120 | 2.7x |
| SonarQube | 480 | 10.7x (mais lento) |

**5.2. Facilidade de Configuração:**
- Semgrep: ⭐⭐⭐ Muito fácil (apenas instalar)
- Bandit: ⭐⭐⭐ Muito fácil (pip install)
- SonarQube: ⭐⭐ Média (requer Docker/servidor)

**5.3. Custo:**
- Todas: $0 (Community Edition/Gratuito)
- Nota: Versões comerciais disponíveis com custos variados

**5.4. Integração CI/CD:**
- Semgrep: ✅ Nativo (GitHub Actions, GitLab CI)
- Bandit: ✅ Script (fácil de integrar)
- SonarQube: ✅ Nativo (GitHub Actions, GitLab CI)

**5.5. Cobertura de Linguagens:**
- Semgrep: ✅ Python, JavaScript, Java, C# (multi-linguagem)
- Bandit: ✅ Apenas Python
- SonarQube: ✅ Python, JavaScript, Java, C# (multi-linguagem)

### Passo 6: Relatório Comparativo

**Solução Esperada - Estrutura do Relatório:**

```markdown
# Relatório Comparativo: Ferramentas SAST

**Data**: 2024-01-15  
**Projeto Analisado**: [Nome do Projeto]  
**Ferramentas Comparadas**: Semgrep, Bandit, SonarQube

## 1. Resumo Executivo

Este relatório compara 3 ferramentas SAST executadas no mesmo projeto.

**Recomendação**: Usar **combinação de Semgrep + Bandit** (se projeto Python) ou **Semgrep + SonarQube** (se multi-linguagem)

**Justificativa**:
- Semgrep para scan rápido em CI/CD (velocidade)
- Bandit/SonarQube para análise profunda (cobertura)
- Combinar pontos fortes de cada ferramenta

## 2. Métricas de Comparação

### 2.1. Número de Findings
[Gráfico/Tabela]

### 2.2. Precisão (False Positive Rate)
- Semgrep: 25%
- Bandit: 12.5% (melhor)
- SonarQube: 30%

### 2.3. Tempo de Execução
- Semgrep: 45s (mais rápido)
- Bandit: 120s
- SonarQube: 480s (mais lento)

## 3. Análise Detalhada

### 3.1. Semgrep
**Pontos Fortes**: Rápido, fácil de configurar, multi-linguagem, regras customizadas fáceis  
**Pontos Fracos**: Taxa de false positives média (25%)  
**Melhor Para**: Scan rápido em CI/CD, projetos multi-linguagem

### 3.2. Bandit
**Pontos Fortes**: Menor taxa de false positives (12.5%), foco Python  
**Pontos Fracos**: Apenas Python, menos findings que SonarQube  
**Melhor Para**: Projetos Python exclusivamente

### 3.3. SonarQube
**Pontos Fortes**: Encontra mais findings (45 total), análise profunda, dashboard  
**Pontos Fracos**: Mais lento (480s), taxa de false positives maior (30%)  
**Melhor Para**: Análise profunda, equipes grandes

## 4. Recomendação

**Recomendação**: Semgrep (CI/CD) + SonarQube (nightly scans)

**Implementação**:
1. Semgrep em pre-commit hooks (scan rápido)
2. Semgrep no CI/CD (scan em cada PR)
3. SonarQube em scheduled scans (análise profunda noturna)

## 5. Próximos Passos
1. Implementar Semgrep em pre-commit
2. Configurar Semgrep no CI/CD
3. Configurar SonarQube para scans noturnos
4. Reavaliar em 3 meses
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (60 pontos)

**Execução e Coleta de Dados:**
- [ ] 2-3 ferramentas SAST executadas no mesmo projeto (15 pontos)
- [ ] Métricas coletadas (findings, tempo, false positives) (15 pontos)

**Análise Comparativa:**
- [ ] Número de findings comparado (10 pontos)
- [ ] False positive rate calculado (10 pontos)
- [ ] Tempo de execução comparado (10 pontos)

### ⭐ Importantes (25 pontos)

**Validação Manual:**
- [ ] Amostra de findings validada manualmente (10 pontos)
- [ ] Taxa de false positives calculada corretamente (5 pontos)

**Análise Completa:**
- [ ] Múltiplos aspectos comparados (custo, facilidade, integração) (10 pontos)
- [ ] Relatório comparativo criado (10 pontos)

### 💡 Bônus (15 pontos)

**Recomendação e Implementação:**
- [ ] Recomendação justificada baseada em dados (5 pontos)
- [ ] Plano de implementação criado (5 pontos)
- [ ] Gráficos/tabelas visuais incluídos no relatório (5 pontos)

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Análise Comparativa**: Aluno compara ferramentas objetivamente?
2. **Validação**: Aluno valida findings manualmente?
3. **Recomendação**: Aluno recomenda baseado em dados?
4. **Implementação**: Aluno propõe plano de implementação?

### Erros Comuns

1. **Erro: Comparar Sem Validar**
   - **Situação**: Aluno compara número de findings sem validar se são reais
   - **Feedback**: "Ótima comparação! Lembre-se de validar manualmente uma amostra para calcular taxa de false positives. Uma ferramenta pode encontrar mais findings, mas se muitos são false positives, pode não ser melhor."

2. **Erro: Recomendação Sem Justificativa**
   - **Situação**: Aluno recomenda ferramenta sem base em dados
   - **Feedback**: "Boa recomendação! Apoie sempre com dados coletados: taxa de false positives, tempo de execução, facilidade de uso. Isso torna a recomendação mais convincente."

3. **Erro: Não Considerar Contexto**
   - **Situação**: Aluno recomenda ferramenta sem considerar orçamento/equipe
   - **Feedback**: "Ótima análise técnica! Considere também contexto: orçamento limitado? Equipe pequena? Projeto multi-linguagem? Isso ajuda a escolher ferramenta apropriada."

---

**Última atualização**: 2025-01-15  
**Criado por**: Equipe Pedagógica CWI  
**Revisado por**: [A definir]
