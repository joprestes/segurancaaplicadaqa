---
exercise_id: lesson-2-1-exercise-5-compare-sast-tools
title: "Exercício 2.1.5: Comparar Ferramentas SAST"
lesson_id: lesson-2-1
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-14
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

**Metodologia de Validação:**
- Amostra selecionada aleatoriamente de findings Critical/High
- Validação manual: ler código, verificar contexto, testar exploitabilidade
- Classificação: True Positive (vulnerabilidade real) ou False Positive (não é vulnerabilidade)

**Conclusões:**
- **Bandit**: Menor taxa de false positives (12.5%) - mais preciso, mas apenas Python
- **Semgrep**: Taxa média (25%) mas muito rápido e multi-linguagem
- **SonarQube**: Taxa maior (30%) mas encontra mais findings e análise mais profunda
```

**Validação Técnica da Metodologia:**
- ✅ Amostra representativa: inclui findings de diferentes tipos e severidades
- ✅ Validação manual apropriada: não apenas contar, mas analisar código
- ✅ Métricas comparáveis: mesma amostra validada para todas as ferramentas
- ✅ Limitações documentadas: amostra pequena pode não ser estatisticamente representativa

### Passo 5: Comparar Outros Aspectos

**Solução Esperada:**

**5.1. Tempo de Execução:**
| Ferramenta | Tempo (s) | Proporcional | Projeto (LOC) |
|------------|-----------|--------------|---------------|
| Semgrep | 45 | 1x (mais rápido) | ~50k LOC |
| Bandit | 120 | 2.7x | ~50k LOC (Python) |
| SonarQube | 480 | 10.7x (mais lento) | ~50k LOC |

**Observações:**
- Tempos variam com tamanho do projeto e configurações
- SonarQube mais lento mas faz análise mais profunda (data flow)
- Semgrep otimizado para velocidade (pattern matching rápido)

**5.2. Facilidade de Configuração:**
| Ferramenta | Instalação | Configuração | Complexidade |
|------------|-----------|--------------|--------------|
| Semgrep | ⭐⭐⭐ Muito fácil (`pip install semgrep`) | ⭐⭐⭐ Muito fácil (usa regras padrão) | Baixa |
| Bandit | ⭐⭐⭐ Muito fácil (`pip install bandit`) | ⭐⭐ Média (pode precisar config) | Baixa-Média |
| SonarQube | ⭐⭐ Média (Docker ou servidor) | ⭐⭐ Média (projeto, token, config) | Média |

**5.3. Custo:**
| Ferramenta | Versão Testada | Custo Anual | Observações |
|------------|----------------|-------------|-------------|
| Semgrep | Community (gratuito) | $0 | Versão comercial disponível com features extras |
| Bandit | Open source | $0 | Sempre gratuito |
| SonarQube | Community Edition | $0 | Versões Developer/Enterprise têm custos significativos |

**5.4. Integração CI/CD:**
| Ferramenta | GitHub Actions | GitLab CI | Jenkins | Facilidade |
|------------|----------------|-----------|---------|------------|
| Semgrep | ✅ Nativo (action oficial) | ✅ Nativo | ✅ Script | Muito fácil |
| Bandit | ✅ Script | ✅ Script | ✅ Script | Fácil |
| SonarQube | ✅ Nativo (action oficial) | ✅ Nativo | ✅ Plugin | Média-Fácil |

**5.5. Cobertura de Linguagens:**
| Ferramenta | Python | JavaScript | Java | C# | Outras |
|------------|--------|------------|------|----|----|
| Semgrep | ✅ | ✅ | ✅ | ✅ | 20+ linguagens |
| Bandit | ✅ | ❌ | ❌ | ❌ | Apenas Python |
| SonarQube | ✅ | ✅ | ✅ | ✅ | 25+ linguagens |

### Passo 6: Relatório Comparativo

**Solução Esperada - Estrutura do Relatório:**

```markdown
# Relatório Comparativo: Ferramentas SAST

**Data**: 2026-01-14  
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
**Vantagens**: Rápido, fácil de configurar, multi-linguagem, regras customizadas fáceis, integração CI/CD nativa  
**Limitações**: Taxa de false positives média (25% na amostra validada)  
**Melhor Para**: Scan rápido em CI/CD, projetos multi-linguagem, feedback rápido para desenvolvedores

### 3.2. Bandit
**Vantagens**: Menor taxa de false positives (12.5% na amostra), foco especializado em Python, precisa  
**Limitações**: Apenas Python, encontra menos findings que ferramentas multi-linguagem (mas pode ser mais preciso)  
**Melhor Para**: Projetos Python exclusivamente, quando precisão é prioridade

### 3.3. SonarQube
**Vantagens**: Encontra mais findings (45 total), análise profunda (data flow), dashboard visual completo, integração IDE  
**Limitações**: Mais lento (480s vs 45s Semgrep), taxa de false positives maior (30%), requer infraestrutura (Docker/servidor)  
**Melhor Para**: Análise profunda, equipes grandes, projetos que precisam de dashboard centralizado

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

### ✅ Essenciais (Obrigatórios para Aprovação)

**Execução e Coleta de Dados:**
- [ ] 2-3 ferramentas SAST executadas no mesmo projeto
- [ ] Métricas coletadas e documentadas:
  - Número total de findings por severidade
  - Tempo de execução de cada ferramenta
  - Configurações utilizadas

**Análise Comparativa:**
- [ ] Número de findings comparado entre ferramentas
- [ ] Overlap de findings analisado (quais findings são comuns a todas as ferramentas)
- [ ] Tempo de execução comparado (com justificativa para diferenças)

### ⭐ Importantes (Recomendados para Resposta Completa)

**Validação Manual:**
- [ ] Amostra representativa de findings validada manualmente (mínimo 15-20 findings)
- [ ] Taxa de false positives calculada corretamente para cada ferramenta
- [ ] Análise de precisão documentada (quais ferramentas são mais precisas)

**Análise Completa:**
- [ ] Múltiplos aspectos comparados:
  - Custo (gratuito vs pago, infraestrutura necessária)
  - Facilidade de configuração e uso
  - Integração com CI/CD
  - Suporte de linguagens
  - Customização de regras
- [ ] Relatório comparativo estruturado e claro

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Recomendação e Implementação:**
- [ ] Recomendação justificada baseada em dados coletados (não apenas opinião)
- [ ] Plano de implementação criado (passos concretos, timeline)
- [ ] Visualizações incluídas no relatório (tabelas, gráficos, comparações visuais)
- [ ] Considera contexto específico (orçamento, tamanho de equipe, stack tecnológico)

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

**Última atualização**: 2026-01-14  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
