---
layout: exercise
title: "Exercício 2.2.5: Comparar Ferramentas DAST"
slug: "compare-dast-tools"
lesson_id: "lesson-2-2"
module: "module-2"
difficulty: "Avançado"
permalink: /modules/testes-seguranca-pratica/lessons/exercises/lesson-2-2-exercise-5-compare-dast-tools/
lesson_url: /modules/testes-seguranca-pratica/lessons/dast-testes-dinamicos/
---

## Objetivo

Este exercício tem como objetivo **comparar diferentes ferramentas DAST** na mesma aplicação, analisar resultados, e criar relatório comparativo com recomendação.

Ao completar este exercício, você será capaz de:

- Executar múltiplas ferramentas DAST na mesma aplicação
- Comparar resultados (findings, false positives, tempo de execução)
- Avaliar precisão de cada ferramenta
- Analisar custo-benefício
- Criar relatório comparativo com recomendação

---

## Descrição

Você vai executar 2-3 ferramentas DAST diferentes na mesma aplicação, comparar resultados detalhadamente, validar findings manualmente, e criar relatório comparativo com recomendação de qual ferramenta usar.

### Contexto

Cada ferramenta DAST tem pontos fortes diferentes. Comparar ferramentas ajuda a escolher a melhor opção para seu contexto, orçamento e necessidades.

### Tarefa Principal

1. Escolher aplicação para análise
2. Executar 2-3 ferramentas DAST diferentes na mesma aplicação
3. Comparar resultados (número de findings, false positives, tempo)
4. Validar manualmente amostra de findings
5. Analisar custo, facilidade de uso, integração
6. Criar relatório comparativo com recomendação

---

## Requisitos

### Passo 1: Preparar Ambiente

**1.1. Escolher Aplicação**

- Aplicação própria (preferido)
- Ou aplicação de exemplo (OWASP Juice Shop, WebGoat)

**1.2. Instalar Ferramentas DAST**

Instalar 2-3 ferramentas DAST:

**Opção A: Open Source (Gratuito)**
- OWASP ZAP
- Nikto (scanner de servidor web)
- Wfuzz (fuzzer web)

**Opção B: Open Source + Trial Comercial**
- OWASP ZAP (gratuito)
- Burp Suite Community (gratuito)
- Acunetix Trial (se disponível)

**1.3. Verificar Instalação**

```bash
# Verificar OWASP ZAP
docker ps | grep zap

# Verificar Burp Suite (se instalado)
# Abrir Burp Suite e verificar que inicia

# Verificar Nikto
nikto -Version
```

### Passo 2: Executar Ferramentas DAST

**2.1. Executar OWASP ZAP**

```bash
# Executar scan completo
docker exec zap zap-full-scan.py \
  -t http://localhost:3000 \
  -J zap-results.json \
  -r zap-results.html

# Medir tempo de execução
time docker exec zap zap-full-scan.py -t http://localhost:3000
```

**2.2. Executar Burp Suite**

1. Iniciar Burp Suite
2. Configurar proxy no navegador
3. Navegar pela aplicação
4. Executar scan automatizado (Scanner tab)
5. Exportar resultados (Report → Generate Report)

**2.3. Executar Nikto (Opcional)**

```bash
# Executar Nikto
nikto -h http://localhost:3000 -Format json -o nikto-results.json

# Medir tempo de execução
time nikto -h http://localhost:3000
```

### Passo 3: Consolidar Resultados

**3.1. Criar Arquivo de Comparação**

Criar arquivo `comparison/dast-comparison.json`:

```json
{
  "application": "http://localhost:3000",
  "scan_date": "2026-01-14",
  "tools": [
    {
      "name": "OWASP ZAP",
      "version": "2.14.0",
      "type": "Open Source",
      "cost": "Free",
      "results": {
        "total_findings": 28,
        "high": 2,
        "medium": 8,
        "low": 18,
        "execution_time_minutes": 15,
        "false_positives_estimated": 3
      }
    },
    {
      "name": "Burp Suite Community",
      "version": "2024.1",
      "type": "Community Edition",
      "cost": "Free",
      "results": {
        "total_findings": 22,
        "high": 1,
        "medium": 7,
        "low": 14,
        "execution_time_minutes": 20,
        "false_positives_estimated": 2
      }
    }
  ]
}
```

**3.2. Extrair Métricas**

Para cada ferramenta, documentar:

- Total de findings
- Por severidade (High, Medium, Low)
- Tempo de execução
- False positives estimados (após validação manual)
- Cobertura (quantas URLs testadas)

### Passo 4: Validar Findings Manualmente

**4.1. Selecionar Amostra**

Selecionar 10-15 findings de cada ferramenta para validação manual:

- Todos os High/Critical
- Amostra aleatória de Medium
- Alguns Low (se tempo permitir)

**4.2. Validar Cada Finding**

Para cada finding:

1. Reproduzir manualmente o ataque
2. Verificar se vulnerabilidade é real
3. Classificar: True Positive ou False Positive
4. Documentar resultado

**4.3. Calcular Precisão**

```python
# Exemplo de cálculo de precisão
total_validated = 15
true_positives = 12
false_positives = 3

precision = (true_positives / total_validated) * 100
# precision = 80%
```

### Passo 5: Comparar Aspectos Técnicos

**5.1. Criar Tabela Comparativa**

| Aspecto | OWASP ZAP | Burp Suite Community | Acunetix |
|---------|-----------|----------------------|----------|
| **Custo** | Gratuito | Gratuito | Pago |
| **Velocidade** | Rápido | Médio | Muito Rápido |
| **Precisão** | Alta (80%) | Alta (85%) | Muito Alta (90%) |
| **False Positives** | Médios (15%) | Baixos (10%) | Muito Baixos (5%) |
| **Automação** | Excelente | Limitada | Excelente |
| **CI/CD Integration** | Excelente | Limitada | Excelente |
| **Interface** | Web/CLI | Desktop | Web |
| **Extensibilidade** | Add-ons | BApp Store | Limitada |
| **Suporte** | Comunidade | Comunidade | Comercial |
| **Melhor Para** | Equipes pequenas/médias | Testes manuais | Empresas grandes |

**5.2. Analisar Pontos Fortes e Fracos**

Para cada ferramenta:

**OWASP ZAP**:
- ✅ Pontos Fortes: Gratuito, excelente automação, boa integração CI/CD
- ❌ Pontos Fracos: Interface pode ser complexa, alguns false positives

**Burp Suite Community**:
- ✅ Pontos Fortes: Interface excelente, ótimo para testes manuais
- ❌ Pontos Fracos: Automação limitada na versão Community, sem CI/CD nativo

**Acunetix**:
- ✅ Pontos Fortes: Muito preciso, poucos false positives, suporte comercial
- ❌ Pontos Fracos: Caro, pode não ser acessível para equipes pequenas

### Passo 6: Analisar Custo-Benefício

**6.1. Calcular ROI**

Para cada ferramenta, considerar:

- **Custo**: Licença, infraestrutura, tempo de setup
- **Benefício**: Vulnerabilidades encontradas, tempo economizado
- **ROI**: (Benefício - Custo) / Custo

**6.2. Exemplo de Análise**

```markdown
## Análise de Custo-Benefício

### OWASP ZAP
- **Custo**: $0 (gratuito) + 2h setup = ~$100 (tempo)
- **Benefício**: 28 findings (12 TP) = ~$24,000 (economia vs produção)
- **ROI**: 23,900%

### Burp Suite Community
- **Custo**: $0 (gratuito) + 1h setup = ~$50 (tempo)
- **Benefício**: 22 findings (10 TP) = ~$20,000 (economia vs produção)
- **ROI**: 39,900%

### Acunetix
- **Custo**: $5,000/ano (licença) + 1h setup = ~$5,050
- **Benefício**: 25 findings (15 TP) = ~$30,000 (economia vs produção)
- **ROI**: 494%
```

### Passo 7: Criar Relatório Comparativo

**7.1. Estrutura do Relatório**

Criar arquivo `reports/dast-tools-comparison.md`:

```markdown
# Relatório Comparativo: Ferramentas DAST

## Resumo Executivo

Este relatório compara 3 ferramentas DAST testadas na aplicação [nome]:
- OWASP ZAP
- Burp Suite Community
- Acunetix (trial)

**Recomendação**: [Ferramenta recomendada] para [contexto específico]

## Metodologia

- Aplicação testada: [URL]
- Data do teste: [Data]
- Ferramentas testadas: [Lista]
- Métricas coletadas: Findings, tempo, precisão, custo

## Resultados

### Número de Findings

| Ferramenta | Total | High | Medium | Low |
|------------|-------|------|--------|-----|
| OWASP ZAP | 28 | 2 | 8 | 18 |
| Burp Suite | 22 | 1 | 7 | 14 |
| Acunetix | 25 | 2 | 9 | 14 |

### Precisão (True Positives)

| Ferramenta | Validados | TP | FP | Precisão |
|------------|-----------|----|----|----------| 
| OWASP ZAP | 15 | 12 | 3 | 80% |
| Burp Suite | 15 | 13 | 2 | 87% |
| Acunetix | 15 | 14 | 1 | 93% |

### Tempo de Execução

| Ferramenta | Tempo (minutos) |
|------------|-----------------|
| OWASP ZAP | 15 |
| Burp Suite | 20 |
| Acunetix | 10 |

### Custo

| Ferramenta | Custo Anual | Setup (horas) |
|------------|-------------|---------------|
| OWASP ZAP | $0 | 2h |
| Burp Suite | $0 | 1h |
| Acunetix | $5,000 | 1h |

## Análise Detalhada

### OWASP ZAP
[Análise detalhada]

### Burp Suite
[Análise detalhada]

### Acunetix
[Análise detalhada]

## Recomendação

**Para equipes pequenas/médias**: OWASP ZAP
- Gratuito
- Boa automação
- Excelente integração CI/CD

**Para testes manuais**: Burp Suite Community
- Interface excelente
- Ótimo para exploração manual

**Para empresas grandes**: Acunetix
- Muito preciso
- Suporte comercial
- Poucos false positives

## Próximos Passos

1. Implementar ferramenta recomendada
2. Configurar integração CI/CD
3. Treinar equipe
4. Estabelecer processo de triagem
```

---

## Dicas

1. **Use mesma aplicação**: Teste todas as ferramentas na mesma aplicação para comparação justa
2. **Valide manualmente**: Não confie apenas nos números, valide findings manualmente
3. **Considere contexto**: Escolha ferramenta apropriada para seu contexto (tamanho de equipe, orçamento, necessidades)
4. **Documente tudo**: Documente configurações, resultados, e decisões
5. **Teste em produção real**: Se possível, teste em aplicação real (staging) para resultados mais precisos

---

## Validação

Verifique se você completou o exercício corretamente:

- [ ] 2-3 ferramentas DAST executadas na mesma aplicação
- [ ] Resultados consolidados e comparados
- [ ] Amostra de findings validada manualmente
- [ ] Precisão calculada para cada ferramenta
- [ ] Tabela comparativa criada
- [ ] Análise de custo-benefício realizada
- [ ] Relatório comparativo criado com recomendação

---

## Próximos Passos

Após completar este exercício, você estará preparado para:

- Escolher ferramenta DAST apropriada para seu contexto
- Implementar ferramenta escolhida em projeto real
- Comparar ferramentas em outros contextos (financeiro, educacional, etc.)

---

## 💼 Contexto CWI (Exemplo Hipotético)

**Cenário**: Comparação para projeto financeiro hipotético

- **Critérios importantes**: Precisão alta, poucos false positives, compliance
- **Orçamento**: Limitado (preferir open source)
- **Recomendação**: OWASP ZAP (gratuito, boa precisão, excelente para CI/CD)

Aplique a comparação considerando esses critérios específicos.

---

## 📤 Enviar Resposta

Complete o exercício e envie:

1. Tabela comparativa completa
2. Análise de precisão (validação manual)
3. Análise de custo-benefício
4. Relatório comparativo com recomendação
5. Justificativa da recomendação

{% include exercise-submission-form.html %}

---

**Duração Estimada**: 90-120 minutos  
**Nível**: Avançado  
**Pré-requisitos**: Aula 2.2 (DAST), Exercícios 2.2.1 e 2.2.2 (OWASP ZAP e Burp Suite)
