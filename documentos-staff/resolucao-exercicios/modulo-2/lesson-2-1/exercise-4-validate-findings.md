---
exercise_id: lesson-2-1-exercise-4-validate-findings
title: "Exercício 2.1.4: Validar e Priorizar Findings SAST"
lesson_id: lesson-2-1
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.1.4: Validar e Priorizar Findings SAST

## 📋 Enunciado Completo

Analisar relatório SAST com 50+ findings, validar quais são TRUE POSITIVES, e criar plano de remediação priorizado.

### Tarefa

1. Analisar relatório SAST (SonarQube ou similar)
2. Validar manualmente top 10 findings (TRUE vs FALSE POSITIVE)
3. Priorizar por risco real (não apenas CVSS)
4. Criar plano de remediação com sprints
5. Documentar processo de triagem

---

## ✅ Soluções Detalhadas

### Solução Esperada: Análise Crítica

**Exemplo de validação profissional:**

```markdown
## Análise de Findings SAST

### Resumo
- Total: 53 findings
- Validados: 10 (top prioridade)
- TRUE POSITIVES: 7 (70%)
- FALSE POSITIVES: 3 (30%)

### Finding #1: SQL Injection em UserController

**Status Validação**: ✅ TRUE POSITIVE

**Evidência:**
- Testado payload: `' OR '1'='1' --`
- Resultado: Bypass de autenticação confirmado
- Código em PRODUÇÃO, endpoint PÚBLICO

**Priorização**: P0 - IMEDIATO
- Justificativa: Crítico + Produção + Dados sensíveis

**Finding #2: Hardcoded Password em TestConfig

**Status Validação**: ❌ FALSE POSITIVE

**Evidência:**
- Código está em `test/` (não vai pra produção)
- Senha é para DB de teste local
- Não expõe dados reais

**Ação**: Marcar como FP, adicionar exceção
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais

- [ ] Validou pelo menos 5 findings manualmente
- [ ] Distinguiu TRUE de FALSE POSITIVES com evidências
- [ ] Priorizou por contexto (não apenas CVSS)
- [ ] Criou plano de remediação

### ⭐ Importantes

- [ ] Testou exploração manual (POC)
- [ ] Considerou impacto no negócio
- [ ] Documentou processo de triagem
- [ ] Configurou exceções para FPs

### 💡 Diferencial

- [ ] Criou script de validação automatizada
- [ ] Dashboard de métricas (% TP vs FP)
- [ ] Estratégia de baseline para código legado

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Marcou tudo como TRUE sem validar"**
**Orientação**: "Valide manualmente! Para cada finding: 1) Tente explorar, 2) Analise contexto (prod vs teste), 3) Documente evidências. Confiança sem validação = risco."

**Erro 2: "Priorizou apenas por CVSS"**
**Orientação**: "CVSS é referência, não verdade absoluta. Re-priorize considerando: 1) Código em produção? 2) Dados sensíveis? 3) Facilidade de exploração? Use matriz de risco."

**Erro 3: "Não documentou processo"**
**Orientação**: "Documente triagem para: 1) Outros QAs replicarem, 2) Devs entenderem priorização, 3) Auditorias compliance. Crie template de triagem."

### Feedback Construtivo

**Para análise matura:**
> "Excelente validação! Evidências sólidas (POCs), priorização contextualizada, plano de remediação realista. Você demonstra maturidade de QA Security sênior. Próximo: lidere triagem com time (ensine o processo)."

**Para análise superficial:**
> "Boa identificação de TPs e FPs. Melhore: 1) Adicione evidências (screenshots, POCs), 2) Justifique priorização (por que P0 vs P2?), 3) Crie template replicável. Sua análise está correta, agora profundidade."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
