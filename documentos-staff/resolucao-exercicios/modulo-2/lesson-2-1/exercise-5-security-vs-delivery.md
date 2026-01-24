---
exercise_id: lesson-2-1-exercise-5-security-vs-delivery
title: "Exercício 2.1.5: Trade-off Segurança vs Entrega"
lesson_id: lesson-2-1
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.1.5: Trade-off Segurança vs Entrega

## 📋 Enunciado Completo

**Cenário**: Sprint de 2 semanas está 80% completo. SAST encontrou 8 vulnerabilidades (2 Critical, 3 High, 3 Medium). Product Owner quer lançar feature na sexta-feira. Time de dev diz que corrigir tudo leva 1 semana adicional.

### Tarefa

Tomar decisão como QA Security sobre o que fazer:
1. Analisar vulnerabilidades e avaliar risco real
2. Propor estratégia que balanceia segurança e entrega
3. Justificar decisão tecnicamente e para stakeholders
4. Criar plano de ação pós-lançamento (se aplicável)

---

## ✅ Soluções Detalhadas

### Solução Esperada: Decisão Fundamentada

**Exemplo de análise profissional:**

```markdown
## Análise de Risco: Lançamento vs Segurança

### Vulnerabilidades Críticas (P0)

**1. SQL Injection em /api/checkout**
- **Risco**: Exposição de dados de cartão de crédito
- **Decisão**: **BLOQUEIA LANÇAMENTO** ❌
- **Justificativa**: Viola PCI-DSS, risco financeiro alto
- **Ação**: Hotfix urgente (6-8h), lançar após correção

**2. Authentication Bypass em /admin**
- **Risco**: Acesso não autorizado a painel admin
- **Decisão**: **MITIGAÇÃO TEMPORÁRIA** ⚠️
- **Justificativa**: Endpoint não está na feature nova
- **Ação**: Desabilitar endpoint via WAF, corrigir pós-lançamento

### Estratégia Proposta

**Lançar na sexta COM mitigações:**
1. Corrigir P0 #1 (SQLi) - URGENTE
2. Desabilitar endpoint /admin via WAF
3. Monitorar 24/7 no fim de semana
4. Corrigir restantes na semana seguinte

**Comunicação para stakeholders:**
> "Podemos lançar na sexta com 1 ajuste crítico (SQLi no checkout). As demais vulnerabilidades têm mitigações temporárias. Risco residual é aceitável com monitoramento. Correção completa: semana seguinte."
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais

- [ ] Analisou todas as vulnerabilidades
- [ ] Avaliou risco real (não apenas severity)
- [ ] Tomou decisão fundamentada
- [ ] Considerou stakeholders (PO, dev, security)

### ⭐ Importantes

- [ ] Propôs mitigações temporárias quando aplicável
- [ ] Criou plano de ação pós-lançamento
- [ ] Comunicação clara para técnicos E não-técnicos
- [ ] Considerou compliance (LGPD, PCI-DSS)

### 💡 Diferencial

- [ ] Propôs monitoramento adicional durante rollout
- [ ] Configurou feature flag para rollback rápido
- [ ] Documentou lições aprendidas
- [ ] Criou processo para prevenir situação no futuro

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Bloqueou lançamento sem avaliar mitigações"**
**Orientação**: "Decisão correta pode ser lançar COM mitigações. Avalie: 1) Há mitigação temporária viável? 2) Risco residual é aceitável? 3) Monitoramento detectaria exploração? Segurança absoluta vs pragmatismo."

**Erro 2: "Liberou lançamento ignorando Critical"**
**Orientação**: "Vulnerabilidade Critical em produção sem mitigação = risco inaceitável. Se vai lançar, DEVE ter: 1) Mitigação técnica (WAF, disable feature), 2) Monitoramento 24/7, 3) Plano de rollback. Justifique decisão."

**Erro 3: "Não considerou stakeholders"**
**Orientação**: "Decisão técnica tem impacto no negócio. Comunique: 1) Para PO: impacto no roadmap, 2) Para dev: esforço de correção, 3) Para security: risco residual. Decisão colaborativa > decisão unilateral."

### Feedback Construtivo

**Para decisão madura:**
> "Excelente análise de trade-offs! Você balanceou segurança com realidade do negócio, propôs mitigações viáveis, e comunicou claramente. Essa é a habilidade de um QA Security sênior. Time pode confiar suas decisões."

**Para decisão simplista:**
> "Sua decisão está no caminho certo. Melhore: 1) Analise CADA vulnerabilidade individualmente, 2) Proponha mitigações temporárias quando possível, 3) Crie plano de ação com prazos. Decisão binária (sim/não) raramente é melhor resposta."

### Contexto Pedagógico

**Por que este exercício é crítico:**

1. **Realidade Profissional**: QAs enfrentam pressão de entrega vs segurança constantemente
2. **Tomada de Decisão**: Desenvolve capacidade de avaliar trade-offs
3. **Comunicação**: Treina explicar decisões técnicas para não-técnicos
4. **Pragmatismo**: Segurança absoluta é inviável; mitigação inteligente é a arte

**Não há resposta única correta** - avalie raciocínio, não apenas a decisão final.

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
