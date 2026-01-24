---
exercise_id: lesson-2-2-exercise-1-owasp-zap-setup
title: "Exercício 2.2.1: Configurar OWASP ZAP"
lesson_id: lesson-2-2
module: module-2
difficulty: "Básico"
last_updated: 2026-01-24
---

# Exercício 2.2.1: Configurar OWASP ZAP em Aplicação Web

## 📋 Enunciado Completo

Configurar OWASP ZAP e executar primeiro scan DAST em aplicação web.

### Tarefa

1. Instalar OWASP ZAP
2. Configurar proxy (manual ou automated)
3. Executar baseline ou active scan
4. Interpretar resultados (top 3 vulnerabilidades)
5. Criar relatório HTML

---

## ✅ Soluções Detalhadas

### Solução Esperada

**Instalação correta:**
- OWASP ZAP instalado (Desktop ou Docker)
- Proxy configurado (ou Automated Scan usado)
- Scan executado com sucesso
- Relatório HTML gerado

**Top 3 vulnerabilidades documentadas:**

```markdown
## Vulnerabilidade #1: Missing Anti-clickjacking Header
- **URL**: http://testphp.vulnweb.com/
- **Severidade**: Medium
- **Recomendação**: Adicionar X-Frame-Options: DENY

## Vulnerabilidade #2: XSS Reflected
- **URL**: http://testphp.vulnweb.com/search.php
- **Payload testado**: <script>alert(1)</script>
- **Severidade**: High
- **Recomendação**: Sanitizar inputs com DOMPurify
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] ZAP instalado e configurado
- [ ] Scan executado com sucesso
- [ ] Top 3 vulnerabilidades identificadas
- [ ] Relatório gerado

### ⭐ Importantes
- [ ] Interpretou findings corretamente
- [ ] Recomendações de correção propostas
- [ ] Screenshots incluídos

### 💡 Diferencial
- [ ] Testou exploit manual (validou TP)
- [ ] Configurou authenticated scan
- [ ] Exportou findings para Jira/GitHub

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Não consegui configurar proxy"**
**Orientação**: "Use 'Automated Scan' ao invés de proxy manual. Mais simples para começar. Tutorial: ZAP → Quick Start → Automated Scan → URL."

**Erro 2: "Scan não encontrou nada"**
**Orientação**: "Use site vulnerável de teste: http://testphp.vulnweb.com ou DVWA. Aplicações reais podem não ter vulnerabilidades óbvias."

**Erro 3: "Apenas exportou relatório sem analisar"**
**Orientação**: "Análise > Export. Selecione top 3 mais críticas, explique impacto, proponha correção. Não queremos lista, queremos ANÁLISE."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
