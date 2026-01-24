---
exercise_id: lesson-2-1-exercise-3-sast-cicd
title: "Exercício 2.1.3: Integrar SAST no CI/CD"
lesson_id: lesson-2-1
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.1.3: Integrar SAST no CI/CD

## 📋 Enunciado Completo

Integrar análise SAST (SonarQube ou Semgrep) no pipeline CI/CD para executar scans automaticamente em cada Pull Request ou commit.

### Tarefa

1. Configurar SAST no pipeline CI/CD (GitHub Actions, GitLab CI, ou similar)
2. Executar scan automaticamente em PRs
3. Configurar Quality Gate que bloqueia PRs com vulnerabilidades críticas
4. Validar integração com PR de teste
5. Documentar processo

---

## ✅ Soluções Detalhadas

### Solução Esperada: Pipeline Funcional

**GitHub Actions (exemplo):**

```yaml
# .github/workflows/sast.yml
name: SAST Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
          
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        
      - name: Quality Gate
        run: |
          # Aguardar resultado do Quality Gate
          # Falhar build se Quality Gate falhou
```

**Evidências de integração correta:**
- Pipeline executa em PRs automaticamente
- Quality Gate bloqueia PRs com Critical vulnerabilities
- Resultados visíveis no PR (comentários, checks)
- Documentação de como visualizar resultados

---

## 📊 Critérios de Avaliação

### ✅ Essenciais

- [ ] Pipeline CI/CD configurado
- [ ] SAST executa automaticamente em PRs
- [ ] Quality Gate configurado (bloqueia Critical)
- [ ] PR de teste validou funcionamento

### ⭐ Importantes

- [ ] Resultados postados como comentário no PR
- [ ] Pipeline otimizado (< 5 min)
- [ ] Documentação clara (README)
- [ ] Configuração de exceções (baseline)

### 💡 Diferencial

- [ ] Múltiplas ferramentas SAST (SonarQube + Semgrep)
- [ ] Scan diferencial (apenas código novo)
- [ ] Métricas de tendência (dashboard)

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Pipeline muito lento (> 10min)"**
**Orientação**: "Otimize: 1) Use cache de dependências, 2) Execute apenas em arquivos modificados (diff), 3) Configure exclusões (node_modules, dist). Meta: < 5min."

**Erro 2: "Quality Gate bloqueia TUDO"**
**Orientação**: "Comece permissivo (0 Critical apenas). Gradualmente aperte (0 High, depois Medium). Configure baseline para código legado."

**Erro 3: "Token exposto no pipeline"**
**Orientação**: "⚠️ Use secrets do GitHub/GitLab! NUNCA hardcode tokens no .yml. Revogue token exposto imediatamente."

### Feedback Construtivo

**Para integração profissional:**
> "Excelente! Pipeline otimizado, Quality Gate apropriado, resultados visíveis. Time pode iterar rapidamente com feedback de segurança. Próximo: monitore métricas (% de PRs bloqueados, tempo de correção)."

**Para integração básica:**
> "Bom trabalho! Pipeline funciona. Melhore: 1) Otimize tempo de execução, 2) Poste resultados no PR, 3) Documente processo. Sua integração está funcional, agora refine experiência do dev."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano
