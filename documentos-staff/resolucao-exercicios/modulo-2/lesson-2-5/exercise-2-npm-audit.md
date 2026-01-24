---
exercise_id: lesson-2-5-exercise-2-npm-audit
title: "Exercício 2.5.2: npm audit e Correção"
lesson_id: lesson-2-5
module: module-2
difficulty: "Básico"
last_updated: 2026-01-24
---

# Exercício 2.5.2: npm audit e Processo de Correção

## 📋 Enunciado
Use `npm audit` para identificar e corrigir vulnerabilidades. Compare com Snyk.

### Requisitos
1. Executar `npm audit`
2. Corrigir vulnerabilidades automaticamente (quando possível)
3. Comparar resultados npm audit vs Snyk
4. Documentar diferenças

---

## ✅ Solução Completa

### 1. Executar npm audit

```bash
# Scan básico
npm audit

# Output exemplo:
┌───────────────┬──────────────────────────────────────────────────────┐
│ High          │ Prototype Pollution in lodash                        │
├───────────────┼──────────────────────────────────────────────────────┤
│ Package       │ lodash                                               │
├───────────────┼──────────────────────────────────────────────────────┤
│ Patched in    │ >=4.17.21                                            │
├───────────────┼──────────────────────────────────────────────────────┤
│ Dependency of │ react-scripts [dev]                                  │
├───────────────┼──────────────────────────────────────────────────────┤
│ Path          │ react-scripts > webpack > lodash                     │
├───────────────┼──────────────────────────────────────────────────────┤
│ More info     │ https://npmjs.com/advisories/1673                    │
└───────────────┴──────────────────────────────────────────────────────┘

2 vulnerabilities found - Packages: 2 (High: 1, Moderate: 1)
```

### 2. Correção Automática

```bash
# Fix automático (apenas patches/minor)
npm audit fix

# Output:
added 3 packages, removed 5 packages, changed 12 packages, and audited 1024 packages in 8s
fixed 1 of 2 vulnerabilities in 1024 scanned packages
  1 vulnerability required manual review and could not be updated

# Fix com breaking changes (force)
npm audit fix --force  # ⚠️ Cuidado: pode quebrar app

# Após fix, verificar
npm audit

# Output:
found 0 vulnerabilities
```

### 3. Correção Manual

```bash
# Se npm audit fix não resolver tudo
npm audit

# Identifique dependência:
Path: react-scripts > webpack-dev-server > express

# Opções:
# 1. Atualizar pai (react-scripts)
npm update react-scripts

# 2. Resolver dependência transiente (package.json)
{
  "overrides": {
    "express": "^4.18.2"
  }
}

npm install
```

### 4. Comparação npm audit vs Snyk

| Aspecto | npm audit | Snyk |
|---------|-----------|------|
| **Database** | npm Advisory Database | Snyk Vulnerability DB (maior) |
| **Cobertura** | Apenas npm packages | npm, Maven, pip, Docker, etc |
| **False Positives** | Menos | Pode ter mais (database maior) |
| **Correção** | `npm audit fix` | `snyk wizard` + automação |
| **CI/CD** | Nativo (npm audit) | Action específico |
| **Monitoramento** | Não (manual) | Sim (24/7) |
| **Custo** | Grátis | Freemium (open source grátis) |
| **Prioritização** | Severidade | Severidade + Reachability + Exploit maturity |

**Conclusão**: npm audit para quick check, Snyk para gestão completa.

---

## 🎓 Pontos para Monitores

### Conceitos-Chave
1. **npm audit**: Ferramenta nativa do npm (sempre disponível)
2. **Transitive Dependencies**: Vulnerabilidades em deps indiretas
3. **Overrides**: Forçar versão específica de dependência transiente
4. **Breaking Changes**: Atualizações que quebram compatibilidade

### Erros Comuns

**Erro 1: "`npm audit fix --force` quebrou a aplicação"**
- **Feedback**: "`--force` atualiza major versions (breaking changes). SEMPRE teste antes: 1) Rode `npm audit fix` (sem force) primeiro, 2) Teste app (`npm test`), 3) Se não resolver tudo E app funciona, considere force em branch separado, 4) Valide antes de merge. Force é última opção."

**Erro 2: "npm audit mostra 0 vulnerabilidades, Snyk mostra 10"**
- **Feedback**: "Normal. Snyk tem database maior (inclui vulnerabilidades não reportadas no npm). Valide Snyk results: são realmente exploitáveis no seu contexto? Snyk às vezes reporta vulnerabilidades teóricas. Use ambas as ferramentas (complementares, não exclusivas)."

**Erro 3: "Vulnerabilidade em dependência de dev (não corrigiu)"**
- **Feedback**: "Vulnerabilidades em devDependencies têm risco menor (não vão para produção). Priorize runtime primeiro. Se for dev: aceite risco ou atualize quando conveniente. Não gaste 2 dias corrigindo vulnerabilidade em ferramenta de build."

**Erro 4: "Não conseguiu atualizar (peer dependency conflict)"**
- **Feedback**: "Alguns packages têm peer dependencies rígidos. Soluções: 1) Use `overrides` (npm 8.3+) ou `resolutions` (Yarn) para forçar versão, 2) Aguarde update da lib pai, 3) Troque lib se criticidade alta. Às vezes não há solução fácil."

### Feedback Construtivo

**Para análise profissional:**
> "Excelente análise comparativa! Usou npm audit E Snyk, entendeu diferenças, priorizou correções. Próximo nível: 1) Automatize ambas no CI (npm audit + Snyk), 2) Configure `overrides` para dependências problemáticas, 3) SLA de correção (Critical 7 dias, High 30 dias)."

**Para análise básica:**
> "Bom uso de npm audit! Para completar: 1) Compare com Snyk (databases diferentes), 2) Documente por que algumas vulnerabilidades não foram corrigidas, 3) Adicione ao CI (não apenas local), 4) Estabeleça processo de manutenção regular (mensal)."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
