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

### Contexto Pedagógico Completo

**Por que este exercício é fundamental:**
- **npm audit é ferramenta nativa**: Sempre disponível (sem custo adicional), 0 configuração
- **Complementaridade**: npm audit + Snyk = cobertura máxima (databases diferentes)
- **Transitive Dependencies**: 80% das vulnerabilidades estão em deps transitivas (não diretas)
- **Overrides/Resolutions**: Técnica avançada para forçar versão de dep transiente sem atualizar pai

**Conexão com o curso:**
- **Pré-requisito**: Exercício 2.5.1 (Snyk setup), conhecimento de npm/package.json
- **Aplica conceitos**: SCA nativo, patch management, transitive dependencies, overrides
- **Prepara para**: Exercício 2.5.3 (SBOM), 2.5.4 (War Room CVE - resposta rápida a CVEs)
- **Integra com**: Aula 2.4 (Automação - npm audit no CI/CD)

**Habilidades desenvolvidas:**
- Uso de npm audit CLI (test, fix, fix --force)
- Análise de dependências transitivas (path de vulnerabilidade)
- Correção automática vs manual (trade-offs)
- Uso de overrides/resolutions para deps problemáticas
- Comparação de ferramentas SCA (npm audit vs Snyk vs Dependabot)
- Priorização de correções (runtime vs devDependencies)

**Diferenças npm audit vs Snyk:**

| Aspecto | npm audit | Snyk |
|---------|-----------|------|
| **Database** | npm Advisory Database (~5K CVEs) | Snyk Vulnerability DB (~10K CVEs) |
| **Cobertura** | Apenas npm packages | npm, Maven, pip, Docker, Kubernetes, etc |
| **False Positives** | Menos (database menor, mais curada) | Pode ter mais (database maior, mais agressiva) |
| **Correção** | `npm audit fix` (automático) | `snyk wizard` + `snyk fix` (guiado) |
| **CI/CD** | Nativo (`npm audit --audit-level=high`) | Action específico (snyk/actions) |
| **Monitoramento** | Não (apenas snapshot) | Sim (24/7, alertas em tempo real) |
| **Custo** | Grátis (sempre) | Freemium (grátis para open-source, pago para privado) |
| **Prioritização** | Severidade apenas | Severidade + Reachability + Exploit maturity + Fixability |

**Conclusão**: Use ambos (complementares). npm audit para quick check diário, Snyk para gestão completa.

**Estatísticas da indústria:**
- npm audit detecta vulnerabilidades em 65% dos projetos Node.js (NPM, 2025)
- 40% das vulnerabilidades podem ser corrigidas automaticamente (`audit fix`)
- Média de 12 dias entre CVE publicado e correção aplicada (MTTR)
- Teams que usam npm audit + Snyk têm 35% menos vulnerabilidades que os que usam apenas um

**Gestão de vulnerabilidades de longo prazo:**

**SLA de Correção (Service Level Agreement):**
```markdown
## SLA de Correção de Vulnerabilidades

| Severidade | Prazo Máximo | Responsável | Escalação |
|------------|--------------|-------------|-----------|
| **Critical** | 7 dias | Dev team | CTO se não cumprido |
| **High** | 30 dias | Dev team | Engineering Manager |
| **Medium** | 90 dias | Dev team | Sprint planning |
| **Low** | Best effort | Dev team | Backlog |

**Exceções:**
- Vulnerabilidades sem patch disponível: aceitar risco + mitigar (WAF, disable feature)
- Vulnerabilidades em devDependencies: prazo 2x maior (não afeta produção)
```

**Processo de manutenção:**
1. **Semanal**: `npm audit` local (devs antes de commit)
2. **Diário**: CI/CD bloqueia se Critical introduzido
3. **Mensal**: Revisão completa (priorizar correções pendentes)
4. **Trimestral**: Auditoria externa (validar processo)

**Ferramentas complementares:**
- **Dependabot** (GitHub): PRs automáticos para updates de segurança
- **Renovate Bot**: Alternativa mais configurável
- **Socket.dev**: Detecta malware em packages (supply chain attacks)
- **npm outdated**: Identificar dependências desatualizadas

**Estratégias de atualização:**

**1. Patch Immediately (Patches e Minor):**
```bash
# Atualizações seguras (não quebram compatibilidade)
npm audit fix
# Ou
npm update lodash  # 4.17.20 → 4.17.21 (patch)
```

**2. Plan for Major (Breaking Changes):**
```bash
# Major versions requerem planejamento
npm outdated  # Ver majors disponíveis
# Agendar no backlog: "Upgrade Express 4 → 5"
# Testar extensivamente antes
```

**3. Accept Risk (Sem Patch Disponível):**
```bash
# Vulnerabilidade sem patch → aceitar temporariamente
npm audit --audit-level=moderate  # Ignora low
# Mitigar: WAF, input validation, monitoring
# Revisitar mensalmente (patch disponível?)
```

**Comparação com Snyk (quando usar cada ferramenta):**

**Use npm audit quando:**
- ✅ Quick check antes de commit (grátis, rápido, sempre disponível)
- ✅ CI/CD bloqueio simples (`npm audit --audit-level=high`)
- ✅ Projeto Node.js puro (não multi-linguagem)

**Use Snyk quando:**
- ✅ Monitoramento contínuo necessário (alertas em tempo real)
- ✅ Priorização inteligente (Reachability analysis, Exploit maturity)
- ✅ Multi-linguagem (Node.js + Python + Java no mesmo mono-repo)
- ✅ Container scanning (Dockerfile, imagens Docker)
- ✅ IaC scanning (Terraform, Kubernetes YAML)

**Conclusão**: Use AMBOS. npm audit (diário, CI/CD) + Snyk (monitoramento, análise profunda).

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
