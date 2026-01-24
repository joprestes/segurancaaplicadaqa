---
exercise_id: lesson-2-5-exercise-1-snyk-setup
title: "Exercício 2.5.1: Configurar Snyk em Projeto"
lesson_id: lesson-2-5
module: module-2
difficulty: "Básico"
last_updated: 2026-01-24
---

# Exercício 2.5.1: Configurar Snyk em Projeto

## 📋 Enunciado Completo

Instalar e configurar Snyk para escanear dependências do projeto.

### Tarefa
1. Instalar Snyk CLI
2. Autenticar com conta Snyk
3. Executar scan de dependências
4. Identificar top 3 vulnerabilidades
5. Propor correções (upgrade ou workaround)

---

## ✅ Soluções Detalhadas

**Instalação e scan:**
```bash
npm install -g snyk
snyk auth
snyk test  # Escanear dependências
```

**Análise esperada:**
```markdown
## Top 3 Vulnerabilidades

### 1. lodash@4.17.15 - Prototype Pollution
- **CVSS**: 7.4 (High)
- **CVE**: CVE-2020-8203
- **Correção**: Upgrade para lodash@4.17.21
- **Comando**: `npm install lodash@4.17.21`

### 2. axios@0.21.0 - SSRF
- **CVSS**: 7.5 (High)
- **CVE**: CVE-2021-3749
- **Correção**: Upgrade para axios@0.21.4
- **Comando**: `npm install axios@0.21.4`

### 3. express@4.16.0 - Information Disclosure
- **CVSS**: 5.3 (Medium)
- **CVE**: CVE-2022-24999
- **Correção**: Upgrade para express@4.18.2
```

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] Snyk instalado e configurado
- [ ] Scan executado com sucesso
- [ ] Top 3 vulnerabilidades identificadas
- [ ] Correções propostas

### ⭐ Importantes
- [ ] Testou correções (aplicou upgrades)
- [ ] Validou que aplicação continua funcionando
- [ ] Documentou processo

### 💡 Diferencial
- [ ] Integrou no CI/CD
- [ ] Configurou monitoramento contínuo
- [ ] Criou PR automatizado (Snyk Auto Fix)

---

## 🎓 Pontos Importantes para Monitores

### Erros Comuns

**Erro 1: "Listou todas as vulnerabilidades sem priorizar"**
**Orientação**: "Foque em top 3-5 mais críticas. Priorize por CVSS + exploitability + se é dependência direta."

**Erro 2: "Propôs upgrade que quebra aplicação"**
**Orientação**: "Sempre teste correções! Upgrade de major version pode quebrar. Teste localmente antes de aplicar em produção."

---

**Última atualização**: 2026-01-24
