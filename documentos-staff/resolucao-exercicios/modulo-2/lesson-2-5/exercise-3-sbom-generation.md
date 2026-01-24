---
exercise_id: lesson-2-5-exercise-3-sbom-generation
title: "Exercício 2.5.3: Gerar SBOM (Software Bill of Materials)"
lesson_id: lesson-2-5
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.5.3: Gerar SBOM

## 📋 Enunciado Completo

Gerar SBOM completo do projeto usando CycloneDX ou SPDX.

### Tarefa
1. Instalar ferramenta de geração SBOM
2. Gerar SBOM em formato JSON/XML
3. Analisar componentes listados
4. Armazenar SBOM para auditoria

---

## ✅ Soluções Detalhadas

**Geração:**
```bash
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm --output-file sbom.json
```

**SBOM deve conter:**
- Nome e versão de cada dependência
- Licenças
- Checksums (hashes)
- Dependências transitivas

---

## 📊 Critérios de Avaliação

### ✅ Essenciais
- [ ] SBOM gerado
- [ ] Formato válido (JSON/XML)
- [ ] Componentes listados corretamente

---

**Última atualização**: 2026-01-24
