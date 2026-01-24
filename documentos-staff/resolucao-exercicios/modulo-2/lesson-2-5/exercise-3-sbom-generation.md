---
exercise_id: lesson-2-5-exercise-3-sbom-generation
title: "Exercício 2.5.3: Geração de SBOM"
lesson_id: lesson-2-5
module: module-2
difficulty: "Intermediário"
last_updated: 2026-01-24
---

# Exercício 2.5.3: Gerar e Analisar SBOM

## 📋 Enunciado
Gere Software Bill of Materials (SBOM) do projeto usando CycloneDX ou SPDX.

### Requisitos
1. SBOM gerado (formato CycloneDX ou SPDX)
2. Análise de dependências diretas vs transitivas
3. Identificar dependências com vulnerabilidades conhecidas
4. Compartilhar SBOM com cliente (se aplicável)

---

## ✅ Solução Completa

### 1. Gerar SBOM com CycloneDX (Node.js)

```bash
# Instalar CycloneDX CLI
npm install -g @cyclonedx/cyclonedx-npm

# Gerar SBOM
npx @cyclonedx/cyclonedx-npm --output-file sbom.json

# Output: sbom.json criado
```

**Exemplo de SBOM gerado:**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-24T10:00:00Z",
    "component": {
      "type": "application",
      "name": "meu-app",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/express@4.17.1",
      "name": "express",
      "version": "4.17.1",
      "scope": "required",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "abc123..."
        }
      ],
      "licenses": [{ "license": { "id": "MIT" } }],
      "purl": "pkg:npm/express@4.17.1"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/lodash@4.17.20",
      "name": "lodash",
      "version": "4.17.20",
      "scope": "required"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/meu-app@1.0.0",
      "dependsOn": [
        "pkg:npm/express@4.17.1",
        "pkg:npm/lodash@4.17.20"
      ]
    }
  ]
}
```

### 2. Alternativa: SPDX (Python)

```bash
# Projeto Python
pip install spdx-tools

# Gerar SBOM SPDX
spdx-tools convert --input-format json --output-format spdx sbom-spdx.json
```

### 3. Análise do SBOM

```bash
# Instalar ferramenta de análise
npm install -g sbom-utility

# Analisar dependências diretas vs transitivas
jq '.components[] | {name, version, scope}' sbom.json

# Output:
{
  "name": "express",
  "version": "4.17.1",
  "scope": "required"  # Direta
}
{
  "name": "body-parser",
  "version": "1.19.0",
  "scope": "required"  # Transitiva (dep de express)
}
```

**Estatísticas:**

```bash
# Total de dependências
jq '.components | length' sbom.json
# Output: 245

# Dependências diretas
jq '[.dependencies[0].dependsOn[]] | length' sbom.json
# Output: 8

# Dependências transitivas
echo "Transitivas: $((245 - 8)) = 237"
```

### 4. Identificar Vulnerabilidades no SBOM

```bash
# Scan SBOM com Grype
brew install anchore/grype/grype

grype sbom:./sbom.json

# Output:
NAME       INSTALLED  VULNERABILITY   SEVERITY
express    4.17.1     CVE-2022-24999  High
lodash     4.17.20    CVE-2021-23337  Medium
```

### 5. Compartilhar SBOM com Cliente

**Caso de uso**: Cliente exige SBOM para auditoria de supply chain

```bash
# Gerar SBOM limpo (sem código fonte)
cyclonedx-npm --omit dev --output-file sbom-production.json

# Converter para PDF (mais legível)
npm install -g @cyclonedx/sbom-viewer
sbom-viewer sbom-production.json --output sbom.pdf

# Enviar ao cliente
# Inclua: SBOM + carta explicativa
```

**Email template:**

```
Prezado Cliente,

Conforme solicitado, segue o Software Bill of Materials (SBOM) do sistema XYZ versão 1.0.0.

**O que é SBOM:**
Lista completa de todas as dependências de software (bibliotecas, frameworks) utilizadas no sistema.

**Formato:** CycloneDX 1.4 (padrão NTIA/CISA)

**Conteúdo:**
- 245 componentes totais
- 8 dependências diretas
- 237 dependências transitivas
- Vulnerabilidades conhecidas: 2 (sendo corrigidas)

**Próximos passos:**
- Atualização de vulnerabilidades agendada para Sprint 15 (15/02/2024)
- SBOM atualizado será fornecido após cada release

Ficamos à disposição para esclarecimentos.

Att,
Time de Segurança
```

---

## 🎓 Pontos para Monitores

### Conceitos-Chave
1. **SBOM**: Lista completa de componentes de software (supply chain transparency)
2. **CycloneDX vs SPDX**: Dois padrões principais (CycloneDX mais focado em segurança)
3. **Transitive Dependencies**: Deps indiretas (maioria do risco)
4. **NTIA Minimum Elements**: Padrão governamental US (supplier, component, dependency relationships)

### Erros Comuns

**Erro 1: "SBOM gerado mas está vazio (0 componentes)"**
- **Feedback**: "Valide que: 1) `package-lock.json` existe (npm install antes), 2) Executou comando na pasta correta (raiz do projeto), 3) Tool compatível com seu package manager (npm vs yarn vs pnpm). SBOM vazio = inútil."

**Erro 2: "SBOM inclui devDependencies (ferramentas de build)"**
- **Feedback**: "Para cliente/auditoria, gere SBOM apenas de produção: `--omit dev`. DevDependencies não vão para produção (não são risco para cliente). SBOM de dev é para uso interno (compliance, não compartilhar)."

**Erro 3: "Não analisou vulnerabilidades no SBOM"**
- **Feedback**: "SBOM sem análise de vulnerabilidades é lista estática. Use Grype/Snyk/Trivy para scan: `grype sbom:./sbom.json`. SBOM é INPUT para análise de segurança, não o output final."

**Erro 4: "SBOM desatualizado (gerado há 6 meses)"**
- **Feedback**: "SBOM deve ser gerado a cada release (automated no CI/CD). SBOM antigo não reflete dependências atuais (updates, vulnerabilidades corrigidas). Configure GitHub Action para gerar SBOM automaticamente em cada tag de release."

**Erro 5: "Compartilhou SBOM com código fonte/secrets"**
- **Feedback**: "⚠️ SBOM deve conter APENAS lista de dependências (nome, versão, licença). Não inclua: código fonte, variáveis de ambiente, secrets. Valide antes de enviar: SBOM é público (pode vazar se tem secrets)."

### Feedback Construtivo

**Para SBOM profissional:**
> "Excelente SBOM! CycloneDX gerado, analisado (diretas vs transitivas), vulnerabilidades identificadas, compartilhado profissionalmente. Próximo nível: 1) Automatize geração no CI (cada release), 2) Versionamento de SBOMs (track changes), 3) Assinatura digital (chain of custody), 4) Integração com sistema de compliance do cliente."

**Para SBOM básico:**
> "Bom SBOM gerado! Para profissionalizar: 1) Analise vulnerabilidades (Grype/Snyk), 2) Documente dependências críticas (transitive com vulnerabilidades), 3) Automatize no CI (não manual), 4) Omita devDependencies se para cliente. SBOM gerado, agora usabilidade."

### Contexto Pedagógico Completo

**Por que SBOM é fundamental:**
- **Compliance**: Executive Order 14028 (US) exige SBOM em software governamental
- **Supply Chain**: 92% dos ataques recentes foram via supply chain (Sonatype, 2024)
- **Transparência**: Clientes/auditores exigem visibilidade de dependências
- **Incident Response**: SBOM acelera resposta a CVEs (qual componente afetado?)

**Conexão com o curso:**
- **Pré-requisito**: Exercício 2.5.1 (Snyk), 2.5.2 (npm audit) - SCA
- **Aplica conceitos**: Software Composition Analysis, Supply Chain Security, Compliance
- **Prepara para**: Módulo 3 (Segurança por Setor - compliance), cargo de Security Compliance Analyst

**Habilidades desenvolvidas:**
- Geração de SBOM (CycloneDX, SPDX)
- Análise de supply chain (diretas vs transitivas)
- Identificação de vulnerabilidades em SBOMs
- Comunicação com clientes/auditores
- Compliance com regulações (NTIA, EO 14028)

**Estatísticas da indústria:**
- 88% das organizações exigirão SBOM até 2027 (Gartner, 2025)
- 61% dos ataques exploram dependências transitivas (Sonatype, 2024)
- SBOM reduz MTTR de CVEs em 70% (CISA, 2025)

**Casos de uso SBOM:**

**1. Compliance/Auditoria:**
- Cliente solicita SBOM para auditoria de supply chain
- Governo exige SBOM (Executive Order 14028 - US)
- Certificações (SOC2, ISO27001) requerem inventário de componentes

**2. Incident Response:**
- CVE crítico publicado (ex: Log4Shell) → consultar SBOM → identificar versões afetadas em segundos
- Sem SBOM: Busca manual em 50 repos = horas/dias
- Com SBOM: Query automatizada = minutos

**3. License Compliance:**
- Identificar dependências com licenças incompatíveis (GPL em software proprietário)
- Prevenir violações de licenciamento (multas, processos)

**4. M&A Due Diligence:**
- Empresa sendo adquirida → SBOM revela tech stack e riscos
- Avaliação de débito técnico de segurança

**Ferramentas de geração SBOM:**
- CycloneDX (OWASP) - foco em segurança
- SPDX (Linux Foundation) - foco em licenciamento
- Syft (Anchore) - scans containers também
- Trivy (Aqua Security) - multi-formato

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
