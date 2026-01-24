---
exercise_id: lesson-2-5-exercise-5-no-patch-available
title: "Exercício 2.5.5: Vulnerabilidade Sem Patch"
lesson_id: lesson-2-5
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.5.5: Vulnerabilidade Sem Patch Disponível

## 📋 Enunciado
Vulnerabilidade crítica detectada em dependência, mas NÃO há patch disponível. Decisão de risco.

### Cenário
- Biblioteca: `old-parser 2.3.4`
- Vulnerabilidade: **Remote Code Execution (RCE)**
- Severidade: **High (8.5 CVSS)**
- Patch: ❌ **Não disponível** (lib descontinuada há 2 anos)
- Seu uso: Parser de arquivos CSV enviados por usuários
- Exposição: Endpoint público `/api/upload-csv`

### Requisitos
1. Avaliar risco real (exploitabilidade no seu contexto)
2. Analisar alternativas (patch manual, lib alternativa, workaround)
3. Tomada de decisão documentada
4. Implementar mitigação

---

## ✅ Análise e Decisão

### 1. Avaliação de Risco Contextualizado

```markdown
## 🔍 Análise de Vulnerabilidade: CVE-2023-XXXX

### Descrição Técnica
**Vulnerabilidade**: Buffer Overflow em função `parseHeader()`
**Causa**: Falta de validação de tamanho de input
**Exploit**: Enviar CSV com header > 10KB → RCE

### Nosso Contexto
- **Uso**: Parsing de CSV upload de usuários
- **Volume**: ~50 uploads/dia
- **Usuários**: Autenticados (não público aberto)
- **Validação atual**: Max 5MB, apenas clientes premium

### Avaliação CVSS Ajustada
- **Base Score**: 8.5 (High)
- **Temporal Score**: 7.2 (exploit disponível, sem patch)
- **Environmental Score**: 6.0 (nosso contexto)
  - Confidentiality: Medium (dados de clientes)
  - Integrity: High (pode modificar dados)
  - Availability: Low (poucos usuários)
  - **Mitigação existente**: Rate limit, auth, file size limit

### Decisão de Criticidade
**Risco Ajustado**: MEDIUM-HIGH (não crítico imediato, mas requer ação)
```

---

### 2. Análise de Alternativas

| Alternativa | Prós | Contras | Esforço | Decisão |
|-------------|------|---------|---------|---------|
| **1. Patch manual** | Corrige root cause | Manter fork, quebra updates | Alto (2-3 sprints) | ❌ Não recomendado |
| **2. Trocar lib** (`papaparse`) | Lib mantida, sem vulnerabilidade | Rewrite código, testes | Médio (1 sprint) | ✅ **RECOMENDADO** |
| **3. Workaround (input validation)** | Rápido | Não corrige root cause | Baixo (1 dia) | ⚠️ Temporário |
| **4. Aceitar risco** | Zero esforço | Risco aceito formalmente | Zero | ❌ Não aceitável |

**Decisão**: **Opção 2 (Trocar lib)** + **Opção 3 (Workaround imediato)**

---

### 3. Implementação de Mitigação

#### 3.1 Workaround Imediato (Dia 1)

```javascript
// src/middleware/csv-upload-validator.js

// ANTES (vulnerável):
app.post('/api/upload-csv', upload.single('file'), (req, res) => {
  const parsed = oldParser.parse(req.file.buffer);  // ❌ Vulnerável
  res.json(parsed);
});

// DEPOIS (mitigado):
app.post('/api/upload-csv', upload.single('file'), validateCsvInput, (req, res) => {
  const parsed = oldParser.parse(req.file.buffer);  // Ainda usa lib vulnerável
  res.json(parsed);
});

// Middleware de validação
function validateCsvInput(req, res, next) {
  const file = req.file;
  
  // 1. Validação de tamanho de header (mitigar buffer overflow)
  const firstLine = file.buffer.toString('utf8').split('\n')[0];
  if (firstLine.length > 1024) {  // Limite header em 1KB
    return res.status(400).json({ 
      error: 'CSV header muito longo (max 1KB)',
      reason: 'Proteção contra CVE-2023-XXXX' 
    });
  }
  
  // 2. Validação de caracteres suspeitos
  if (/[\x00-\x08\x0B-\x0C\x0E-\x1F]/.test(firstLine)) {
    return res.status(400).json({ 
      error: 'CSV contém caracteres inválidos' 
    });
  }
  
  // 3. Sanitização básica
  req.file.buffer = Buffer.from(file.buffer.toString('utf8').trim());
  
  next();
}
```

**Teste do workaround:**

```bash
# Payload de exploit original
curl -X POST http://localhost:3000/api/upload-csv \
  -F "file=@exploit-long-header.csv"

# Output esperado:
{ "error": "CSV header muito longo (max 1KB)" } ✅

# CSV legítimo ainda funciona
curl -X POST http://localhost:3000/api/upload-csv \
  -F "file=@legit-file.csv"

# Output:
{ "data": [...] } ✅
```

**Deploy**: Hotfix em produção (dia 1)

---

#### 3.2 Solução Definitiva (Sprint 10)

```javascript
// src/services/csv-parser.js

// ANTES (old-parser vulnerável):
const oldParser = require('old-parser');  // ❌ CVE-2023-XXXX

function parseCSV(buffer) {
  return oldParser.parse(buffer);
}

// DEPOIS (papaparse):
const Papa = require('papaparse');  // ✅ Mantido, sem vulnerabilidades

function parseCSV(buffer) {
  const result = Papa.parse(buffer.toString('utf8'), {
    header: true,
    skipEmptyLines: true,
    transformHeader: (header) => header.trim(),
    // Configurações de segurança
    worker: false,  // Não usar web workers (desnecessário no backend)
    download: false,
    fastMode: false,  // Modo seguro (parsing completo)
  });
  
  if (result.errors.length > 0) {
    throw new Error(`CSV parsing error: ${result.errors[0].message}`);
  }
  
  return result.data;
}

module.exports = { parseCSV };
```

**Testes de regressão:**

```javascript
// tests/csv-parser.test.js
const { parseCSV } = require('../src/services/csv-parser');

test('deve parsear CSV legítimo', () => {
  const csv = Buffer.from('name,age\nJohn,30\nJane,25');
  const result = parseCSV(csv);
  
  expect(result).toEqual([
    { name: 'John', age: '30' },
    { name: 'Jane', age: '25' },
  ]);
});

test('deve rejeitar CSV com header longo (proteção CVE)', () => {
  const longHeader = 'a'.repeat(2000);  // 2KB header
  const csv = Buffer.from(`${longHeader}\nvalue`);
  
  expect(() => parseCSV(csv)).toThrow('CSV parsing error');
});

test('deve tratar caracteres especiais', () => {
  const csv = Buffer.from('name,value\n"O\'Reilly",123');
  const result = parseCSV(csv);
  
  expect(result[0].name).toBe("O'Reilly");
});
```

**Validação de segurança:**

```bash
# Scan de vulnerabilidades (antes)
snyk test
# Output: ✗ High severity vulnerability in old-parser

# Atualizar dependência
npm uninstall old-parser
npm install papaparse

# Scan de vulnerabilidades (depois)
snyk test
# Output: ✓ no vulnerabilities found ✅

# Atualizar SBOM
cyclonedx-npm --output-file sbom-v2.0.json
```

---

### 4. Documentação de Decisão

```markdown
## 📋 ADR (Architecture Decision Record): Substituir old-parser

**Status**: Aprovado  
**Data**: 2024-01-24  
**Decisores**: Security Lead, Backend Lead, CTO  

### Contexto
CVE-2023-XXXX (RCE) em `old-parser` sem patch disponível (lib descontinuada).

### Decisão
Substituir `old-parser` por `papaparse` (Sprint 10).  
Implementar workaround (input validation) como mitigação temporária.

### Justificativa
1. **Segurança**: `papaparse` mantido ativamente, sem vulnerabilidades conhecidas
2. **Funcionalidade**: API similar, migração simples
3. **Performance**: Benchmark similar (~5% mais lento, aceitável)
4. **Custo**: 1 sprint de desenvolvimento vs risco de RCE

### Alternativas Consideradas
- Patch manual de old-parser: Rejeitado (custo alto, manutenção contínua)
- Aceitar risco: Rejeitado (não aceitável para RCE)

### Consequências
- **Positivas**: Elimina vulnerabilidade, lib mantida a longo prazo
- **Negativas**: Rewrite de código, testes de regressão
- **Neutras**: Dependência similar (CSV parsing)

### Riscos Residuais
- Workaround pode ter bypass (não testado exaustivamente)
- Migração pode introduzir bugs (cobertura de testes 95%)

### Compliance
- LGPD: Vulnerabilidade RCE = risco de vazamento de dados (Art. 46)
- ISO 27001: A.12.6.1 (gestão de vulnerabilidades técnicas)
```

---

### 5. Comunicação e Rastreamento

**Ticket de Segurança**:

```markdown
## [SEC-1234] CVE-2023-XXXX: RCE em old-parser

**Prioridade**: P1 (High)  
**Severidade**: High  
**Status**: In Progress  

**Timeline:**
- [x] 2024-01-24: Vulnerabilidade detectada
- [x] 2024-01-24: Análise de risco completada
- [x] 2024-01-25: Workaround deployado (produção)
- [ ] 2024-02-10: Migração para papaparse (Sprint 10)
- [ ] 2024-02-15: Validação em produção
- [ ] 2024-02-20: Fechar ticket

**Action Items:**
- [x] Deploy workaround (input validation) - @backend-lead
- [ ] Migrar para papaparse - @dev-team
- [ ] Testes de regressão (100 casos) - @qa-team
- [ ] Validação de segurança - @security-lead
- [ ] Atualizar SBOM - @devops
```

---

## 🎓 Pontos para Monitores

### Conceitos-Chave
1. **Risk-Based Approach**: Decisão baseada em risco contextualizado (não apenas CVSS base)
2. **Defense in Depth**: Workaround temporário + correção definitiva
3. **ADR**: Documentar decisões técnicas importantes
4. **Risk Acceptance**: Quando aceitar risco (formalmente, nunca silenciosamente)

### Erros Comuns

**Erro 1: "Aceitou risco sem documentar"**
- **Feedback**: "Aceitar risco de segurança = decisão executiva. NUNCA aceite silenciosamente. Documente: 1) Por que aceitar (custo vs benefício), 2) Quem aprovou (CTO/CISO), 3) Prazo de revisão (3-6 meses), 4) Mitigações compensatórias. Risco não documentado = responsabilidade pessoal."

**Erro 2: "Aplicou apenas workaround (não corrigiu root cause)"**
- **Feedback**: "Workaround é TEMPORÁRIO. Deve ter plano de correção definitiva (trocar lib, patch, etc). Workaround eterno = débito técnico insustentável. Defina deadline: 'Workaround por 1 sprint, correção definitiva em Sprint 10'."

**Erro 3: "Não testou workaround (assumiu que funciona)"**
- **Feedback**: "Workaround não testado = não funciona. Teste com: 1) Payload de exploit original (deve bloquear), 2) Inputs legítimos (deve permitir), 3) Edge cases (header exatamente 1KB, etc). Workaround falho é pior que nenhum (falsa sensação de segurança)."

**Erro 4: "Não considerou alternativas (focou em patch manual)"**
- **Feedback**: "Antes de fork/patch manual, considere: 1) Libs alternativas (mais fácil que manter fork), 2) Remover funcionalidade (se pouco usada), 3) Isolamento (sandbox/container). Patch manual é última opção (custo alto, manutenção contínua)."

**Erro 5: "CVSS 8.5 = sempre crítico (não contextualizou)"**
- **Feedback**: "CVSS base é genérico. Ajuste por contexto: 1) Exploitabilidade (precisa auth? local?), 2) Impacto (dados sensíveis?), 3) Mitigações existentes (WAF, rate limit). CVSS 8.5 com auth + rate limit + dados não sensíveis = Medium. Use CVSS Environmental Score."

### Feedback Construtivo

**Para análise profissional:**
> "Excelente análise risk-based! Contextualizou CVSS, analisou alternativas, implementou defense in depth (workaround + correção definitiva), documentou decisão (ADR). Isso é security engineering maduro. Processo completo e bem documentado."

**Para análise funcional:**
> "Boa mitigação! Implementou workaround. Para profissionalizar: 1) Documente decisão (ADR), 2) Plano de correção definitiva (deadline), 3) Teste workaround (exploit payload), 4) Comunique stakeholders (risco aceito temporariamente). Técnico correto, agora governança."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
