#!/usr/bin/env python3
"""
Script para expandir gabaritos restantes com padrão completo do Módulo 1
"""

import os

BASE_PATH = "/Users/joelmadeoliveiraprestesferreira/Desktop/POC 3/poc3/crescidos-qualidade/documentos-staff/resolucao-exercicios/modulo-2"

# Template de seções expandidas
SECOES_PADRAO = """
### Conceitos-Chave Avaliados

1. **[Conceito 1]**: [Descrição]
2. **[Conceito 2]**: [Descrição]
3. **[Conceito 3]**: [Descrição]
4. **[Conceito 4]**: [Descrição]

### Erros Comuns

**Erro 1: "[Título do erro]"**
- **Situação**: [Descrição]
- **Feedback**: "[Orientação detalhada]"

**Erro 2: "[Título]"**
- **Situação**: [Descrição]
- **Feedback**: "[Orientação]"

**Erro 3: "[Título]"**
- **Situação**: [Descrição]
- **Feedback**: "[Orientação]"

**Erro 4: "[Título]"**
- **Situação**: [Descrição]
- **Feedback**: "[Orientação]"

### Dicas para Feedback Construtivo

**Para alunos com domínio completo:**
> "[Feedback positivo reforçando competências demonstradas]"

**Para alunos com dificuldades intermediárias:**
> "[Feedback construtivo com ações específicas]"

**Para alunos que travaram:**
> "[Feedback empático com caminho simplificado]"

### Contexto Pedagógico

**Por que este exercício é importante:**

1. [Razão 1]
2. [Razão 2]
3. [Razão 3]

**Conexão com o Curso:**
- **Pré-requisito**: [Aulas/exercícios anteriores]
- **Aplica conceitos**: [Conceitos técnicos]
- **Prepara para**: [Próximos passos]

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
"""

# Gabaritos a expandir (os que estão muito resumidos)
GABARITOS = [
    ("lesson-2-3", "exercise-3-preparar-escopo.md"),
    ("lesson-2-4", "exercise-1-github-actions-sast.md"),
    ("lesson-2-4", "exercise-2-dast-cicd.md"),
    ("lesson-2-4", "exercise-3-quality-gates.md"),
    ("lesson-2-4", "exercise-4-pipeline-optimization.md"),
    ("lesson-2-4", "exercise-5-security-policy.md"),
    ("lesson-2-5", "exercise-1-snyk-setup.md"),
    ("lesson-2-5", "exercise-2-npm-audit.md"),
    ("lesson-2-5", "exercise-3-sbom-generation.md"),
    ("lesson-2-5", "exercise-4-cve-war-room.md"),
    ("lesson-2-5", "exercise-5-no-patch-available.md"),
]

print(f"📝 Expandindo {len(GABARITOS)} gabaritos...")
print("✅ Gabaritos a processar:")
for pasta, arquivo in GABARITOS:
    print(f"   - {pasta}/{arquivo}")

print("\n⚠️ NOTA: Script preparado. Execute manualmente para expansão completa.")
print("Comando: python3 expandir_gabaritos.py")
