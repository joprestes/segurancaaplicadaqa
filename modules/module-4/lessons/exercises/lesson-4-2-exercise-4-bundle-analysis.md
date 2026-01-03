---
layout: exercise
title: "Exercício 4.2.4: Bundle Analysis"
slug: "bundle-analysis"
lesson_id: "lesson-4-2"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **análise de bundles** através da **análise de bundles de aplicação e identificação de oportunidades de otimização**.

Ao completar este exercício, você será capaz de:

- Analisar bundles usando webpack-bundle-analyzer
- Identificar bundles grandes
- Entender composição de bundles
- Identificar oportunidades de otimização
- Aplicar otimizações baseadas em análise

---

## Descrição

Você precisa analisar bundles de uma aplicação Angular e identificar oportunidades de otimização.

### Contexto

Uma aplicação precisa ser otimizada e análise de bundles é essencial para identificar problemas.

### Tarefa

Crie:

1. **Build com Stats**: Gerar build com estatísticas
2. **Análise**: Analisar bundles usando ferramentas
3. **Identificação**: Identificar problemas e oportunidades
4. **Otimização**: Aplicar otimizações identificadas
5. **Comparação**: Comparar antes e depois

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Build com stats gerado
- [ ] Análise realizada
- [ ] Problemas identificados
- [ ] Otimizações aplicadas
- [ ] Comparação documentada

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Análise é completa
- [ ] Otimizações são efetivas

---

## Solução Esperada

### Abordagem Recomendada

**package.json**
```json
{
  "scripts": {
    "build": "ng build",
    "build:stats": "ng build --stats-json",
    "analyze": "npm run build:stats && npx webpack-bundle-analyzer dist/stats.json"
  },
  "devDependencies": {
    "webpack-bundle-analyzer": "^4.9.0"
  }
}
```

**analysis-report.md**
```markdown
# Relatório de Análise de Bundles

## Antes da Otimização

### Bundle Principal (main.js)
- Tamanho: 2.5 MB
- Problemas:
  - Muitas dependências não usadas
  - Código não otimizado
  - Sem code splitting adequado

### Chunks Lazy
- products.chunk.js: 800 KB
- admin.chunk.js: 1.2 MB
- cart.chunk.js: 400 KB

## Otimizações Aplicadas

1. **Lazy Loading**
   - Convertidas rotas para lazy loading
   - Redução de 60% no bundle principal

2. **Tree-shaking**
   - Removidas dependências não usadas
   - Redução de 20% no tamanho total

3. **Code Splitting**
   - Divididos módulos grandes
   - Chunks menores e mais gerenciáveis

## Depois da Otimização

### Bundle Principal (main.js)
- Tamanho: 1.0 MB
- Redução: 60%

### Chunks Lazy
- products.chunk.js: 600 KB (redução de 25%)
- admin.chunk.js: 900 KB (redução de 25%)
- cart.chunk.js: 300 KB (redução de 25%)

## Conclusão

Otimizações resultaram em redução significativa de tamanho de bundles e melhoria de performance.
```

**optimization-steps.md**
```markdown
# Passos de Otimização

## 1. Instalar Ferramentas
```bash
npm install --save-dev webpack-bundle-analyzer
```

## 2. Gerar Build com Stats
```bash
ng build --stats-json
```

## 3. Analisar Bundles
```bash
npx webpack-bundle-analyzer dist/stats.json
```

## 4. Identificar Problemas
- Bundles muito grandes
- Dependências duplicadas
- Código não usado
- Falta de code splitting

## 5. Aplicar Otimizações
- Implementar lazy loading
- Remover dependências não usadas
- Otimizar imports
- Aplicar tree-shaking

## 6. Verificar Resultados
- Comparar tamanhos antes/depois
- Medir performance
- Validar funcionalidade
```

**Explicação da Solução**:

1. webpack-bundle-analyzer instalado
2. Build com --stats-json gera estatísticas
3. Análise visual mostra composição de bundles
4. Problemas identificados e documentados
5. Otimizações aplicadas baseadas em análise
6. Resultados medidos e comparados

---

## Testes

### Casos de Teste

**Teste 1**: Análise funciona
- **Input**: Executar análise
- **Output Esperado**: Relatório gerado

**Teste 2**: Problemas identificados
- **Input**: Analisar relatório
- **Output Esperado**: Problemas claramente identificados

**Teste 3**: Otimizações efetivas
- **Input**: Comparar antes/depois
- **Output Esperado**: Melhorias mensuráveis

---

## Extensões (Opcional)

1. **Automated Analysis**: Automatize análise em CI/CD
2. **Performance Budgets**: Configure budgets de performance
3. **Continuous Monitoring**: Monitore bundles continuamente

---

## Referências Úteis

- **[webpack-bundle-analyzer](https://github.com/webpack-contrib/webpack-bundle-analyzer)**: Documentação
- **[Bundle Optimization](https://angular.io/guide/performance#optimize-bundle-size)**: Guia otimização

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

