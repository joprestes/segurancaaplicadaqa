---
layout: exercise
title: "Exercício 4.4.4: Lighthouse Audit"
slug: "lighthouse"
lesson_id: "lesson-4-4"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **Lighthouse audit** através da **execução de Lighthouse audit e implementação de otimizações sugeridas**.

Ao completar este exercício, você será capaz de:

- Executar Lighthouse audit
- Entender Core Web Vitals
- Analisar métricas de performance
- Implementar otimizações sugeridas
- Melhorar scores do Lighthouse

---

## Descrição

Você precisa executar Lighthouse audit em uma aplicação Angular e implementar otimizações sugeridas.

### Contexto

Uma aplicação precisa melhorar scores do Lighthouse para melhor SEO e UX.

### Tarefa

Crie:

1. **Audit Inicial**: Executar Lighthouse audit
2. **Análise**: Analisar resultados e sugestões
3. **Otimizações**: Implementar otimizações
4. **Audit Final**: Executar audit novamente
5. **Comparação**: Comparar scores antes/depois

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Lighthouse audit executado
- [ ] Resultados analisados
- [ ] Otimizações implementadas
- [ ] Scores melhorados
- [ ] Comparação documentada

### Critérios de Qualidade

- [ ] Audit está completo
- [ ] Otimizações são efetivas
- [ ] Scores melhoraram significativamente

---

## Solução Esperada

### Abordagem Recomendada

**lighthouse-audit.md**
```markdown
# Relatório de Lighthouse Audit

## Audit Inicial

### Performance: 45
- First Contentful Paint: 3.2s
- Largest Contentful Paint: 4.5s
- Time to Interactive: 5.8s
- Total Blocking Time: 1.2s
- Cumulative Layout Shift: 0.15

### Accessibility: 78
- Missing alt text em imagens
- Contraste de cores insuficiente
- Elementos sem labels

### Best Practices: 65
- Console errors
- Imagens não otimizadas
- HTTPS não configurado

### SEO: 72
- Meta tags faltando
- Títulos não otimizados
- Sitemap não encontrado

## Otimizações Aplicadas

1. **Performance**
   - Implementado lazy loading
   - Otimizado bundle size
   - Adicionado preloading
   - Otimizado imagens

2. **Accessibility**
   - Adicionado alt text
   - Melhorado contraste
   - Adicionado labels

3. **Best Practices**
   - Removido console errors
   - Configurado HTTPS
   - Otimizado imagens

4. **SEO**
   - Adicionado meta tags
   - Otimizado títulos
   - Criado sitemap

## Audit Final

### Performance: 85 (+40)
- First Contentful Paint: 1.2s (-62%)
- Largest Contentful Paint: 2.1s (-53%)
- Time to Interactive: 2.8s (-52%)
- Total Blocking Time: 0.3s (-75%)
- Cumulative Layout Shift: 0.05 (-67%)

### Accessibility: 92 (+14)
- Todos alt texts adicionados
- Contraste melhorado
- Labels adicionados

### Best Practices: 95 (+30)
- Console errors removidos
- Imagens otimizadas
- HTTPS configurado

### SEO: 88 (+16)
- Meta tags completos
- Títulos otimizados
- Sitemap criado
```

**optimizations.ts**
```typescript
import { Component } from '@angular/core';
import { CommonModule, NgOptimizedImage } from '@angular/common';
import { Meta, Title } from '@angular/platform-browser';

@Component({
  selector: 'app-optimized',
  standalone: true,
  imports: [CommonModule, NgOptimizedImage],
  template: `
    <div>
      <h1>Página Otimizada</h1>
      <img 
        ngSrc="/assets/hero.jpg"
        width="1200"
        height="600"
        priority
        alt="Hero image description">
      
      <section>
        <h2>Conteúdo Principal</h2>
        <p>Conteúdo otimizado para performance...</p>
      </section>
    </div>
  `
})
export class OptimizedComponent {
  constructor(
    private meta: Meta,
    private title: Title
  ) {
    this.title.setTitle('Página Otimizada - Meu Site');
    this.meta.addTag({ name: 'description', content: 'Descrição otimizada para SEO' });
    this.meta.addTag({ name: 'keywords', content: 'angular, performance, optimization' });
    this.meta.addTag({ property: 'og:title', content: 'Página Otimizada' });
    this.meta.addTag({ property: 'og:description', content: 'Descrição para redes sociais' });
  }
}
```

**Explicação da Solução**:

1. Lighthouse audit executado inicialmente
2. Resultados analisados e documentados
3. Otimizações implementadas baseadas em sugestões
4. ngOptimizedImage usado para imagens
5. Meta tags adicionadas para SEO
6. Audit final mostra melhorias significativas

---

## Testes

### Casos de Teste

**Teste 1**: Audit executado
- **Input**: Executar Lighthouse
- **Output Esperado**: Relatório gerado

**Teste 2**: Otimizações aplicadas
- **Input**: Implementar sugestões
- **Output Esperado**: Código otimizado

**Teste 3**: Scores melhorados
- **Input**: Executar audit novamente
- **Output Esperado**: Scores melhorados

---

## Extensões (Opcional)

1. **CI/CD Integration**: Integre Lighthouse em CI/CD
2. **Performance Budgets**: Configure budgets
3. **Continuous Monitoring**: Monitore scores continuamente

---

## Referências Úteis

- **[Lighthouse](https://developer.chrome.com/docs/lighthouse/)**: Guia Lighthouse
- **[Core Web Vitals](https://web.dev/vitals/)**: Guia Core Web Vitals
- **[ngOptimizedImage](https://angular.io/api/common/NgOptimizedImage)**: Documentação ngOptimizedImage

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

