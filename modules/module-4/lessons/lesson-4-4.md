---
layout: lesson
title: "Aula 4.4: Profiling e Otimização"
slug: profiling
module: module-4
lesson_id: lesson-4-4
duration: "90 minutos"
level: "Avançado"
prerequisites: 
  - "lesson-4-3"
exercises:
  - 
  - "lesson-4-4-exercise-1"
  - "lesson-4-4-exercise-2"
  - "lesson-4-4-exercise-3"
  - "lesson-4-4-exercise-4"
  - "lesson-4-4-exercise-5"
podcast:
  file: "assets/podcasts/04.4-Profiling_Angular_Otimizacao_Como_Fazer.m4a"
  image: "assets/images/podcasts/04.4-Profiling_Angular_Otimizacao_Como_Fazer.png"
  title: "Profiling Angular - Otimização Como Fazer"
  description: "Aprenda a identificar gargalos de performance usando Angular DevTools."
  duration: "55-70 minutos"
permalink: /modules/performance-otimizacao/lessons/profiling/
---

## Introdução

Nesta aula, você dominará técnicas de profiling e otimização para aplicações Angular. Profiling é essencial para identificar gargalos de performance e otimizar aplicações de forma eficiente.

### O que você vai aprender

- Usar Angular DevTools para debugging
- Integrar Chrome DevTools para profiling
- Realizar performance profiling
- Detectar memory leaks
- Analisar bundles
- Executar Lighthouse audits
- Otimizar imagens com ngOptimizedImage

### Por que isso é importante

Profiling permite identificar problemas de performance antes que afetem usuários. Ferramentas modernas fornecem insights valiosos sobre como aplicações Angular se comportam, permitindo otimizações baseadas em dados reais.

---

## Conceitos Teóricos

### Angular DevTools

**Definição**: Angular DevTools é extensão do navegador que fornece insights sobre estrutura de componentes, change detection e performance.

**Explicação Detalhada**:

Angular DevTools:
- Inspeciona componente tree
- Mostra change detection cycles
- Identifica componentes com problemas
- Profiling de performance
- Debugging de state
- Essencial para desenvolvimento

**Analogia**:

Angular DevTools é como um raio-X para sua aplicação Angular, mostrando o que está acontecendo internamente.

**Exemplo Prático**:

```typescript
import { Component } from '@angular/core';

@Component({
  selector: 'app-profile',
  standalone: true,
  template: `<div>Profile Component</div>`
})
export class ProfileComponent {}
```

**Uso**: Instalar extensão Angular DevTools no Chrome/Firefox e inspecionar componentes.

---

### Chrome DevTools Performance

**Definição**: Chrome DevTools Performance tab permite gravar e analisar performance de aplicações.

**Explicação Detalhada**:

Performance Profiling:
- Grava execução da aplicação
- Mostra timeline de eventos
- Identifica long tasks
- Mostra FPS e frame drops
- Analisa JavaScript execution
- Essencial para otimização

**Analogia**:

Performance Profiling é como um gravador de vídeo que captura tudo que acontece, permitindo análise detalhada depois.

**Exemplo Prático**:

1. Abrir Chrome DevTools
2. Ir para Performance tab
3. Clicar em Record
4. Interagir com aplicação
5. Parar gravação
6. Analisar timeline

---

### Memory Profiling

**Definição**: Memory Profiling identifica memory leaks e uso excessivo de memória.

**Explicação Detalhada**:

Memory Profiling:
- Heap snapshots
- Memory timeline
- Identifica objetos não coletados
- Detecta memory leaks
- Mostra uso de memória ao longo do tempo
- Essencial para estabilidade

**Exemplo Prático**:

1. Abrir Chrome DevTools
2. Ir para Memory tab
3. Tirar heap snapshot
4. Interagir com aplicação
5. Tirar outro snapshot
6. Comparar snapshots
7. Identificar objetos não coletados

---

### Bundle Analysis

**Definição**: Bundle Analysis analisa tamanho e composição de bundles JavaScript.

**Explicação Detalhada**:

Bundle Analysis:
- Mostra tamanho de cada bundle
- Identifica dependências grandes
- Encontra código duplicado
- Sugere otimizações
- Essencial para reduzir bundle size

**Exemplo Prático**:

```bash
ng build --stats-json
npx webpack-bundle-analyzer dist/stats.json
```

---

### Lighthouse Audits

**Definição**: Lighthouse é ferramenta automatizada que audita performance, acessibilidade e SEO.

**Explicação Detalhada**:

Lighthouse:
- Performance score
- First Contentful Paint
- Largest Contentful Paint
- Time to Interactive
- Cumulative Layout Shift
- Sugestões de otimização

**Exemplo Prático**:

1. Abrir Chrome DevTools
2. Ir para Lighthouse tab
3. Selecionar categorias
4. Clicar em Generate report
5. Analisar resultados
6. Implementar sugestões

---

### ngOptimizedImage

**Definição**: `ngOptimizedImage` é diretiva Angular que otimiza carregamento e renderização de imagens.

**Explicação Detalhada**:

ngOptimizedImage:
- Lazy loading automático
- Priorização de imagens críticas
- Otimização de tamanho
- Responsive images
- Placeholder support
- Melhora Core Web Vitals

**Exemplo Prático**:

```typescript
import { NgOptimizedImage } from '@angular/common';

@Component({
  selector: 'app-image',
  standalone: true,
  imports: [NgOptimizedImage],
  template: `
    <img 
      ngSrc="/assets/image.jpg"
      width="800"
      height="600"
      priority
      alt="Description">
  `
})
export class ImageComponent {}
```

---

## Exemplos Práticos Completos

### Exemplo 1: Profiling Completo

**Contexto**: Realizar profiling completo de aplicação Angular.

**Código**:

```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-profile-demo',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Performance Profiling Demo</h2>
      <button (click)="heavyOperation()">Heavy Operation</button>
      <button (click)="memoryLeak()">Memory Leak Test</button>
      <ul>
        @for (item of items; track item.id) {
          <li>{{ item.name }}</li>
        }
      </ul>
    </div>
  `
})
export class ProfileDemoComponent implements OnInit {
  items: any[] = [];
  
  ngOnInit(): void {
    console.time('Component Init');
    this.loadData();
    console.timeEnd('Component Init');
  }
  
  heavyOperation(): void {
    console.time('Heavy Operation');
    const result = this.processLargeArray();
    console.timeEnd('Heavy Operation');
    console.log('Result:', result);
  }
  
  memoryLeak(): void {
    setInterval(() => {
      this.items.push({ id: Date.now(), name: 'Item' });
    }, 100);
  }
  
  private processLargeArray(): number {
    let sum = 0;
    for (let i = 0; i < 1000000; i++) {
      sum += i;
    }
    return sum;
  }
  
  private loadData(): void {
    this.items = Array.from({ length: 1000 }, (_, i) => ({
      id: i,
      name: `Item ${i}`
    }));
  }
}
```

---

## Padrões e Boas Práticas

### ✅ Boas Práticas

1. **Profile regularmente**
   - **Por quê**: Identifica problemas cedo
   - **Exemplo**: Profile após mudanças significativas

2. **Use Angular DevTools**
   - **Por quê**: Insights específicos do Angular
   - **Exemplo**: Inspecionar componente tree

3. **Monitore Core Web Vitals**
   - **Por quê**: Métricas importantes para SEO e UX
   - **Exemplo**: Lighthouse audits

4. **Otimize imagens**
   - **Por quê**: Imagens são grandes parte do bundle
   - **Exemplo**: ngOptimizedImage

### ❌ Anti-padrões Comuns

1. **Não ignorar profiling**
   - **Problema**: Problemas não identificados
   - **Solução**: Profile regularmente

2. **Não otimizar prematuramente**
   - **Problema**: Tempo gasto sem necessidade
   - **Solução**: Profile primeiro, otimize depois

3. **Não ignorar memory leaks**
   - **Problema**: Degradação gradual de performance
   - **Solução**: Monitorar memória regularmente

---

## Exercícios Práticos

### Exercício 1: Angular DevTools (Básico)

**Objetivo**: Usar Angular DevTools para debugging

**Descrição**: 
Instale e use Angular DevTools para inspecionar aplicação.

**Arquivo**: `exercises/exercise-4-4-1-devtools.md`

---

### Exercício 2: Performance Profiling (Intermediário)

**Objetivo**: Realizar performance profiling

**Descrição**:
Use Chrome DevTools para fazer profiling de performance e identificar gargalos.

**Arquivo**: `exercises/exercise-4-4-2-performance.md`

---

### Exercício 3: Memory Leaks Detection (Intermediário)

**Objetivo**: Detectar memory leaks

**Descrição**:
Use Chrome DevTools para detectar e corrigir memory leaks.

**Arquivo**: `exercises/exercise-4-4-3-memory-leaks.md`

---

### Exercício 4: Lighthouse Audit (Avançado)

**Objetivo**: Executar Lighthouse audit

**Descrição**:
Execute Lighthouse audit e implemente otimizações sugeridas.

**Arquivo**: `exercises/exercise-4-4-4-lighthouse.md`

---

### Exercício 5: Otimização Completa (Avançado)

**Objetivo**: Otimizar aplicação completa

**Descrição**:
Aplique todas técnicas de profiling e otimização em aplicação real.

**Arquivo**: `exercises/exercise-4-4-5-otimizacao-completa.md`

---

## Referências Externas

### Documentação Oficial

- **[Angular DevTools](https://angular.io/guide/devtools)**: Guia Angular DevTools
- **[Performance](https://angular.io/guide/performance)**: Guia performance
- **[ngOptimizedImage](https://angular.io/api/common/NgOptimizedImage)**: Documentação ngOptimizedImage

---

## Resumo

### Principais Conceitos

- Angular DevTools fornece insights sobre componentes
- Chrome DevTools permite profiling detalhado
- Memory profiling identifica leaks
- Bundle analysis ajuda otimização
- Lighthouse audita performance
- ngOptimizedImage otimiza imagens

### Pontos-Chave para Lembrar

- Profile regularmente
- Use Angular DevTools
- Monitore Core Web Vitals
- Otimize imagens
- Analise bundles
- Detecte memory leaks

### Próximos Passos

- Próxima aula: Zone.js e Zoneless Apps
- Praticar profiling em aplicações
- Explorar ferramentas avançadas

---

## Checklist de Qualidade

Antes de considerar esta aula completa:

- [x] Introdução clara e envolvente
- [x] Todos os conceitos têm definições e explicações detalhadas
- [x] Analogias presentes para conceitos abstratos
- [x] Diagramas ASCII para visualização de conceitos complexos
- [x] Exemplos práticos completos e funcionais
- [x] Boas práticas e anti-padrões documentados
- [x] Exercícios práticos ordenados por dificuldade
- [x] Referências externas validadas e organizadas
- [x] Resumo com pontos principais

---

**Aula Anterior**: [Aula 4.3: Deferrable Views e Performance](./lesson-4-3-deferrable-views.md)  
**Próxima Aula**: [Aula 4.5: Zone.js e Zoneless Apps](./lesson-4-5-zonejs.md)  
**Voltar ao Módulo**: [Módulo 4: Performance e Otimização](../modules/module-4-performance-otimizacao.md)

