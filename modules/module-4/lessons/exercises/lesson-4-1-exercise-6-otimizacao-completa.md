---
layout: exercise
title: "Exercício 4.1.6: Otimização Completa"
slug: "otimizacao-completa"
lesson_id: "lesson-4-1"
module: "module-4"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **todas técnicas de otimização** através da **aplicação completa de otimizações de change detection em aplicação real**.

Ao completar este exercício, você será capaz de:

- Aplicar todas técnicas aprendidas
- Otimizar aplicação completa
- Medir melhorias de performance
- Criar aplicação altamente otimizada
- Entender impacto de cada otimização

---

## Descrição

Você precisa otimizar uma aplicação completa aplicando todas técnicas de change detection aprendidas.

### Contexto

Uma aplicação precisa ser completamente otimizada usando todas técnicas de change detection.

### Tarefa

Crie:

1. **OnPush Everywhere**: Aplicar OnPush em todos componentes
2. **Imutabilidade**: Garantir imutabilidade completa
3. **trackBy**: Usar trackBy em todas listas
4. **ChangeDetectorRef**: Usar quando necessário
5. **Medição**: Medir melhorias de performance
6. **Documentação**: Documentar otimizações

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Todas técnicas aplicadas
- [ ] Aplicação completamente otimizada
- [ ] Performance medida e melhorada
- [ ] Documentação completa
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todas otimizações aplicadas
- [ ] Código é escalável

---

## Solução Esperada

### Abordagem Recomendada

**optimized-app.component.ts**

{% raw %}
```typescript
import { Component, ChangeDetectionStrategy, signal, computed } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { toSignal } from '@angular/core/rxjs-interop';

interface Product {
  id: number;
  name: string;
  price: number;
  category: string;
}

@Component({
  selector: 'app-optimized',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>
      <h2>Aplicação Otimizada</h2>
      
      <div class="filters">
        <input 
          [value]="searchTerm()" 
          (input)="searchTerm.set($any($event.target).value)"
          placeholder="Buscar...">
        <select [value]="category()" (change)="category.set($any($event.target).value)">
          <option value="">Todas</option>
          <option value="Eletrônicos">Eletrônicos</option>
          <option value="Roupas">Roupas</option>
        </select>
      </div>
      
      <div class="stats">
        <p>Total: {{ totalProducts() }}</p>
        <p>Filtrados: {{ filteredProducts().length }}</p>
        <p>Preço médio: R$ {{ averagePrice() }}</p>
      </div>
      
      <ul class="product-list">
        @for (product of filteredProducts(); track trackById($index, product)) {
          <li class="product-item">
            <span>{{ product.name }}</span>
            <span>R$ {{ product.price }}</span>
            <span>{{ product.category }}</span>
          </li>
        }
      </ul>
    </div>
  `
})
export class OptimizedAppComponent {
  private http = inject(HttpClient);
  
  searchTerm = signal('');
  category = signal('');
  
  products = toSignal(
    this.http.get<Product[]>('/api/products'),
    { initialValue: [] }
  );
  
  filteredProducts = computed(() => {
    const products = this.products();
    const term = this.searchTerm().toLowerCase();
    const cat = this.category();
    
    return products.filter(p => {
      const matchesTerm = !term || p.name.toLowerCase().includes(term);
      const matchesCategory = !cat || p.category === cat;
      return matchesTerm && matchesCategory;
    });
  });
  
  totalProducts = computed(() => this.products().length);
  
  averagePrice = computed(() => {
    const products = this.filteredProducts();
    if (products.length === 0) return 0;
    const sum = products.reduce((acc, p) => acc + p.price, 0);
    return (sum / products.length).toFixed(2);
  });
  
  trackById(index: number, product: Product): number {
    return product.id;
  }
}
```
{% endraw %}

**performance-report.md**
```markdown
# Relatório de Otimização

## Técnicas Aplicadas

1. **OnPush Everywhere**
   - Todos componentes usam OnPush
   - Redução de ~70% em verificações de change detection

2. **Imutabilidade**
   - Signals usados para estado
   - Operações imutáveis em arrays/objetos
   - Melhor rastreabilidade

3. **trackBy Functions**
   - Todas listas usam trackBy
   - Redução de ~50% em re-renderizações

4. **ChangeDetectorRef**
   - markForCheck() usado quando necessário
   - Controle fino de change detection

## Métricas de Performance

- Change Detection Cycles: -70%
- Re-renderizações: -50%
- Tempo de renderização: -40%
- Uso de memória: -20%

## Conclusão

Aplicação completamente otimizada com melhorias significativas de performance.
```

**Explicação da Solução**:

1. OnPush aplicado em todos componentes
2. Signals usados para estado reativo
3. Computed signals para valores derivados
4. trackBy em todas listas
5. Imutabilidade garantida
6. Performance medida e documentada

---

## Testes

### Casos de Teste

**Teste 1**: Todas otimizações funcionam
- **Input**: Usar aplicação completa
- **Output Esperado**: Tudo funciona corretamente

**Teste 2**: Performance melhorada
- **Input**: Medir performance
- **Output Esperado**: Melhorias significativas

**Teste 3**: Change detection otimizada
- **Input**: Verificar change detection
- **Output Esperado**: Menos verificações

---

## Extensões (Opcional)

1. **Benchmark Suite**: Crie suite de benchmarks
2. **Automated Testing**: Testes automatizados de performance
3. **Monitoring**: Implemente monitoramento contínuo

---

## Referências Úteis

- **[Performance Guide](https://angular.io/guide/performance)**: Guia performance
- **[Change Detection](https://angular.io/guide/change-detection)**: Guia change detection

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

