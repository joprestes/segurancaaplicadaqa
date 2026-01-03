---
layout: exercise
title: "Exercício 3.4.2: takeUntil Pattern"
slug: "takeuntil"
lesson_id: "lesson-3-4"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **takeUntil Pattern** através da **implementação de componente que gerencia múltiplas subscriptions**.

Ao completar este exercício, você será capaz de:

- Criar Subject para cleanup
- Usar takeUntil em múltiplas subscriptions
- Implementar ngOnDestroy corretamente
- Gerenciar múltiplas subscriptions de forma segura
- Prevenir memory leaks com takeUntil

---

## Descrição

Você precisa criar um componente que gerencia múltiplas subscriptions usando takeUntil pattern.

### Contexto

Uma aplicação precisa subscrever a múltiplos Observables e garantir cleanup adequado.

### Tarefa

Crie:

1. **Subject**: Criar destroy$ Subject
2. **Subscriptions**: Múltiplas subscriptions com takeUntil
3. **Cleanup**: Implementar ngOnDestroy
4. **Component**: Componente completo e funcional

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] destroy$ Subject criado
- [ ] Múltiplas subscriptions usam takeUntil
- [ ] ngOnDestroy implementado
- [ ] Cleanup funciona corretamente
- [ ] Memory leaks prevenidos
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] takeUntil pattern está implementado corretamente
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**dashboard.component.ts**
```typescript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subject } from 'rxjs';
import { takeUntil, finalize } from 'rxjs/operators';
import { UserService } from './user.service';
import { ProductService } from './product.service';
import { OrderService } from './order.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div>
      <h2>Dashboard</h2>
      
      <div class="stats">
        <div>
          <h3>Usuários</h3>
          <p>{{ userCount }}</p>
        </div>
        <div>
          <h3>Produtos</h3>
          <p>{{ productCount }}</p>
        </div>
        <div>
          <h3>Pedidos</h3>
          <p>{{ orderCount }}</p>
        </div>
      </div>
      
      <button (click)="refresh()">Atualizar</button>
    </div>
  `,
  styles: [`
    .stats {
      display: flex;
      gap: 2rem;
      margin: 2rem 0;
    }
  `]
})
export class DashboardComponent implements OnInit, OnDestroy {
  userCount = 0;
  productCount = 0;
  orderCount = 0;
  
  private destroy$ = new Subject<void>();
  
  constructor(
    private userService: UserService,
    private productService: ProductService,
    private orderService: OrderService
  ) {}
  
  ngOnInit(): void {
    this.loadData();
  }
  
  loadData(): void {
    this.userService.getUsers()
      .pipe(
        takeUntil(this.destroy$),
        finalize(() => console.log('User subscription completed'))
      )
      .subscribe(users => {
        this.userCount = users.length;
      });
    
    this.productService.getProducts()
      .pipe(
        takeUntil(this.destroy$),
        finalize(() => console.log('Product subscription completed'))
      )
      .subscribe(products => {
        this.productCount = products.length;
      });
    
    this.orderService.getOrders()
      .pipe(
        takeUntil(this.destroy$),
        finalize(() => console.log('Order subscription completed'))
      )
      .subscribe(orders => {
        this.orderCount = orders.length;
      });
  }
  
  refresh(): void {
    this.loadData();
  }
  
  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
    console.log('Component destroyed, all subscriptions cleaned');
  }
}
```

**Explicação da Solução**:

1. destroy$ Subject criado como propriedade privada
2. Todas subscriptions usam takeUntil(this.destroy$)
3. ngOnDestroy completa destroy$ Subject
4. finalize operator para logging (opcional)
5. Todas subscriptions são desinscritas automaticamente
6. Memory leaks prevenidos

---

## Testes

### Casos de Teste

**Teste 1**: Subscriptions funcionam
- **Input**: Carregar componente
- **Output Esperado**: Dados carregados e exibidos

**Teste 2**: Cleanup funciona
- **Input**: Destruir componente
- **Output Esperado**: Todas subscriptions desinscritas

**Teste 3**: Memory leak prevenido
- **Input**: Criar e destruir múltiplas vezes
- **Output Esperado**: Sem memory leaks

---

## Extensões (Opcional)

1. **Error Handling**: Adicione tratamento de erros
2. **Loading States**: Adicione estados de loading
3. **Retry Logic**: Adicione lógica de retry

---

## Referências Úteis

- **[takeUntil](https://rxjs.dev/api/operators/takeUntil)**: Documentação takeUntil
- **[Subject](https://rxjs.dev/api/index/class/Subject)**: Documentação Subject

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

