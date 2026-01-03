---
layout: exercise
title: "Exercício 1.5.5: Componente Completo com Control Flow e Pipes"
slug: "componente-completo"
lesson_id: "lesson-1-5"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **todas as técnicas de Control Flow e Pipes** através da **criação de um componente completo de transações financeiras**.

Ao completar este exercício, você será capaz de:

- Combinar @if, @for, @switch em um componente
- Usar pipes embutidos e customizados juntos
- Criar componente real e funcional
- Aplicar todas as técnicas aprendidas

---

## Descrição

Você precisa criar um componente `TransactionListComponent` que exibe uma lista de transações financeiras usando Control Flow completo e múltiplos pipes para formatação de dados.

### Contexto

Um sistema bancário precisa exibir transações financeiras com formatação adequada e filtros. O componente deve demonstrar uso completo de Control Flow e Pipes.

### Tarefa

Crie um componente `TransactionListComponent` com:

1. **Lista de Transações**: Array com id, descrição, valor, data, tipo, categoria
2. **@for**: Renderizar transações com track
3. **@if/@else**: Mostrar diferentes estados
4. **@switch**: Exibir ícones baseado em tipo
5. **Pipes Embutidos**: CurrencyPipe, DatePipe, PercentPipe
6. **Pipes Customizados**: Criar pipe para formatação de tipo
7. **Filtros**: Filtrar por tipo, categoria, período
8. **Estatísticas**: Resumo com totais formatados

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente completo e funcional
- [ ] @for usado para lista
- [ ] @if/@else usado para estados
- [ ] @switch usado para tipos
- [ ] Pipes embutidos aplicados
- [ ] Pipes customizados criados e usados
- [ ] Filtros funcionais
- [ ] Estatísticas calculadas e formatadas

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todas as técnicas são aplicadas corretamente
- [ ] Componente é útil e realista
- [ ] Código é bem organizado

---

## Solução Esperada

### Abordagem Recomendada

**transaction-type.pipe.ts**
```typescript
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'transactionType',
  standalone: true
})
export class TransactionTypePipe implements PipeTransform {
  transform(type: 'income' | 'expense' | 'transfer'): string {
    const types: {[key: string]: string} = {
      'income': 'Receita',
      'expense': 'Despesa',
      'transfer': 'Transferência'
    };
    return types[type] || type;
  }
}
```

**transaction-list.component.ts**
```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { TransactionTypePipe } from './transaction-type.pipe';

interface Transaction {
  id: number;
  description: string;
  amount: number;
  date: Date;
  type: 'income' | 'expense' | 'transfer';
  category: string;
}

@Component({
  selector: 'app-transaction-list',
  standalone: true,
  imports: [CommonModule, FormsModule, TransactionTypePipe],
  templateUrl: './transaction-list.component.html',
  styleUrls: ['./transaction-list.component.css']
})
export class TransactionListComponent implements OnInit {
  transactions: Transaction[] = [
    {
      id: 1,
      description: 'Salário',
      amount: 5000,
      date: new Date('2024-01-01'),
      type: 'income',
      category: 'Trabalho'
    },
    {
      id: 2,
      description: 'Supermercado',
      amount: -350.50,
      date: new Date('2024-01-05'),
      type: 'expense',
      category: 'Alimentação'
    },
    {
      id: 3,
      description: 'Transferência para Poupança',
      amount: -1000,
      date: new Date('2024-01-10'),
      type: 'transfer',
      category: 'Investimentos'
    }
  ];
  
  filteredTransactions: Transaction[] = [];
  filterType: string = 'all';
  filterCategory: string = 'all';
  searchTerm: string = '';
  
  ngOnInit(): void {
    this.applyFilters();
  }
  
  applyFilters(): void {
    let filtered = [...this.transactions];
    
    if (this.filterType !== 'all') {
      filtered = filtered.filter(t => t.type === this.filterType);
    }
    
    if (this.filterCategory !== 'all') {
      filtered = filtered.filter(t => t.category === this.filterCategory);
    }
    
    if (this.searchTerm) {
      filtered = filtered.filter(t => 
        t.description.toLowerCase().includes(this.searchTerm.toLowerCase())
      );
    }
    
    this.filteredTransactions = filtered;
  }
  
  getTotalIncome(): number {
    return this.filteredTransactions
      .filter(t => t.type === 'income')
      .reduce((sum, t) => sum + Math.abs(t.amount), 0);
  }
  
  getTotalExpenses(): number {
    return this.filteredTransactions
      .filter(t => t.type === 'expense')
      .reduce((sum, t) => sum + Math.abs(t.amount), 0);
  }
  
  getBalance(): number {
    return this.getTotalIncome() - this.getTotalExpenses();
  }
  
  getCategories(): string[] {
    return [...new Set(this.transactions.map(t => t.category))];
  }
}
```

**transaction-list.component.html**
{% raw %}
```html
<div class="transaction-list">
  <h2>Transações Financeiras</h2>
  
  <div class="filters">
    <input 
      type="text" 
      [(ngModel)]="searchTerm"
      (input)="applyFilters()"
      placeholder="Buscar transações...">
    
    <select [(ngModel)]="filterType" (change)="applyFilters()">
      <option value="all">Todos os tipos</option>
      <option value="income">Receitas</option>
      <option value="expense">Despesas</option>
      <option value="transfer">Transferências</option>
    </select>
    
    <select [(ngModel)]="filterCategory" (change)="applyFilters()">
      <option value="all">Todas as categorias</option>
      @for (category of getCategories(); track category) {
        <option [value]="category">{{ category }}</option>
      }
    </select>
  </div>
  
  <div class="summary">
    <div class="summary-item">
      <span class="label">Receitas:</span>
      <span class="value income">{{ getTotalIncome() | currency:'BRL':'symbol':'1.2-2' }}</span>
    </div>
    <div class="summary-item">
      <span class="label">Despesas:</span>
      <span class="value expense">{{ getTotalExpenses() | currency:'BRL':'symbol':'1.2-2' }}</span>
    </div>
    <div class="summary-item">
      <span class="label">Saldo:</span>
      <span class="value" [class.positive]="getBalance() >= 0" [class.negative]="getBalance() < 0">
        {{ getBalance() | currency:'BRL':'symbol':'1.2-2' }}
      </span>
    </div>
  </div>
  
  @if (filteredTransactions.length === 0) {
    <div class="empty-state">
      <p>Nenhuma transação encontrada</p>
    </div>
  } @else {
    <div class="transactions">
      @for (transaction of filteredTransactions; track transaction.id) {
        <div class="transaction-card" [class.income]="transaction.type === 'income'" 
             [class.expense]="transaction.type === 'expense'"
             [class.transfer]="transaction.type === 'transfer'">
          <div class="transaction-header">
            <h3>{{ transaction.description }}</h3>
            <span class="amount" [class.positive]="transaction.amount > 0" 
                  [class.negative]="transaction.amount < 0">
              {{ transaction.amount | currency:'BRL':'symbol':'1.2-2' }}
            </span>
          </div>
          
          <div class="transaction-details">
            <div class="detail-item">
              <span class="label">Tipo:</span>
              <span class="type-badge">
                @switch (transaction.type) {
                  @case ('income') {
                    <span class="badge income">💰 {{ transaction.type | transactionType }}</span>
                  }
                  @case ('expense') {
                    <span class="badge expense">💸 {{ transaction.type | transactionType }}</span>
                  }
                  @default {
                    <span class="badge transfer">🔄 {{ transaction.type | transactionType }}</span>
                  }
                }
              </span>
            </div>
            
            <div class="detail-item">
              <span class="label">Categoria:</span>
              <span>{{ transaction.category }}</span>
            </div>
            
            <div class="detail-item">
              <span class="label">Data:</span>
              <span>{{ transaction.date | date:'dd/MM/yyyy' }}</span>
            </div>
            
            <div class="detail-item">
              <span class="label">Hora:</span>
              <span>{{ transaction.date | date:'HH:mm' }}</span>
            </div>
          </div>
        </div>
      }
    </div>
  }
  
  <div class="statistics">
    <h3>Estatísticas</h3>
    <div class="stats-grid">
      <div class="stat-card">
        <span class="stat-label">Total de Transações</span>
        <span class="stat-value">{{ filteredTransactions.length }}</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">Média de Receitas</span>
        <span class="stat-value">
          {{ getTotalIncome() / (filteredTransactions.filter(t => t.type === 'income').length || 1) | currency:'BRL' }}
        </span>
      </div>
      <div class="stat-card">
        <span class="stat-label">Média de Despesas</span>
        <span class="stat-value">
          {{ getTotalExpenses() / (filteredTransactions.filter(t => t.type === 'expense').length || 1) | currency:'BRL' }}
        </span>
      </div>
    </div>
  </div>
</div>
```
{% endraw %}

**transaction-list.component.css**
```css
.transaction-list {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem;
}

.filters {
  display: flex;
  gap: 1rem;
  margin-bottom: 2rem;
  flex-wrap: wrap;
}

.filters input, .filters select {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.summary {
  display: flex;
  gap: 2rem;
  margin-bottom: 2rem;
  padding: 1.5rem;
  background-color: #f5f5f5;
  border-radius: 8px;
}

.summary-item {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.summary-item .value {
  font-size: 1.5rem;
  font-weight: bold;
}

.value.income {
  color: #4caf50;
}

.value.expense {
  color: #f44336;
}

.value.positive {
  color: #4caf50;
}

.value.negative {
  color: #f44336;
}

.transactions {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  margin-bottom: 2rem;
}

.transaction-card {
  padding: 1.5rem;
  border-left: 4px solid #ddd;
  border-radius: 4px;
  background-color: white;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.transaction-card.income {
  border-left-color: #4caf50;
}

.transaction-card.expense {
  border-left-color: #f44336;
}

.transaction-card.transfer {
  border-left-color: #2196f3;
}

.transaction-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.amount {
  font-size: 1.25rem;
  font-weight: bold;
}

.transaction-details {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 0.5rem;
}

.badge {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.875rem;
}

.badge.income {
  background-color: #e8f5e9;
  color: #2e7d32;
}

.badge.expense {
  background-color: #ffebee;
  color: #c62828;
}

.badge.transfer {
  background-color: #e3f2fd;
  color: #1565c0;
}

.statistics {
  margin-top: 2rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.stat-card {
  padding: 1rem;
  background-color: #f9f9f9;
  border-radius: 4px;
  text-align: center;
}

.stat-value {
  display: block;
  font-size: 1.5rem;
  font-weight: bold;
  margin-top: 0.5rem;
}
```

**Explicação da Solução**:

1. Pipe customizado `TransactionTypePipe` para tipos
2. `@for` com track para lista de transações
3. `@if/@else` para estado vazio
4. `@switch` para ícones de tipo
5. Pipes embutidos: CurrencyPipe, DatePipe
6. Filtros funcionais
7. Estatísticas calculadas e formatadas
8. Componente completo e realista

---

## Testes

### Casos de Teste

**Teste 1**: Lista renderiza corretamente
- **Input**: Componente carregado
- **Output Esperado**: Todas as transações devem aparecer

**Teste 2**: Filtros funcionam
- **Input**: Selecionar filtros
- **Output Esperado**: Lista deve filtrar corretamente

**Teste 3**: Estatísticas corretas
- **Input**: Transações filtradas
- **Output Esperado**: Totais devem estar corretos

**Teste 4**: Pipes formatam corretamente
- **Input**: Valores e datas
- **Output Esperado**: Formatação brasileira aplicada

---

## Extensões (Opcional)

1. **Exportar CSV**: Adicione funcionalidade para exportar transações
2. **Gráficos**: Adicione gráficos de receitas vs despesas
3. **Agrupamento**: Agrupe transações por mês
4. **Validação**: Adicione validação de dados

---

## Referências Úteis

- **[Control Flow](https://angular.io/guide/control-flow)**: Guia completo
- **[Pipes](https://angular.io/guide/pipes)**: Guia de pipes
- **[All Built-in Pipes](https://angular.io/api/common#pipes)**: Lista completa

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

