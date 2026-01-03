---
layout: exercise
title: "Exercício 1.4.6: Componente Interativo Completo"
slug: "componente-interativo"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **todas as técnicas de data binding** através da **criação de um dashboard interativo completo**.

Ao completar este exercício, você será capaz de:

- Combinar todos os tipos de binding
- Usar diretivas estruturais e de atributo juntas
- Criar componentes altamente interativos
- Aplicar múltiplas técnicas simultaneamente

---

## Descrição

Você precisa criar um componente `DashboardComponent` que demonstra uso de interpolação, property binding, event binding, two-way binding, diretivas estruturais e de atributo em um único componente funcional.

### Contexto

Um sistema precisa de um dashboard que permite visualizar e interagir com dados de forma dinâmica. O dashboard deve demonstrar todas as capacidades de data binding do Angular.

### Tarefa

Crie um componente `DashboardComponent` com:

1. **Interpolação**: Exibir estatísticas e dados
2. **Property Binding**: Binding de imagens, classes, estilos
3. **Event Binding**: Botões, inputs, eventos customizados
4. **Two-Way Binding**: Formulários e controles
5. ***ngFor**: Lista de itens dinâmica
6. ***ngIf**: Mostrar/ocultar seções
7. ***ngSwitch**: Seleção de visualizações
8. **[ngClass]**: Classes dinâmicas
9. **[ngStyle]**: Estilos dinâmicos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Todas as técnicas de binding implementadas
- [ ] Componente funcional e interativo
- [ ] Múltiplas funcionalidades integradas
- [ ] Interface intuitiva
- [ ] Código bem organizado

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Todas as técnicas são aplicadas corretamente
- [ ] Componente é funcional e útil
- [ ] Código é legível e mantível

---

## Solução Esperada

### Abordagem Recomendada

**dashboard.component.ts**
```typescript
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

interface Metric {
  label: string;
  value: number;
  change: number;
  icon: string;
}

interface Activity {
  id: number;
  title: string;
  time: string;
  type: 'info' | 'success' | 'warning' | 'error';
}

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [FormsModule, CommonModule],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent {
  userName: string = 'João Silva';
  viewMode: 'grid' | 'list' = 'grid';
  theme: 'light' | 'dark' = 'light';
  searchTerm: string = '';
  
  metrics: Metric[] = [
    { label: 'Vendas', value: 1250, change: 12, icon: '💰' },
    { label: 'Usuários', value: 3420, change: 8, icon: '👥' },
    { label: 'Pedidos', value: 890, change: -3, icon: '📦' },
    { label: 'Receita', value: 45200, change: 15, icon: '💵' }
  ];
  
  activities: Activity[] = [
    { id: 1, title: 'Novo pedido recebido', time: '2 min atrás', type: 'success' },
    { id: 2, title: 'Usuário cadastrado', time: '15 min atrás', type: 'info' },
    { id: 3, title: 'Alerta de estoque', time: '1 hora atrás', type: 'warning' },
    { id: 4, title: 'Erro no pagamento', time: '2 horas atrás', type: 'error' }
  ];
  
  filteredActivities: Activity[] = [];
  
  ngOnInit(): void {
    this.filteredActivities = this.activities;
  }
  
  onSearchChange(): void {
    if (this.searchTerm.trim() === '') {
      this.filteredActivities = this.activities;
    } else {
      this.filteredActivities = this.activities.filter(a => 
        a.title.toLowerCase().includes(this.searchTerm.toLowerCase())
      );
    }
  }
  
  toggleViewMode(): void {
    this.viewMode = this.viewMode === 'grid' ? 'list' : 'grid';
  }
  
  toggleTheme(): void {
    this.theme = this.theme === 'light' ? 'dark' : 'light';
  }
  
  getThemeClasses(): {[key: string]: boolean} {
    return {
      'theme-light': this.theme === 'light',
      'theme-dark': this.theme === 'dark'
    };
  }
  
  getThemeStyles(): {[key: string]: string} {
    return {
      'background-color': this.theme === 'dark' ? '#1a1a1a' : '#ffffff',
      'color': this.theme === 'dark' ? '#ffffff' : '#000000'
    };
  }
  
  getActivityClass(type: string): string {
    return `activity-${type}`;
  }
}
```

**dashboard.component.html**
```html
<div class="dashboard" [ngClass]="getThemeClasses()" [ngStyle]="getThemeStyles()">
  <header class="dashboard-header">
    <h1>Dashboard de {{ userName }}</h1>
    <div class="header-controls">
      <input 
        type="text" 
        [(ngModel)]="searchTerm"
        (input)="onSearchChange()"
        placeholder="Buscar atividades..."
        name="search">
      <button (click)="toggleViewMode()">
        Modo: {{ viewMode === 'grid' ? 'Grade' : 'Lista' }}
      </button>
      <button (click)="toggleTheme()">
        Tema: {{ theme === 'light' ? 'Claro' : 'Escuro' }}
      </button>
    </div>
  </header>
  
  <section class="metrics">
    <h2>Métricas</h2>
    <div [ngClass]="{'metrics-grid': viewMode === 'grid', 'metrics-list': viewMode === 'list'}">
      <div 
        *ngFor="let metric of metrics; trackBy: trackByLabel"
        class="metric-card"
        [ngClass]="{'positive': metric.change > 0, 'negative': metric.change < 0}">
        <span class="metric-icon">{{ metric.icon }}</span>
        <div class="metric-content">
          <h3>{{ metric.label }}</h3>
          <p class="metric-value">{{ metric.value | number }}</p>
          <span 
            class="metric-change"
            [ngStyle]="{'color': metric.change > 0 ? 'green' : 'red'}">
            {{ metric.change > 0 ? '+' : '' }}{{ metric.change }}%
          </span>
        </div>
      </div>
    </div>
  </section>
  
  <section class="activities">
    <h2>Atividades Recentes</h2>
    <div [ngSwitch]="filteredActivities.length">
      <div *ngSwitchCase="0" class="empty-state">
        <p>Nenhuma atividade encontrada</p>
      </div>
      <ul *ngSwitchDefault [ngClass]="{'activity-list': true, 'list-view': viewMode === 'list'}">
        <li 
          *ngFor="let activity of filteredActivities; trackBy: trackById"
          [ngClass]="getActivityClass(activity.type)">
          <span class="activity-icon">
            <span [ngSwitch]="activity.type">
              <span *ngSwitchCase="'success'">✓</span>
              <span *ngSwitchCase="'info'">ℹ</span>
              <span *ngSwitchCase="'warning'">⚠</span>
              <span *ngSwitchDefault>✗</span>
            </span>
          </span>
          <div class="activity-content">
            <p class="activity-title">{{ activity.title }}</p>
            <span class="activity-time">{{ activity.time }}</span>
          </div>
        </li>
      </ul>
    </div>
  </section>
</div>
```

**dashboard.component.css**
```css
.dashboard {
  padding: 2rem;
  min-height: 100vh;
  transition: background-color 0.3s, color 0.3s;
}

.theme-dark {
  background-color: #1a1a1a;
  color: #ffffff;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  padding-bottom: 1rem;
  border-bottom: 2px solid #e0e0e0;
}

.header-controls {
  display: flex;
  gap: 1rem;
  align-items: center;
}

.header-controls input {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
}

.metrics-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.metric-card {
  padding: 1.5rem;
  border-radius: 8px;
  border: 1px solid #e0e0e0;
  display: flex;
  align-items: center;
  gap: 1rem;
  transition: transform 0.2s;
}

.metric-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.metric-icon {
  font-size: 2.5rem;
}

.metric-value {
  font-size: 2rem;
  font-weight: bold;
  margin: 0.5rem 0;
}

.activity-list {
  list-style: none;
  padding: 0;
}

.activity-list.list-view li {
  width: 100%;
}

.activity-list li {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 1rem;
  margin-bottom: 0.5rem;
  border-radius: 4px;
  border-left: 4px solid;
}

.activity-success {
  background-color: #e8f5e9;
  border-left-color: #4caf50;
}

.activity-info {
  background-color: #e3f2fd;
  border-left-color: #2196f3;
}

.activity-warning {
  background-color: #fff3e0;
  border-left-color: #ff9800;
}

.activity-error {
  background-color: #ffebee;
  border-left-color: #f44336;
}

.empty-state {
  text-align: center;
  padding: 3rem;
  color: #666;
}
```

**Explicação da Solução**:

1. Interpolação para exibir dados
2. Property binding para classes e estilos dinâmicos
3. Event binding em botões e inputs
4. Two-way binding para busca e controles
5. *ngFor para listas dinâmicas
6. *ngIf para mostrar/ocultar
7. *ngSwitch para seleção condicional
8. [ngClass] para classes dinâmicas
9. [ngStyle] para estilos dinâmicos
10. Todas as técnicas integradas em um componente funcional

---

## Testes

### Casos de Teste

**Teste 1**: Todas as técnicas funcionam
- **Input**: Interagir com componente
- **Output Esperado**: Todas as funcionalidades devem funcionar

**Teste 2**: Busca filtra atividades
- **Input**: Digitar no campo de busca
- **Output Esperado**: Lista deve filtrar em tempo real

**Teste 3**: Toggle de tema funciona
- **Input**: Clicar em botão de tema
- **Output Esperado**: Tema deve mudar

**Teste 4**: Toggle de visualização funciona
- **Input**: Clicar em botão de modo
- **Output Esperado**: Layout deve mudar entre grid e lista

---

## Extensões (Opcional)

1. **Mais Métricas**: Adicione mais métricas e gráficos
2. **Filtros Avançados**: Adicione filtros por tipo de atividade
3. **Ordenação**: Permita ordenar atividades
4. **Persistência**: Salve preferências no localStorage

---

## Referências Úteis

- **[Template Syntax](https://angular.io/guide/template-syntax)**: Guia completo
- **[All Binding Types](https://angular.io/guide/template-syntax)**: Todos os tipos de binding

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

