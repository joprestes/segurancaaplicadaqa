---
layout: exercise
title: "Exercício 5.1.1: Testes Unitários Básicos"
slug: "testes-unitarios-basicos"
lesson_id: "lesson-5-1"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **testes unitários básicos** através da **criação de primeiros testes unitários para componente simples**.

Ao completar este exercício, você será capaz de:

- Configurar ambiente de testes
- Escrever testes básicos
- Usar AAA pattern (Arrange, Act, Assert)
- Entender estrutura de testes
- Executar testes

---

## Descrição

Você precisa criar testes unitários básicos para um componente de contador simples.

### Contexto

Uma aplicação precisa ter testes para garantir qualidade do código.

### Tarefa

Crie:

1. **Configuração**: Configurar Jest ou Vitest
2. **Componente**: Criar componente simples para testar
3. **Testes**: Escrever testes básicos
4. **Execução**: Executar testes

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Ambiente de testes configurado
- [ ] Componente criado
- [ ] Testes básicos escritos
- [ ] Testes executam com sucesso
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Testes estão bem estruturados
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**counter.component.ts**
```typescript
import { Component, signal } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-counter',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="counter">
      <h2>Contador</h2>
      <p>Valor: {{ count() }}</p>
      <button (click)="increment()">+</button>
      <button (click)="decrement()">-</button>
      <button (click)="reset()">Reset</button>
    </div>
  `
})
export class CounterComponent {
  count = signal(0);
  
  increment(): void {
    this.count.update(v => v + 1);
  }
  
  decrement(): void {
    this.count.update(v => v - 1);
  }
  
  reset(): void {
    this.count.set(0);
  }
}
```

**counter.component.spec.ts**
```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { CounterComponent } from './counter.component';

describe('CounterComponent', () => {
  let component: CounterComponent;
  let fixture: ComponentFixture<CounterComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CounterComponent]
    }).compileComponents();

    fixture = TestBed.createComponent(CounterComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should initialize with count 0', () => {
    expect(component.count()).toBe(0);
  });

  it('should increment count', () => {
    component.increment();
    expect(component.count()).toBe(1);
    
    component.increment();
    expect(component.count()).toBe(2);
  });

  it('should decrement count', () => {
    component.count.set(5);
    component.decrement();
    expect(component.count()).toBe(4);
  });

  it('should reset count to 0', () => {
    component.count.set(10);
    component.reset();
    expect(component.count()).toBe(0);
  });
});
```

**jest.config.js**
```javascript
module.exports = {
  preset: 'jest-preset-angular',
  setupFilesAfterEnv: ['<rootDir>/setup-jest.ts'],
  testMatch: ['**/*.spec.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.spec.ts',
    '!src/**/*.module.ts'
  ]
};
```

**Explicação da Solução**:

1. TestBed configurado para testes
2. Componente criado e testado
3. Testes seguem AAA pattern
4. Cada teste verifica um comportamento
5. Testes isolados e independentes
6. Código limpo e testável

---

## Testes

### Casos de Teste

**Teste 1**: Componente criado
- **Input**: Criar componente
- **Output Esperado**: Componente criado com sucesso

**Teste 2**: Increment funciona
- **Input**: Chamar increment()
- **Output Esperado**: Count incrementa

**Teste 3**: Decrement funciona
- **Input**: Chamar decrement()
- **Output Esperado**: Count decrementa

**Teste 4**: Reset funciona
- **Input**: Chamar reset()
- **Output Esperado**: Count volta para 0

---

## Extensões (Opcional)

1. **Mais Testes**: Adicione mais casos de teste
2. **Edge Cases**: Teste casos extremos
3. **Coverage**: Aumente cobertura de testes

---

## Referências Úteis

- **[Angular Testing](https://angular.io/guide/testing)**: Guia testes Angular
- **[Jest](https://jestjs.io/)**: Documentação Jest

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

