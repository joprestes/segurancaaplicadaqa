---
layout: exercise
title: "Exercício 5.1.3: Testes de Componentes"
slug: "testes-componentes"
lesson_id: "lesson-5-1"
module: "module-5"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **testes de componentes** através da **criação de testes completos para componente com inputs, outputs e interações**.

Ao completar este exercício, você será capaz de:

- Testar componentes com @Input()
- Testar componentes com @Output()
- Testar interações do usuário
- Verificar renderização do template
- Testar change detection

---

## Descrição

Você precisa criar testes completos para um componente de tarefa que tem inputs, outputs e interações.

### Contexto

Uma aplicação precisa testar componentes que recebem dados e emitem eventos.

### Tarefa

Crie:

1. **Componente**: Criar componente com Input/Output
2. **Testes Input**: Testar @Input()
3. **Testes Output**: Testar @Output()
4. **Testes Interação**: Testar cliques e eventos
5. **Testes Template**: Verificar renderização

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente criado
- [ ] Testes de Input escritos
- [ ] Testes de Output escritos
- [ ] Testes de interação escritos
- [ ] Testes de template escritos
- [ ] Todos testes passam

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Testes estão completos
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**task.component.ts**
```typescript
import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';

export interface Task {
  id: number;
  title: string;
  completed: boolean;
}

@Component({
  selector: 'app-task',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="task" [class.completed]="task.completed">
      <input 
        type="checkbox" 
        [checked]="task.completed"
        (change)="onToggle()"
        data-cy="task-checkbox">
      <span class="task-title">{{ task.title }}</span>
      <button 
        (click)="onDelete()"
        data-cy="delete-button">
        Deletar
      </button>
    </div>
  `,
  styles: [`
    .task {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 1rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      margin-bottom: 0.5rem;
    }
    
    .task.completed {
      opacity: 0.6;
      text-decoration: line-through;
    }
  `]
})
export class TaskComponent {
  @Input({ required: true }) task!: Task;
  @Output() toggle = new EventEmitter<number>();
  @Output() delete = new EventEmitter<number>();
  
  onToggle(): void {
    this.toggle.emit(this.task.id);
  }
  
  onDelete(): void {
    this.delete.emit(this.task.id);
  }
}
```

**task.component.spec.ts**
```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { TaskComponent, Task } from './task.component';
import { By } from '@angular/platform-browser';

describe('TaskComponent', () => {
  let component: TaskComponent;
  let fixture: ComponentFixture<TaskComponent>;
  let mockTask: Task;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TaskComponent]
    }).compileComponents();

    fixture = TestBed.createComponent(TaskComponent);
    component = fixture.componentInstance;
    
    mockTask = {
      id: 1,
      title: 'Test Task',
      completed: false
    };
    
    component.task = mockTask;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display task title', () => {
    const titleElement = fixture.debugElement.query(By.css('.task-title'));
    expect(titleElement.nativeElement.textContent).toContain('Test Task');
  });

  it('should apply completed class when task is completed', () => {
    component.task = { ...mockTask, completed: true };
    fixture.detectChanges();
    
    const taskElement = fixture.debugElement.query(By.css('.task'));
    expect(taskElement.nativeElement.classList).toContain('completed');
  });

  it('should check checkbox when task is completed', () => {
    component.task = { ...mockTask, completed: true };
    fixture.detectChanges();
    
    const checkbox = fixture.debugElement.query(By.css('input[type="checkbox"]'));
    expect(checkbox.nativeElement.checked).toBe(true);
  });

  it('should emit toggle event when checkbox is clicked', () => {
    spyOn(component.toggle, 'emit');
    
    const checkbox = fixture.debugElement.query(By.css('input[type="checkbox"]'));
    checkbox.nativeElement.click();
    
    expect(component.toggle.emit).toHaveBeenCalledWith(1);
  });

  it('should emit delete event when delete button is clicked', () => {
    spyOn(component.delete, 'emit');
    
    const deleteButton = fixture.debugElement.query(By.css('button'));
    deleteButton.nativeElement.click();
    
    expect(component.delete.emit).toHaveBeenCalledWith(1);
  });

  it('should update when task input changes', () => {
    component.task = { id: 2, title: 'Updated Task', completed: false };
    fixture.detectChanges();
    
    const titleElement = fixture.debugElement.query(By.css('.task-title'));
    expect(titleElement.nativeElement.textContent).toContain('Updated Task');
  });
});
```

**Explicação da Solução**:

1. Componente criado com Input e Output
2. Testes verificam renderização de Input
3. Testes verificam emissão de Output
4. Testes verificam interações do usuário
5. Testes verificam mudanças de estado
6. Cobertura completa do componente

---

## Testes

### Casos de Teste

**Teste 1**: Input funciona
- **Input**: Definir task via @Input()
- **Output Esperado**: Dados exibidos corretamente

**Teste 2**: Output funciona
- **Input**: Clicar em checkbox ou botão
- **Output Esperado**: Eventos emitidos

**Teste 3**: Template renderiza
- **Input**: Mudar task
- **Output Esperado**: Template atualizado

---

## Extensões (Opcional)

1. **Form Testing**: Teste formulários em componentes
2. **Router Testing**: Teste navegação
3. **Animation Testing**: Teste animações

---

## Referências Úteis

- **[Component Testing](https://angular.io/guide/testing-components)**: Guia testes de componentes
- **[By](https://angular.io/api/platform-browser/By)**: Documentação By

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

