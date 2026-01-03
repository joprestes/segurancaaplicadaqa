---
layout: exercise
title: "Exercício 3.2.2: effect() e Reatividade"
slug: "effect"
lesson_id: "lesson-3-2"
module: "module-3"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **effect()** através da **implementação de sincronização de estado com localStorage**.

Ao completar este exercício, você será capaz de:

- Usar effect() para side effects
- Sincronizar signals com localStorage
- Entender quando usar effect()
- Evitar loops infinitos
- Gerenciar lifecycle de effects

---

## Descrição

Você precisa criar um componente que sincroniza estado com localStorage usando effect().

### Contexto

Uma aplicação precisa persistir estado do usuário localmente e restaurar ao recarregar.

### Tarefa

Crie:

1. **Signals**: Criar signals para estado
2. **effect()**: Sincronizar com localStorage
3. **Restauração**: Restaurar estado ao inicializar
4. **Componente**: Componente funcional completo

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Signals criados para estado
- [ ] effect() implementado para sincronização
- [ ] Estado persiste no localStorage
- [ ] Estado restaurado ao inicializar
- [ ] Effect não causa loops infinitos
- [ ] Código funcional

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Effect está bem implementado
- [ ] Código é legível

---

## Solução Esperada

### Abordagem Recomendada

**preferences-signal.component.ts**
```typescript
import { Component, signal, effect, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-preferences-signal',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div>
      <h2>Preferências do Usuário</h2>
      
      <div class="preference">
        <label>
          Tema:
          <select [value]="theme()" (change)="theme.set($any($event.target).value)">
            <option value="light">Claro</option>
            <option value="dark">Escuro</option>
          </select>
        </label>
      </div>
      
      <div class="preference">
        <label>
          Idioma:
          <select [value]="language()" (change)="language.set($any($event.target).value)">
            <option value="pt">Português</option>
            <option value="en">English</option>
            <option value="es">Español</option>
          </select>
        </label>
      </div>
      
      <div class="preference">
        <label>
          Tamanho da Fonte:
          <input 
            type="range" 
            [value]="fontSize()" 
            (input)="fontSize.set(+$any($event.target).value)"
            min="12" 
            max="24">
          <span>{{ fontSize() }}px</span>
        </label>
      </div>
      
      <div class="preference">
        <label>
          Notificações:
          <input 
            type="checkbox" 
            [checked]="notifications()"
            (change)="notifications.set($any($event.target).checked)">
        </label>
      </div>
      
      <button (click)="reset()">Resetar Preferências</button>
      
      <div class="preview">
        <h3>Preview</h3>
        <p [style.font-size.px]="fontSize()">
          Texto de exemplo com tema {{ theme() }} e idioma {{ language() }}
        </p>
      </div>
    </div>
  `,
  styles: [`
    .preference {
      margin-bottom: 1rem;
    }
    
    .preference label {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    
    .preview {
      margin-top: 2rem;
      padding: 1rem;
      border: 1px solid #ccc;
      border-radius: 4px;
    }
  `]
})
export class PreferencesSignalComponent implements OnInit {
  theme = signal<'light' | 'dark'>('light');
  language = signal<'pt' | 'en' | 'es'>('pt');
  fontSize = signal<number>(16);
  notifications = signal<boolean>(true);
  
  constructor() {
    effect(() => {
      const preferences = {
        theme: this.theme(),
        language: this.language(),
        fontSize: this.fontSize(),
        notifications: this.notifications()
      };
      
      localStorage.setItem('preferences', JSON.stringify(preferences));
      console.log('Preferences saved:', preferences);
      
      document.body.className = this.theme();
      document.documentElement.style.fontSize = `${this.fontSize()}px`;
    });
  }
  
  ngOnInit(): void {
    const saved = localStorage.getItem('preferences');
    if (saved) {
      try {
        const preferences = JSON.parse(saved);
        this.theme.set(preferences.theme || 'light');
        this.language.set(preferences.language || 'pt');
        this.fontSize.set(preferences.fontSize || 16);
        this.notifications.set(preferences.notifications !== undefined ? preferences.notifications : true);
      } catch (error) {
        console.error('Error loading preferences:', error);
      }
    }
  }
  
  reset(): void {
    this.theme.set('light');
    this.language.set('pt');
    this.fontSize.set(16);
    this.notifications.set(true);
  }
}
```

**Explicação da Solução**:

1. Signals criados para cada preferência
2. effect() sincroniza com localStorage
3. effect() também aplica mudanças ao DOM
4. Estado restaurado no ngOnInit
5. Reset restaura valores padrão
6. Effect executa automaticamente quando signals mudam

---

## Testes

### Casos de Teste

**Teste 1**: Effect sincroniza
- **Input**: Mudar preferências
- **Output Esperado**: Valores salvos no localStorage

**Teste 2**: Estado restaurado
- **Input**: Recarregar página
- **Output Esperado**: Preferências restauradas

**Teste 3**: DOM atualizado
- **Input**: Mudar tema ou tamanho da fonte
- **Output Esperado**: DOM atualizado automaticamente

---

## Extensões (Opcional)

1. **Debounce**: Adicione debounce ao effect
2. **Sync**: Sincronize com servidor
3. **Validation**: Adicione validação de preferências

---

## Referências Úteis

- **[effect()](https://angular.io/api/core/effect)**: Documentação effect()
- **[Signals Guide](https://angular.io/guide/signals)**: Guia completo Signals

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

