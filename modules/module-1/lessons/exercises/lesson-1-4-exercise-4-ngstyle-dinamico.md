---
layout: exercise
title: "Exercício 1.4.4: Estilos Dinâmicos com ngStyle"
slug: "ngstyle-dinamico"
lesson_id: "lesson-1-4"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **ngStyle** através da **criação de um seletor de cores que aplica estilos dinamicamente**.

Ao completar este exercício, você será capaz de:

- Usar `[ngStyle]` com objetos
- Aplicar estilos inline dinamicamente
- Criar interfaces visuais dinâmicas
- Combinar múltiplos estilos

---

## Descrição

Você precisa criar um componente `ColorPickerComponent` que permite escolher cor de fundo, cor de texto e tamanho da fonte, aplicando estilos dinamicamente usando `[ngStyle]`.

### Contexto

Um editor de texto precisa de um seletor de cores para personalizar aparência. O componente deve aplicar estilos em tempo real conforme o usuário seleciona opções.

### Tarefa

Crie um componente `ColorPickerComponent` com:

1. **Seletor de Cor de Fundo**: Input color para escolher cor de fundo
2. **Seletor de Cor de Texto**: Input color para escolher cor de texto
3. **Slider de Tamanho**: Range input para tamanho da fonte
4. **Preview**: Área de preview que aplica estilos dinamicamente
5. **ngStyle**: Usar `[ngStyle]` para aplicar estilos

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Componente criado com seletores de cor
- [ ] Slider para tamanho da fonte
- [ ] `[ngStyle]` usado para aplicar estilos
- [ ] Preview atualiza em tempo real
- [ ] Estilos são aplicados corretamente
- [ ] Código compila sem erros

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Estilos são aplicados dinamicamente
- [ ] Interface é intuitiva
- [ ] Código é legível e bem organizado

---

## Dicas

### Dica 1: ngStyle com Objeto

```html
<div [ngStyle]="{ 'background-color': bgColor, 'color': textColor }">
```

### Dica 2: ngStyle com Método

```typescript
getStyles(): {[key: string]: string} {
  return {
    'background-color': this.bgColor,
    'color': this.textColor,
    'font-size': this.fontSize + 'px'
  };
}
```

### Dica 3: Property Binding de Estilo

```html
<div [style.background-color]="bgColor" [style.font-size.px]="fontSize">
```

### Dica 4: Input Color

```html
<input type="color" [(ngModel)]="bgColor">
```

---

## Solução Esperada

### Abordagem Recomendada

**color-picker.component.ts**
```typescript
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-color-picker',
  standalone: true,
  imports: [FormsModule, CommonModule],
  templateUrl: './color-picker.component.html',
  styleUrls: ['./color-picker.component.css']
})
export class ColorPickerComponent {
  backgroundColor: string = '#ffffff';
  textColor: string = '#000000';
  fontSize: number = 16;
  fontFamily: string = 'Arial';
  
  getStyles(): {[key: string]: string} {
    return {
      'background-color': this.backgroundColor,
      'color': this.textColor,
      'font-size': this.fontSize + 'px',
      'font-family': this.fontFamily,
      'padding': '2rem',
      'border-radius': '8px',
      'min-height': '200px'
    };
  }
  
  resetStyles(): void {
    this.backgroundColor = '#ffffff';
    this.textColor = '#000000';
    this.fontSize = 16;
    this.fontFamily = 'Arial';
  }
}
```

**color-picker.component.html**
{% raw %}
```html
<div class="color-picker">
  <h2>Seletor de Cores e Estilos</h2>
  
  <div class="controls">
    <div class="control-group">
      <label>Cor de Fundo:</label>
      <input 
        type="color" 
        [(ngModel)]="backgroundColor"
        name="backgroundColor">
      <span>{{ backgroundColor }}</span>
    </div>
    
    <div class="control-group">
      <label>Cor do Texto:</label>
      <input 
        type="color" 
        [(ngModel)]="textColor"
        name="textColor">
      <span>{{ textColor }}</span>
    </div>
    
    <div class="control-group">
      <label>Tamanho da Fonte: {{ fontSize }}px</label>
      <input 
        type="range" 
        [(ngModel)]="fontSize"
        name="fontSize"
        min="12"
        max="48"
        step="2">
    </div>
    
    <div class="control-group">
      <label>Fonte:</label>
      <select [(ngModel)]="fontFamily" name="fontFamily">
        <option value="Arial">Arial</option>
        <option value="Georgia">Georgia</option>
        <option value="Courier New">Courier New</option>
        <option value="Times New Roman">Times New Roman</option>
      </select>
    </div>
    
    <button (click)="resetStyles()">Resetar</button>
  </div>
  
  <div class="preview">
    <h3>Preview</h3>
    <div class="preview-content" [ngStyle]="getStyles()">
      <p>Este é um texto de exemplo que demonstra como os estilos são aplicados dinamicamente.</p>
      <p>Você pode ver como a cor de fundo, cor do texto, tamanho da fonte e família de fonte mudam em tempo real.</p>
    </div>
  </div>
  
  <div class="code-output">
    <h3>Código CSS Gerado</h3>
    <pre>{{ getStyles() | json }}</pre>
  </div>
</div>
```
{% raw %}
<div class="color-picker">
  <h2>Seletor de Cores e Estilos</h2>
  
  <div class="controls">
    <div class="control-group">
      <label>Cor de Fundo:</label>
      <input 
        type="color" 
        [(ngModel)]="backgroundColor"
        name="backgroundColor">
      <span>{{ backgroundColor }}</span>
    </div>
    
    <div class="control-group">
      <label>Cor do Texto:</label>
      <input 
        type="color" 
        [(ngModel)]="textColor"
        name="textColor">
      <span>{{ textColor }}</span>
    </div>
    
    <div class="control-group">
      <label>Tamanho da Fonte: {{ fontSize }}px</label>
      <input 
        type="range" 
        [(ngModel)]="fontSize"
        name="fontSize"
        min="12"
        max="48"
        step="2">
    </div>
    
    <div class="control-group">
      <label>Fonte:</label>
      <select [(ngModel)]="fontFamily" name="fontFamily">
        <option value="Arial">Arial</option>
        <option value="Georgia">Georgia</option>
        <option value="Courier New">Courier New</option>
        <option value="Times New Roman">Times New Roman</option>
      </select>
    </div>
    
    <button (click)="resetStyles()">Resetar</button>
  </div>
  
  <div class="preview">
    <h3>Preview</h3>
    <div class="preview-content" [ngStyle]="getStyles()">
      <p>Este é um texto de exemplo que demonstra como os estilos são aplicados dinamicamente.</p>
      <p>Você pode ver como a cor de fundo, cor do texto, tamanho da fonte e família de fonte mudam em tempo real.</p>
    </div>
  </div>
  
  <div class="code-output">
    <h3>Código CSS Gerado</h3>
    <pre>{{ getStyles() | json }}</pre>
  </div>
</div>
```
{% endraw %}

**color-picker.component.css**
```css
.color-picker {
  max-width: 800px;
  margin: 0 auto;
  padding: 2rem;
}

.controls {
  display: grid;
  gap: 1.5rem;
  margin-bottom: 2rem;
  padding: 1.5rem;
  background-color: #f5f5f5;
  border-radius: 8px;
}

.control-group {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.control-group label {
  min-width: 150px;
  font-weight: 500;
}

.control-group input[type="color"] {
  width: 60px;
  height: 40px;
  border: 1px solid #ddd;
  border-radius: 4px;
  cursor: pointer;
}

.control-group input[type="range"] {
  flex: 1;
}

.control-group select {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  flex: 1;
}

button {
  padding: 0.75rem 1.5rem;
  background-color: #1976d2;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

.preview {
  margin-bottom: 2rem;
}

.preview-content {
  border: 2px dashed #ddd;
  margin-top: 1rem;
}

.code-output {
  padding: 1rem;
  background-color: #f9f9f9;
  border-radius: 4px;
}

pre {
  background-color: #263238;
  color: #aed581;
  padding: 1rem;
  border-radius: 4px;
  overflow-x: auto;
}
```

**Explicação da Solução**:

1. Propriedades para cada estilo (cor, tamanho, fonte)
2. `getStyles()` retorna objeto com estilos
3. `[ngStyle]` aplica estilos dinamicamente
4. Two-way binding sincroniza controles e preview
5. Código CSS gerado exibido para referência
6. Botão reset restaura valores padrão

**Decisões de Design**:

- Método `getStyles()` centraliza lógica
- Preview atualiza em tempo real
- Código CSS exibido para aprendizado
- Interface intuitiva e organizada

---

## Testes

### Casos de Teste

**Teste 1**: Cor de fundo aplicada
- **Input**: Selecionar cor de fundo
- **Output Esperado**: Preview deve mudar cor de fundo

**Teste 2**: Tamanho da fonte aplicado
- **Input**: Mover slider de tamanho
- **Output Esperado**: Texto deve mudar de tamanho

**Teste 3**: Múltiplos estilos aplicados
- **Input**: Mudar múltiplos controles
- **Output Esperado**: Todos os estilos devem ser aplicados simultaneamente

**Teste 4**: Reset funciona
- **Input**: Clicar em "Resetar"
- **Output Esperado**: Todos os valores devem voltar ao padrão

---

## Extensões (Opcional)

1. **Salvar Presets**: Salve combinações de estilos favoritas
2. **Exportar CSS**: Botão para copiar CSS gerado
3. **Mais Opções**: Adicione opções para padding, margin, border
4. **Temas Pré-definidos**: Botões para aplicar temas pré-definidos

---

## Referências Úteis

- **[ngStyle](https://angular.io/api/common/NgStyle)**: Documentação oficial
- **[Style Binding](https://angular.io/guide/attribute-binding#style-binding)**: Guia de binding de estilos

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

