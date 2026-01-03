---
layout: exercise
title: "Exercício 1.5.3: Pipe Customizado Simples"
slug: "pipe-simples"
lesson_id: "lesson-1-5"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **criação de pipes customizados** através da **implementação de um pipe capitalize que capitaliza primeira letra de cada palavra**.

Ao completar este exercício, você será capaz de:

- Criar pipe customizado standalone
- Implementar interface PipeTransform
- Usar decorator @Pipe
- Aplicar pipe no template
- Entender pure vs impure

---

## Descrição

Você precisa criar um pipe `CapitalizePipe` que capitaliza a primeira letra de cada palavra em uma string. O pipe deve ser standalone e pode aceitar parâmetros opcionais.

### Contexto

Um sistema precisa formatar nomes e títulos de forma consistente. Um pipe customizado é a solução ideal para esta necessidade.

### Tarefa

Crie um pipe `CapitalizePipe` com:

1. **Decorator @Pipe**: Nome 'capitalize', standalone: true
2. **PipeTransform**: Implementar interface PipeTransform
3. **Método transform**: Capitalizar primeira letra de cada palavra
4. **Parâmetro opcional**: Aceitar opção para capitalizar apenas primeira palavra
5. **Uso**: Aplicar pipe em template

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Pipe criado com @Pipe decorator
- [ ] Interface PipeTransform implementada
- [ ] Método transform implementado
- [ ] Capitalização funciona corretamente
- [ ] Parâmetro opcional funciona
- [ ] Pipe pode ser usado no template

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Pipe é pure (padrão)
- [ ] Tratamento de casos edge (null, undefined, empty)
- [ ] Código é legível e bem organizado

---

## Dicas

### Dica 1: Estrutura Básica

```typescript
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'capitalize',
  standalone: true
})
export class CapitalizePipe implements PipeTransform {
  transform(value: string): string {
    // implementação
  }
}
```

### Dica 2: Capitalizar Palavra

```typescript
capitalizeWord(word: string): string {
  if (!word) return word;
  return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
}
```

### Dica 3: Dividir e Juntar

```typescript
const words = value.split(' ');
const capitalized = words.map(w => this.capitalizeWord(w));
return capitalized.join(' ');
```

### Dica 4: Parâmetro Opcional

```typescript
transform(value: string, onlyFirst: boolean = false): string {
  if (onlyFirst) {
    // capitalizar apenas primeira palavra
  } else {
    // capitalizar todas
  }
}
```

---

## Solução Esperada

### Abordagem Recomendada

**capitalize.pipe.ts**
```typescript
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'capitalize',
  standalone: true
})
export class CapitalizePipe implements PipeTransform {
  transform(value: string | null | undefined, onlyFirst: boolean = false): string {
    if (!value) return '';
    
    const trimmed = value.trim();
    if (trimmed.length === 0) return '';
    
    if (onlyFirst) {
      return this.capitalizeWord(trimmed);
    }
    
    const words = trimmed.split(/\s+/);
    const capitalized = words.map(word => this.capitalizeWord(word));
    return capitalized.join(' ');
  }
  
  private capitalizeWord(word: string): string {
    if (!word || word.length === 0) return word;
    return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
  }
}
```

**exemplo-uso.component.ts**
{% raw %}
```typescript
import { Component } from '@angular/core';
import { CapitalizePipe } from './capitalize.pipe';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-exemplo-uso',
  standalone: true,
  imports: [CapitalizePipe, CommonModule],
{% raw %}
  template: `
    <div class="capitalize-examples">
      <h2>Exemplos de Capitalize Pipe</h2>
      
      <div class="example">
        <h3>Capitalizar Todas as Palavras</h3>
        <p>Original: "joão silva santos"</p>
        <p>Resultado: {{ "joão silva santos" | capitalize }}</p>
      </div>
      
      <div class="example">
        <h3>Capitalizar Apenas Primeira Palavra</h3>
        <p>Original: "joão silva santos"</p>
        <p>Resultado: {{ "joão silva santos" | capitalize:true }}</p>
      </div>
      
      <div class="example">
        <h3>Com Variável</h3>
        <p>Nome: {{ userName | capitalize }}</p>
        <p>Título: {{ title | capitalize:true }}</p>
      </div>
      
      <div class="example">
        <h3>Casos Especiais</h3>
        <p>Vazio: "{{ emptyString | capitalize }}"</p>
        <p>Múltiplos espaços: "{{ multipleSpaces | capitalize }}"</p>
        <p>Já capitalizado: "{{ alreadyCapitalized | capitalize }}"</p>
      </div>
    </div>
  `
{% endraw %}
})
export class ExemploUsoComponent {
  userName: string = 'maria da silva';
  title: string = 'desenvolvedor angular';
  emptyString: string = '';
  multipleSpaces: string = '  joão   silva  ';
  alreadyCapitalized: string = 'João Silva';
}
```
{% endraw %}

**Explicação da Solução**:

1. Pipe criado com `@Pipe` e `standalone: true`
2. `PipeTransform` interface implementada
3. Método `transform` aceita valor e parâmetro opcional
4. Tratamento de null/undefined/empty
5. Método helper `capitalizeWord` para reutilização
6. Suporte para capitalizar todas ou apenas primeira palavra
7. Tratamento de múltiplos espaços

**Decisões de Design**:

- Pipe é pure (padrão) para melhor performance
- Método helper privado para organização
- Tratamento robusto de edge cases
- Parâmetro opcional com valor padrão

---

## Testes

### Casos de Teste

**Teste 1**: Capitalizar todas as palavras
- **Input**: `"joão silva" | capitalize`
- **Output Esperado**: "João Silva"

**Teste 2**: Capitalizar apenas primeira
- **Input**: `"joão silva" | capitalize:true`
- **Output Esperado**: "João silva"

**Teste 3**: String vazia
- **Input**: `"" | capitalize`
- **Output Esperado**: ""

**Teste 4**: Múltiplos espaços
- **Input**: `"  joão   silva  " | capitalize`
- **Output Esperado**: "João Silva"

**Teste 5**: Já capitalizado
- **Input**: `"João Silva" | capitalize`
- **Output Esperado**: "João Silva"

---

## Extensões (Opcional)

1. **Preservar Maiúsculas**: Adicione opção para preservar maiúsculas existentes
2. **Palavras de Exceção**: Não capitalizar palavras como "de", "da", "do"
3. **Múltiplos Idiomas**: Suporte para diferentes regras de capitalização
4. **Performance**: Teste performance com strings muito longas

---

## Referências Úteis

- **[Creating Pipes](https://angular.io/guide/pipes#creating-pipes)**: Guia de criação de pipes
- **[PipeTransform](https://angular.io/api/core/PipeTransform)**: Documentação PipeTransform
- **[@Pipe](https://angular.io/api/core/Pipe)**: Documentação @Pipe

---

## Checklist de Qualidade

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais
- [x] Referências úteis estão incluídas

