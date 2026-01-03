---
layout: exercise
title: "Exercício 1.2.3: Usar Generics"
slug: "generics"
lesson_id: "lesson-1-2"
module: "module-1"
difficulty: "Intermediário"
---

## Objetivo

Este exercício tem como objetivo praticar **uso de generics** através da **criação de funções genéricas reutilizáveis**.

Ao completar este exercício, você será capaz de:

- Criar funções genéricas com TypeScript
- Usar constraints em generics
- Entender como generics mantêm type safety
- Criar código reutilizável que funciona com múltiplos tipos

---

## Descrição

Você precisa criar funções genéricas utilitárias que funcionam com qualquer tipo que tenha uma propriedade `id`. Essas funções devem ser type-safe e reutilizáveis.

### Contexto

Um sistema precisa de funções utilitárias para operações comuns em arrays de entidades. Essas funções devem funcionar com qualquer tipo de entidade, mas mantendo type safety.

### Tarefa

Crie as seguintes funções genéricas:

1. **`getById<T>`**: Recebe um array de `T` e um `id` (number), retorna `T | undefined`
   - Constraint: `T` deve ter propriedade `id: number`

2. **`filter<T>`**: Recebe um array de `T` e uma função predicado, retorna `T[]`
   - Função predicado: `(item: T) => boolean`

3. **`map<T, R>`**: Recebe um array de `T` e uma função de transformação, retorna `R[]`
   - Função de transformação: `(item: T) => R`

4. **`findFirst<T>`**: Recebe um array de `T` e uma função predicado, retorna `T | undefined`

---

## Requisitos

### Funcionalidades Obrigatórias

- [ ] Função `getById` criada com constraint apropriado
- [ ] Função `filter` implementada corretamente
- [ ] Função `map` implementada com dois tipos genéricos
- [ ] Função `findFirst` implementada
- [ ] Todas as funções têm tipos explícitos
- [ ] Código funciona com diferentes tipos (Product, User, etc.)

### Critérios de Qualidade

- [ ] Código segue boas práticas aprendidas na aula
- [ ] Constraints são usados apropriadamente
- [ ] Type safety é mantido em todas as funções
- [ ] Código é legível e bem organizado
- [ ] Não há uso de `any`

---

## Dicas

### Dica 1: Sintaxe de Generics

Uma função genérica segue esta estrutura:
```typescript
function nomeFuncao<T>(parametro: T): T {
  // implementação
}
```

### Dica 2: Constraints com extends

Para garantir que T tenha uma propriedade específica:
```typescript
function exemplo<T extends { id: number }>(item: T): T {
  // T garante ter id: number
}
```

### Dica 3: Múltiplos Tipos Genéricos

Você pode usar múltiplos tipos genéricos:
```typescript
function exemplo<T, R>(item: T): R {
  // implementação
}
```

### Dica 4: Usando Array Methods

Use métodos nativos do array: `find`, `filter`, `map`

---

## Solução Esperada

### Abordagem Recomendada

```typescript
interface Identifiable {
  id: number;
}

function getById<T extends Identifiable>(items: T[], id: number): T | undefined {
  return items.find(item => item.id === id);
}

function filter<T>(items: T[], predicate: (item: T) => boolean): T[] {
  return items.filter(predicate);
}

function map<T, R>(items: T[], transform: (item: T) => R): R[] {
  return items.map(transform);
}

function findFirst<T>(items: T[], predicate: (item: T) => boolean): T | undefined {
  return items.find(predicate);
}
```

**Explicação da Solução**:

1. `Identifiable` interface define o contrato para entidades com id
2. `getById` usa constraint `extends Identifiable` para garantir type safety
3. `filter` é genérico puro que funciona com qualquer tipo
4. `map` usa dois tipos genéricos: `T` (entrada) e `R` (saída)
5. `findFirst` combina busca com predicado customizado

**Decisões de Design**:

- `Identifiable` interface permite reutilização do constraint
- `getById` usa constraint para garantir acesso seguro a `id`
- `map` usa dois tipos genéricos para flexibilidade de transformação
- Todas as funções mantêm type safety completo

---

## Testes

### Casos de Teste

**Teste 1**: getById com Product
- **Input**: 
```typescript
const products: Product[] = [
  { id: 1, name: "Produto 1", /* ... */ },
  { id: 2, name: "Produto 2", /* ... */ }
];
const found = getById(products, 1);
```
- **Output Esperado**: `found` deve ser o produto com id 1, tipo `Product | undefined`

**Teste 2**: filter com função predicado
- **Input**: 
```typescript
const numbers = [1, 2, 3, 4, 5];
const evens = filter(numbers, n => n % 2 === 0);
```
- **Output Esperado**: `evens` deve ser `[2, 4]`, tipo `number[]`

**Teste 3**: map com transformação
- **Input**: 
```typescript
const products: Product[] = [/* ... */];
const names = map(products, p => p.name);
```
- **Output Esperado**: `names` deve ser `string[]` com nomes dos produtos

**Teste 4** (Edge Case): getById com id inexistente
- **Input**: 
```typescript
const found = getById(products, 999);
```
- **Output Esperado**: `found` deve ser `undefined`

**Teste 5**: findFirst com predicado complexo
- **Input**: 
```typescript
const expensive = findFirst(products, p => p.price > 1000);
```
- **Output Esperado**: `expensive` deve ser primeiro produto com preço > 1000 ou `undefined`

---

## Extensões (Opcional)

Se você completou o exercício e quer um desafio adicional:

1. **`groupBy`**: Crie função genérica que agrupa itens por uma chave
2. **`sortBy`**: Crie função genérica que ordena por uma propriedade
3. **`reduce`**: Crie função genérica de redução customizada
4. **`chunk`**: Crie função que divide array em chunks de tamanho N

---

## Referências Úteis

- **[TypeScript Generics](https://www.typescriptlang.org/docs/handbook/2/generics.html)**: Documentação oficial sobre generics
- **[Generic Constraints](https://www.typescriptlang.org/docs/handbook/2/generics.html#generic-constraints)**: Como usar constraints
- **[TypeScript Utility Types](https://www.typescriptlang.org/docs/handbook/utility-types.html)**: Utility types que usam generics

---

## Checklist de Qualidade

Antes de considerar este exercício completo:

- [x] Objetivo está claro
- [x] Descrição fornece contexto suficiente
- [x] Requisitos são específicos e mensuráveis
- [x] Dicas guiam sem dar solução completa
- [x] Solução esperada está completa e explicada
- [x] Casos de teste cobrem cenários principais e edge cases
- [x] Referências úteis estão incluídas

