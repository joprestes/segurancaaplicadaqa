---
layout: module
title: "Performance e Otimização"
slug: performance-otimizacao
duration: "8 horas"
description: "Crie aplicações extremamente performáticas"
lessons: 
  - "lesson-4-1"
  - "lesson-4-2"
  - "lesson-4-3"
  - "lesson-4-4"
  - "lesson-4-5"
module: module-4
---

## Objetivos do Módulo

Ao final deste módulo, o aluno será capaz de:

1. Implementar estratégias avançadas de change detection (OnPush)
2. Configurar lazy loading avançado e code splitting eficiente
3. Usar deferrable views (@defer) para otimização de performance
4. Realizar profiling e otimização de aplicações Angular
5. Migrar para aplicações zoneless

---

## Tópicos Cobertos

### 4.1 Change Detection Strategies (2h)
- Default strategy vs OnPush
- Imutabilidade
- ChangeDetectorRef
- detach() e detectChanges()
- OnPush everywhere
- TrackBy functions
- Detecção de mudanças manual

### 4.2 Lazy Loading e Code Splitting (2h)
- Lazy Loading de módulos
- Preloading strategies
- Custom Preloading Strategy
- Code splitting avançado
- Tree-shaking
- Bundle optimization
- Análise de bundles

### 4.3 Deferrable Views e Performance (1.5h)
- @defer block
- @placeholder, @loading, @error
- Triggers (on idle, on timer, on viewport, on interaction)
- Performance improvements
- Casos de uso práticos

### 4.4 Profiling e Otimização (1.5h)
- Angular DevTools
- Chrome DevTools integration
- Performance profiling
- Memory leaks detection
- Bundle analysis
- Lighthouse audits
- Otimização de imagens (ngOptimizedImage)

### 4.5 Zone.js e Zoneless Apps (1h)
- Zone.js e NgZone
- runOutsideAngular()
- NoopNgZone
- Zoneless Apps (Angular 18+)
- Migração para aplicações sem Zone.js
- Benefícios e trade-offs

---

## Aulas Planejadas

1. **Aula 4.1**: Change Detection Strategies (2h)
   - Objetivo: Implementar OnPush e otimizar change detection
   - Exercícios: 6 exercícios práticos

2. **Aula 4.2**: Lazy Loading e Code Splitting (2h)
   - Objetivo: Configurar lazy loading avançado e code splitting
   - Exercícios: 5 exercícios práticos

3. **Aula 4.3**: Deferrable Views e Performance (1.5h)
   - Objetivo: Usar deferrable views para otimização
   - Exercícios: 4 exercícios práticos

4. **Aula 4.4**: Profiling e Otimização (1.5h)
   - Objetivo: Profilar e otimizar aplicações
   - Exercícios: 5 exercícios práticos

5. **Aula 4.5**: Zone.js e Zoneless Apps (1h)
   - Objetivo: Entender Zone.js e migrar para zoneless
   - Exercícios: 3 exercícios práticos

**Total de Aulas**: 5  
**Total de Exercícios**: 23

---

## Projeto Prático do Módulo

### Projeto: Otimização de Aplicação Existente

**Descrição**: Pegar uma aplicação existente e aplicar todas as técnicas de otimização aprendidas.

**Requisitos**:
- Converter para OnPush strategy
- Implementar lazy loading completo
- Adicionar deferrable views
- Otimizar bundles
- Profilar e melhorar performance
- Documentar melhorias de performance

**Duração Estimada**: 3 horas

---

## Dependências

**Pré-requisitos**:
- Módulo 1: Fundamentos Acelerados completo
- Módulo 2: Desenvolvimento Intermediário completo
- Módulo 3: Programação Reativa e Estado completo

**Dependências de Módulos**:
- Requer conhecimento de componentes, roteamento e estado

**Prepara para**:
- Módulo 5: Práticas Avançadas e Projeto Final

---

## Recursos Adicionais

- [Angular Performance Guide](https://angular.io/guide/performance)
- [Angular Change Detection](https://angular.io/guide/change-detection)
- [Angular Lazy Loading](https://angular.io/guide/lazy-loading-ngmodules)
- [Angular Deferrable Views](https://angular.io/guide/defer)

---

## Checklist de Conclusão

- [ ] OnPush strategy implementada
- [ ] Lazy loading configurado
- [ ] Code splitting otimizado
- [ ] Deferrable views aplicadas
- [ ] Profiling realizado
- [ ] Performance otimizada
- [ ] Zone.js entendido
- [ ] Migração para zoneless (opcional)
- [ ] Projeto prático concluído

---

**Módulo Anterior**: [Módulo 3: Programação Reativa e Estado](./module-3-programacao-reativa-estado.md)  
**Próximo Módulo**: [Módulo 5: Práticas Avançadas e Projeto Final](./module-5-praticas-avancadas-projeto-final.md)

