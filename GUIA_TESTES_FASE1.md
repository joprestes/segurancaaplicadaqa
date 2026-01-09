# 🧪 Guia de Testes - Fase 1

**Data:** Janeiro 2025  
**Status:** ✅ Correções Implementadas - Pronto para Teste

---

## 🚀 Como Iniciar o Servidor

```bash
cd "/Users/joelmadeoliveiraprestesferreira/Desktop/POC 3/poc3/crescidos-qualidade"
bundle exec jekyll serve --force_polling
```

O servidor estará disponível em: **http://localhost:4000/seguranca-qa/**

**Importante:** 
- Use `--force_polling` para garantir detecção de mudanças
- Limpe o cache do navegador (Cmd+Shift+R no Mac, Ctrl+Shift+R no Windows)

---

## ✅ Checklist de Testes - Fase 1

### 1.1 🔴 Compilação CSS

#### Teste 1.1.1: Empty State Visível
- [ ] Navegar para uma página de módulo (ex: `/seguranca-qa/modules/fundamentos-seguranca-qa/`)
- [ ] Se não houver quizzes completados, verificar se aparece o componente **empty-state**
- [ ] Verificar se o empty-state tem:
  - [ ] Ícone centralizado
  - [ ] Título visível
  - [ ] Descrição legível
  - [ ] Estilos aplicados corretamente (padding, alinhamento)

**Onde testar:**
- Página de resumo do módulo
- Seção de quizzes quando não há resultados

#### Teste 1.1.2: Navegação com Espaçamento
- [ ] Navegar para qualquer aula (ex: `/seguranca-qa/modules/fundamentos-seguranca-qa/lessons/...`)
- [ ] Verificar a seção de navegação (botões "Aula Anterior" / "Próxima Aula")
- [ ] Verificar se há espaçamento adequado entre os botões
- [ ] Quando há apenas um botão, verificar se não está colado na borda

**Onde testar:**
- Qualquer página de aula
- Página de exercício

#### Teste 1.1.3: Footer Moderno
- [ ] Rolar até o final de qualquer página
- [ ] Verificar se o footer tem:
  - [ ] Gradiente de fundo
  - [ ] Barra superior animada (se animações estiverem habilitadas)
  - [ ] Links organizados
  - [ ] Estilos modernos aplicados

**Onde testar:**
- Qualquer página do site

---

### 1.2 🔴 Exercícios (404 Corrigido)

#### Teste 1.2.1: Acessar Exercícios
- [ ] Navegar para uma aula que tenha exercícios
- [ ] Clicar em um link de exercício
- [ ] Verificar se a página carrega (não retorna 404)
- [ ] Verificar se o conteúdo do exercício é exibido

**Exercícios para testar:**
1. `/seguranca-qa/modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-2-exercise-1-identificar-vulnerabilidades/`
2. `/seguranca-qa/modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-3-exercise-1-security-requirements/`
3. `/seguranca-qa/modules/fundamentos-seguranca-qa/lessons/exercises/lesson-1-5-exercise-1-lgpd-checklist/`

#### Teste 1.2.2: Layout do Exercício
- [ ] Verificar se o layout `exercise.html` está sendo aplicado
- [ ] Verificar se há:
  - [ ] Título do exercício
  - [ ] Conteúdo formatado
  - [ ] Navegação (voltar para aula)
  - [ ] Estilos corretos

#### Teste 1.2.3: Navegação entre Exercícios
- [ ] De um exercício, navegar para outro
- [ ] Verificar se as URLs estão corretas
- [ ] Verificar se não há erros 404

---

### 1.3 🟡 Empty State em Quizzes

#### Teste 1.3.1: Empty State Quando Não Há Resultados
- [ ] Limpar localStorage (DevTools → Application → Local Storage → Clear)
- [ ] Navegar para página de resumo do módulo
- [ ] Verificar se aparece o empty-state na seção de quizzes
- [ ] Verificar se a mensagem é clara e útil

**Como limpar localStorage:**
1. Abrir DevTools (F12)
2. Ir em "Application" (Chrome) ou "Storage" (Firefox)
3. Selecionar "Local Storage"
4. Clicar em "Clear" ou deletar manualmente

#### Teste 1.3.2: Empty State com Estilos
- [ ] Verificar se o empty-state tem:
  - [ ] Padding adequado
  - [ ] Alinhamento centralizado
  - [ ] Cores corretas (respeitando tema claro/escuro)
  - [ ] Ícone visível (se houver)

---

### 1.4 🟡 Navegação com Botões

#### Teste 1.4.1: Espaçamento Visual
- [ ] Navegar para uma aula
- [ ] Verificar a seção `.lesson-navigation`
- [ ] Verificar se há `gap: 1.5rem` aplicado (usar DevTools)
- [ ] Verificar visualmente se os botões não estão colados

**Como verificar no DevTools:**
1. Inspecionar elemento `.lesson-navigation`
2. Verificar no painel de estilos se há `gap: 1.5rem`
3. Verificar visualmente o espaçamento

#### Teste 1.4.2: Responsividade
- [ ] Testar em diferentes tamanhos de tela:
  - [ ] Mobile (375px)
  - [ ] Tablet (768px)
  - [ ] Desktop (1920px)
- [ ] Verificar se o espaçamento se mantém adequado

---

## 🔍 Verificações Técnicas (DevTools)

### Verificar CSS Compilado

1. Abrir DevTools (F12)
2. Ir em "Network" → Recarregar página
3. Procurar por `main.css`
4. Clicar no arquivo → Ver "Response"
5. Procurar por:
   - `.empty-state` (deve encontrar)
   - `gap:1.5rem` ou `gap: 1.5rem` (deve encontrar)
   - `.site-footer` (deve encontrar estilos modernos)

### Verificar Console

1. Abrir DevTools → Console
2. Verificar se há erros JavaScript
3. Verificar se há warnings
4. Se houver erros relacionados a CSS, reportar

---

## 📋 Checklist Rápido

### Funcionalidades Críticas
- [ ] CSS compila corretamente
- [ ] Empty-state aparece quando não há quizzes
- [ ] Exercícios abrem sem 404
- [ ] Navegação tem espaçamento adequado
- [ ] Footer tem estilos modernos

### Visual
- [ ] Empty-state estilizado corretamente
- [ ] Botões de navegação com espaçamento
- [ ] Footer com gradiente e animação
- [ ] Tema claro/escuro funciona

### Técnico
- [ ] Sem erros no console
- [ ] CSS carregado corretamente
- [ ] URLs de exercícios corretas
- [ ] Layouts aplicados corretamente

---

## 🐛 Problemas Conhecidos a Verificar

### Se Empty State Não Aparecer:
1. Limpar cache do navegador (Cmd+Shift+R)
2. Verificar se localStorage está limpo
3. Verificar console para erros JavaScript
4. Verificar se CSS foi carregado (Network tab)

### Se Exercícios Retornarem 404:
1. Verificar se build foi executado: `bundle exec jekyll build`
2. Verificar se arquivos existem em `_site/seguranca-qa/modules/.../exercises/`
3. Verificar se permalink está correto no arquivo `.md`

### Se Espaçamento Não Estiver Correto:
1. Verificar se CSS foi recarregado
2. Limpar cache do navegador
3. Verificar no DevTools se `gap: 1.5rem` está aplicado

---

## 📝 Relatório de Testes

Após testar, preencha:

**Data do Teste:** _______________

**Navegador:** _______________
- [ ] Chrome
- [ ] Firefox
- [ ] Safari
- [ ] Edge

**Sistema Operacional:** _______________

**Resultados:**
- [ ] Todos os testes passaram
- [ ] Alguns testes falharam (especificar abaixo)
- [ ] Problemas encontrados (descrever)

**Problemas Encontrados:**
1. _______________________________________
2. _______________________________________
3. _______________________________________

**Observações:**
_______________________________________
_______________________________________

---

## ✅ Critérios de Sucesso

A Fase 1 será considerada **completa** quando:

1. ✅ Empty-state aparece corretamente quando não há quizzes
2. ✅ Todos os exercícios abrem sem erro 404
3. ✅ Navegação tem espaçamento visual adequado
4. ✅ Footer tem estilos modernos aplicados
5. ✅ CSS compilado contém todos os estilos necessários
6. ✅ Sem erros críticos no console

---

**Próximos Passos Após Testes:**
- Se todos os testes passarem → Iniciar Fase 2
- Se houver problemas → Corrigir antes de continuar
