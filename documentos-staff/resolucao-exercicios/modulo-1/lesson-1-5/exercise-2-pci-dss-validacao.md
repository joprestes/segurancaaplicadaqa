---
exercise_id: lesson-1-5-exercise-2-pci-dss-validacao
title: "Exercício 1.5.2: Validação PCI-DSS"
lesson_id: lesson-1-5
module: module-1
difficulty: "Intermediário"
last_updated: 2026-01-14
---

# Exercício 1.5.2: Validação PCI-DSS

## 📋 Enunciado Completo

Este exercício tem como objetivo **validar compliance PCI-DSS** através da criação de testes e validação dos 12 requisitos PCI-DSS.

### Tarefa Principal

1. Entender os 12 requisitos PCI-DSS
2. Criar testes de validação PCI-DSS
3. Validar controles de segurança de pagamentos
4. Preparar evidências para auditoria PCI-DSS

---

## ✅ Soluções Detalhadas

### Parte 1: Entender Requisitos PCI-DSS

**Solução Esperada - Resumo dos 12 Requisitos:**

#### Grupo 1: Construir e Manter Rede Segura
- **Requisito 1**: Instalar e manter firewall
- **Requisito 2**: Não usar senhas padrão

#### Grupo 2: Proteger Dados do Portador
- **Requisito 3**: Proteger dados armazenados (nunca armazenar dados de cartão em texto plano)
- **Requisito 4**: Criptografar dados em trânsito (HTTPS obrigatório)

#### Grupo 3: Manter Programa de Gestão de Vulnerabilidades
- **Requisito 5**: Usar e atualizar antivírus
- **Requisito 6**: Desenvolver e manter sistemas seguros (secure coding, testes de segurança)

#### Grupo 4: Implementar Medidas de Controle de Acesso
- **Requisito 7**: Restringir acesso por necessidade de negócio (princípio de menor privilégio)
- **Requisito 8**: Identificar e autenticar acesso (autenticação forte, MFA)
- **Requisito 9**: Restringir acesso físico a dados

#### Grupo 5: Monitorar e Testar Redes
- **Requisito 10**: Rastrear e monitorar acesso (logs de todas as operações)
- **Requisito 11**: Testar regularmente sistemas (testes de segurança, scans de vulnerabilidades)

#### Grupo 6: Manter Política de Segurança
- **Requisito 12**: Manter política que aborde segurança (políticas, procedimentos, treinamento)

**Validação Técnica:**
- ✅ 12 requisitos PCI-DSS listados
- ✅ Agrupamento correto por categoria
- ✅ Resumo adequado de cada requisito

---

### Parte 2: Criar Testes de Validação

**Solução Esperada:**

#### Requisito PCI-DSS 3: Proteger Dados Armazenados

**Objetivo**: Dados de cartão não devem ser armazenados em texto plano. Dados devem ser tokenizados ou não armazenados.

**Controles Esperados:**
- [ ] Dados de cartão nunca são armazenados em texto plano no banco de dados
- [ ] Tokenização implementada (usar token de gateway de pagamento)
- [ ] Apenas últimos 4 dígitos armazenados para identificação (se necessário)
- [ ] CVV nunca é armazenado (mesmo após transação)
- [ ] Dados de cartão não aparecem em logs

**Testes de Validação:**
- **Teste 1**: Verificar que dados de cartão não estão no banco de dados
  - **Passos**: Verificar banco de dados, procurar por padrões de cartão (16 dígitos, números)
  - **Resultado Esperado**: Nenhum dado de cartão encontrado no banco
  - **Evidência**: Query no banco mostrando que não há dados de cartão

- **Teste 2**: Verificar que tokenização está implementada
  - **Passos**: Processar pagamento, verificar que apenas token é armazenado (não número do cartão)
  - **Resultado Esperado**: Apenas token armazenado (formato diferente de número de cartão)
  - **Evidência**: Query no banco mostrando token armazenado

- **Teste 3**: Verificar que CVV nunca é armazenado
  - **Passos**: Processar pagamento, verificar banco de dados e logs
  - **Resultado Esperado**: CVV não encontrado em banco ou logs
  - **Evidência**: Busca no banco e logs confirmando ausência de CVV

- **Teste 4**: Verificar que logs não contêm dados de cartão
  - **Passos**: Processar pagamento, verificar logs (aplicação, servidor, gateway)
  - **Resultado Esperado**: Nenhum dado de cartão completo encontrado em logs (apenas últimos 4 dígitos se necessário)
  - **Evidência**: Busca em logs confirmando ausência de dados de cartão completos

**Validação Técnica:**
- ✅ Testes específicos criados para requisito PCI-DSS 3
- ✅ Controles esperados listados
- ✅ Steps to reproduce detalhados
- ✅ Evidências necessárias listadas

---

#### Requisito PCI-DSS 4: Criptografar Dados em Trânsito

**Objetivo**: Dados de cartão devem ser criptografados em trânsito (HTTPS obrigatório).

**Controles Esperados:**
- [ ] HTTPS obrigatório em todo o fluxo de pagamento
- [ ] TLS 1.2+ obrigatório (não TLS 1.0, 1.1)
- [ ] Redirecionamento automático de HTTP para HTTPS
- [ ] Certificados SSL válidos e atualizados
- [ ] Não há dados de cartão transmitidos via HTTP

**Testes de Validação:**
- **Teste 1**: Verificar que HTTPS é obrigatório
  - **Passos**: Acessar endpoint de checkout via HTTP, verificar redirecionamento para HTTPS
  - **Resultado Esperado**: Redirecionamento automático para HTTPS (301/302)
  - **Evidência**: Screenshot de redirecionamento, logs de servidor

- **Teste 2**: Verificar versão TLS (1.2+)
  - **Passos**: Usar SSL Labs ou ferramenta similar para testar configuração TLS
  - **Resultado Esperado**: TLS 1.2 ou superior, protocolos antigos (TLS 1.0, 1.1) desabilitados
  - **Evidência**: Resultado de SSL Labs mostrando TLS 1.2+

- **Teste 3**: Verificar que certificado SSL é válido
  - **Passos**: Verificar certificado SSL (validade, emissor confiável, domínio correto)
  - **Resultado Esperado**: Certificado válido, não expirado, emitido por CA confiável
  - **Evidência**: Detalhes do certificado SSL

- **Teste 4**: Verificar que dados de cartão não são transmitidos via HTTP
  - **Passos**: Interceptar requisição de pagamento via HTTP (se possível), verificar que dados não são enviados
  - **Resultado Esperado**: Dados de cartão não são enviados via HTTP (apenas HTTPS)
  - **Evidência**: Logs ou captura de tráfego mostrando que não há dados via HTTP

**Validação Técnica:**
- ✅ Testes específicos criados para requisito PCI-DSS 4
- ✅ Controles técnicos validados (TLS, certificados)
- ✅ Evidências necessárias listadas

---

#### Requisito PCI-DSS 6: Desenvolver e Manter Sistemas Seguros

**Objetivo**: Sistemas devem ser desenvolvidos e mantidos de forma segura (secure coding, testes de segurança).

**Controles Esperados:**
- [ ] Secure coding practices seguidas (OWASP Top 10)
- [ ] Testes de segurança realizados (SQL Injection, XSS, Broken Access Control)
- [ ] Dependências atualizadas (sem vulnerabilidades conhecidas - CVE)
- [ ] Code reviews de segurança realizados
- [ ] Vulnerabilidades corrigidas antes de produção

**Testes de Validação:**
- **Teste 1**: Verificar que testes de segurança são realizados
  - **Passos**: Executar testes de segurança (OWASP ZAP, Semgrep, etc.)
  - **Resultado Esperado**: Testes executados, vulnerabilidades críticas/altas corrigidas
  - **Evidência**: Relatórios de testes de segurança, histórico de correções

- **Teste 2**: Verificar que dependências estão atualizadas
  - **Passos**: Executar scanner de dependências (Snyk, OWASP Dependency-Check)
  - **Resultado Esperado**: Sem vulnerabilidades conhecidas (CVE) em dependências
  - **Evidência**: Relatório de scanner de dependências

- **Teste 3**: Verificar que code reviews de segurança são realizados
  - **Passos**: Revisar histórico de PRs/MRs, verificar que code reviews de segurança são realizados
  - **Resultado Esperado**: Code reviews de segurança realizados para mudanças críticas
  - **Evidência**: Histórico de PRs/MRs com code reviews

- **Teste 4**: Verificar que vulnerabilidades são corrigidas
  - **Passos**: Revisar histórico de vulnerabilidades encontradas, verificar que foram corrigidas
  - **Resultado Esperado**: Vulnerabilidades críticas/altas corrigidas antes de produção
  - **Evidência**: Histórico de vulnerabilidades e correções

**Validação Técnica:**
- ✅ Testes específicos criados para requisito PCI-DSS 6
- ✅ Secure coding e testes de segurança validados
- ✅ Evidências necessárias listadas

---

#### Requisito PCI-DSS 8: Identificar e Autenticar Acesso

**Objetivo**: Acesso deve ser identificado e autenticado (autenticação forte, MFA).

**Controles Esperados:**
- [ ] Autenticação forte implementada (senhas complexas, mínimo 12 caracteres)
- [ ] MFA obrigatório para operações sensíveis (pagamentos acima de valor limite)
- [ ] Senhas nunca são transmitidas em texto plano
- [ ] Senhas são armazenadas com hash (bcrypt, nunca texto plano)
- [ ] Sessões expiram após inatividade

**Testes de Validação:**
- **Teste 1**: Verificar política de senhas forte
  - **Passos**: Tentar criar conta com senha fraca (menos de 12 caracteres, sem complexidade)
  - **Resultado Esperado**: Senha rejeitada, política de senhas forte aplicada
  - **Evidência**: Teste de criação de conta com senha fraca (deve falhar)

- **Teste 2**: Verificar que MFA é obrigatório para pagamentos
  - **Passos**: Tentar fazer pagamento acima de valor limite sem MFA
  - **Resultado Esperado**: MFA obrigatório antes de processar pagamento
  - **Evidência**: Teste de pagamento sem MFA (deve requerer MFA)

- **Teste 3**: Verificar que senhas são armazenadas com hash
  - **Passos**: Verificar banco de dados, confirmar que senhas estão em hash (bcrypt)
  - **Resultado Esperado**: Senhas em hash, nunca em texto plano
  - **Evidência**: Query no banco mostrando hash de senhas

- **Teste 4**: Verificar que sessões expiram
  - **Passos**: Fazer login, aguardar tempo de inatividade, tentar operação sensível
  - **Resultado Esperado**: Sessão expirada, reautenticação requerida
  - **Evidência**: Teste de expiração de sessão

**Validação Técnica:**
- ✅ Testes específicos criados para requisito PCI-DSS 8
- ✅ Autenticação forte e MFA validados
- ✅ Evidências necessárias listadas

---

#### Requisito PCI-DSS 10: Rastrear e Monitorar Acesso

**Objetivo**: Todas as operações em dados de cartão devem ser logadas e monitoradas.

**Controles Esperados:**
- [ ] Logs de todas as operações em dados de cartão (processamento, consulta, modificação)
- [ ] Logs incluem: data/hora, usuário, ação, resultado
- [ ] Logs são imutáveis (não podem ser modificados)
- [ ] Logs são retidos por pelo menos 1 ano (compliance PCI-DSS)
- [ ] Monitoramento em tempo real configurado (alertas de acesso não autorizado)

**Testes de Validação:**
- **Teste 1**: Verificar que operações em dados de cartão são logadas
  - **Passos**: Processar pagamento, verificar logs (aplicação, servidor)
  - **Resultado Esperado**: Operação logada com data/hora, usuário, ação, resultado
  - **Evidência**: Logs de operação de pagamento

- **Teste 2**: Verificar que logs incluem informações necessárias
  - **Passos**: Revisar logs, verificar que incluem: data/hora, usuário, ação, resultado
  - **Resultado Esperado**: Logs contêm todas as informações necessárias
  - **Evidência**: Exemplo de log com todas as informações

- **Teste 3**: Verificar que logs são imutáveis
  - **Passos**: Tentar modificar log (se possível), verificar que não pode ser modificado
  - **Resultado Esperado**: Logs não podem ser modificados (imutáveis)
  - **Evidência**: Teste de modificação de log (deve falhar)

- **Teste 4**: Verificar retenção de logs (1 ano mínimo)
  - **Passos**: Verificar política de retenção de logs, confirmar que logs são retidos por 1+ ano
  - **Resultado Esperado**: Logs retidos por pelo menos 1 ano
  - **Evidência**: Política de retenção de logs, logs antigos disponíveis

**Validação Técnica:**
- ✅ Testes específicos criados para requisito PCI-DSS 10
- ✅ Logs e auditoria validados
- ✅ Evidências necessárias listadas

---

### Parte 3: Resumo de Validação PCI-DSS

**Solução Esperada:**

```markdown
# Relatório de Validação PCI-DSS

## Informações Gerais
- **Aplicação**: [Nome]
- **Data**: [Data]
- **Responsável**: [Nome]
- **Escopo**: Requisitos PCI-DSS relacionados a dados de cartão

## Resumo de Conformidade

### Requisitos Validados
| Requisito | Status | Observações |
|-----------|--------|-------------|
| 3 - Proteger Dados Armazenados | ✅ Conforme | Tokenização implementada |
| 4 - Criptografar em Trânsito | ✅ Conforme | HTTPS obrigatório, TLS 1.2+ |
| 6 - Sistemas Seguros | ⚠️ Parcialmente Conforme | Testes realizados, mas dependências precisam atualização |
| 8 - Autenticação | ✅ Conforme | Autenticação forte, MFA para pagamentos |
| 10 - Monitoramento | ✅ Conforme | Logs implementados, retenção 1+ ano |

### Não Conformidades Encontradas
1. **Requisito 6**: 2 dependências com CVE conhecido (prioridade P2 - corrigir em 1 semana)
2. **Requisito 3**: Logs podem conter últimos 4 dígitos (aceitável, mas documentar)

### Recomendações
1. Atualizar dependências vulneráveis (Requisito 6)
2. Documentar uso de últimos 4 dígitos em logs (Requisito 3)
3. Implementar monitoramento em tempo real (Requisito 10)

## Próximos Passos
1. Corrigir dependências vulneráveis
2. Documentar não conformidades menores
3. Implementar melhorias recomendadas
```

**Validação Técnica:**
- ✅ Resumo de conformidade criado
- ✅ Não conformidades identificadas
- ✅ Recomendações priorizadas

---

## 📊 Critérios de Avaliação

### ✅ Essenciais (Obrigatórios para Aprovação)

**Entendimento PCI-DSS:**
- [ ] 12 requisitos PCI-DSS listados
- [ ] Pelo menos 3-4 requisitos principais entendidos (3, 4, 6, 8, 10)

**Testes de Validação:**
- [ ] Testes criados para pelo menos 3 requisitos PCI-DSS principais
- [ ] Cada teste tem steps to reproduce e resultado esperado
- [ ] Evidências necessárias listadas

**Validação:**
- [ ] Resumo de conformidade criado
- [ ] Não conformidades identificadas (se houver)

### ⭐ Importantes (Recomendados para Resposta Completa)

**Testes de Validação:**
- [ ] Testes criados para 5+ requisitos PCI-DSS principais
- [ ] Testes são específicos e acionáveis
- [ ] Controles esperados listados para cada requisito
- [ ] Evidências bem documentadas

**Validação:**
- [ ] Resumo de conformidade completo
- [ ] Não conformidades identificadas e priorizadas
- [ ] Recomendações detalhadas

### 💡 Diferencial (Demonstram Conhecimento Avançado)

**Testes:**
- [ ] Testes automatizados criados
- [ ] Processo de validação contínua documentado
- [ ] Integração com CI/CD considerada

**Validação:**
- [ ] Processo de validação PCI-DSS completo documentado
- [ ] Métricas de compliance definidas
- [ ] Preparação para auditoria PCI-DSS documentada

---

## 🎓 Pontos Importantes para Monitores

### Conceitos-Chave Avaliados

1. **Entendimento PCI-DSS**: Aluno entende os 12 requisitos PCI-DSS?
2. **Testes de Validação**: Aluno cria testes específicos para validar PCI-DSS?
3. **Preparação para Auditoria**: Aluno prepara evidências adequadamente?

### Erros Comuns

1. **Erro: Focar apenas em requisitos técnicos**
   - **Situação**: Aluno valida apenas requisitos 3, 4, 6 e ignora requisitos organizacionais (12)
   - **Feedback**: "Boa validação dos requisitos técnicos! Lembre-se que PCI-DSS também inclui requisitos organizacionais (Requisito 12: políticas, procedimentos, treinamento). Valide que políticas e procedimentos estão documentados."

2. **Erro: Testes genéricos**
   - **Situação**: Aluno cria teste "verificar que dados de cartão estão protegidos" sem detalhar como
   - **Feedback**: "Boa ideia validar proteção de dados! Para tornar teste acionável, seja específico: 'verificar que dados de cartão não estão no banco (query procurando por 16 dígitos)', 'verificar que apenas token é armazenado (formato diferente de número de cartão)'. Isso torna teste implementável."

### Dicas para Feedback

- ✅ **Reconheça**: Entendimento dos requisitos PCI-DSS, testes específicos, evidências coletadas
- ❌ **Corrija**: Foco apenas em requisitos técnicos, testes genéricos, evidências ausentes
- 💡 **Incentive**: Testes automatizados, processo de validação contínua, preparação para auditoria

### Contexto Pedagógico

Este exercício é fundamental porque:

1. **Compliance Essencial**: PCI-DSS é obrigatório para processar pagamentos
2. **Habilidade Essencial**: QA precisa saber validar compliance PCI-DSS
3. **Prevenção**: Validação previne não conformidades antes de auditorias
4. **Segurança**: PCI-DSS garante proteção de dados de cartão

**Conexão com o Curso:**
- Aula 1.5: Compliance e Regulamentações (teoria) → Este exercício (prática de PCI-DSS)
- Pré-requisito para: Exercícios avançados de compliance (1.5.3-1.5.5)
- Base para: Validação de compliance em projetos financeiros

---

## 🌟 Exemplos de Boas Respostas

### Exemplo 1: Resposta Completa (Excelente)

**Testes Criados:**
"Requisito 3 - Proteger Dados Armazenados: Teste 1 - Verificar banco de dados não contém dados de cartão (query procurando por 16 dígitos). Teste 2 - Verificar tokenização implementada (apenas token armazenado). Teste 3 - Verificar CVV nunca armazenado. Teste 4 - Verificar logs não contêm dados de cartão. Todos os testes passando."

**Validação:**
"Requisito 3: ✅ Conforme - Tokenização implementada, dados de cartão não no banco, CVV nunca armazenado. Requisito 4: ✅ Conforme - HTTPS obrigatório, TLS 1.2+, certificado válido. Requisito 6: ⚠️ Parcialmente Conforme - Testes realizados, mas 2 dependências com CVE. Requisito 8: ✅ Conforme - Autenticação forte, MFA para pagamentos. Requisito 10: ✅ Conforme - Logs implementados, retenção 1+ ano."

**Características da Resposta:**
- ✅ Testes específicos criados para requisitos principais
- ✅ Validação completa documentada
- ✅ Não conformidades identificadas e priorizadas
- ✅ Recomendações específicas

---

**Última atualização**: 2026-01-14  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
