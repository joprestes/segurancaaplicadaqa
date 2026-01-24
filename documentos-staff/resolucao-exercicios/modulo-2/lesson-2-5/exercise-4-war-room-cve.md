---
exercise_id: lesson-2-5-exercise-4-war-room-cve
title: "Exercício 2.5.4: War Room - CVE Crítico"
lesson_id: lesson-2-5
module: module-2
difficulty: "Avançado"
last_updated: 2026-01-24
---

# Exercício 2.5.4: War Room - CVE Crítico em Produção

## 📋 Enunciado
CVE crítico publicado em lib que você usa em produção. Simule resposta de incidente.

### Cenário
**09:00 Segunda-feira**: CVE-2024-1234 publicado (log4j-like)
- Severidade: **Critical (10.0 CVSS)**
- Biblioteca: `express-jwt 7.0.0`
- Sua app usa: `express-jwt 7.0.0` ✅ (afetada!)
- Exploit: Já público (GitHub PoC disponível)
- Patch: Versão 7.0.1 disponível

### Requisitos
1. Verificar impacto (seu sistema usa a lib afetada?)
2. Avaliar exposição (funcionalidade exposta na internet?)
3. Criar plano de ação (correção, workaround, rollback)
4. Executar correção em PRODUÇÃO
5. Comunicar stakeholders

---

## ✅ Resposta Esperada

### 1. Verificação de Impacto (0-15min)

```bash
# 1.1 Verificar se seu sistema usa a lib
grep -r "express-jwt" package.json
# Output: "express-jwt": "^7.0.0" ✅ Afetado!

# 1.2 Versão exata instalada
npm list express-jwt
# Output: express-jwt@7.0.0 ⚠️ Versão vulnerável!

# 1.3 Onde é usado no código?
grep -r "expressjwt" src/
# Output:
# src/middleware/auth.js:5: const { expressjwt } = require('express-jwt');
# src/routes/api.js:12: app.use('/api', expressjwt({ secret }));

# 1.4 Avaliar exposição
# Funcionalidade: Autenticação JWT em todas as rotas /api/*
# Exposição: Público (internet-facing)
# Criticidade: ALTA (bypass de auth = acesso total)
```

**Conclusão Impacto**: 🔴 **CRÍTICO** - Sistema afetado, exposto na internet, exploit público.

---

### 2. Plano de Ação (15-30min)

**War Room iniciado**: Slack #incident-cve-2024-1234

**Participantes**:
- Incident Commander: Security Lead
- Tech Lead: Backend Lead
- Comms: CTO
- On-call: SRE Engineer

**Plano de Ação:**

| Ação | Responsável | Prazo | Status |
|------|-------------|-------|--------|
| 1. Validar CVE (é real?) | Security Lead | 09:15 | ✅ Done |
| 2. Verificar impacto interno | Backend Lead | 09:30 | ✅ Afetado |
| 3. Testar patch (7.0.1) em staging | Backend Lead | 10:00 | ⏳ In Progress |
| 4. Deploy hotfix em produção | SRE Engineer | 10:30 | ⏳ Pending |
| 5. Validar correção | Security Lead | 11:00 | ⏳ Pending |
| 6. Comunicar clientes | CTO | 11:30 | ⏳ Pending |
| 7. Post-mortem | Todos | 16:00 | ⏳ Pending |

**Workaround temporário** (enquanto patch não testado):
- WAF rule: Bloquear payloads suspeitos (regex)
- Rate limiting agressivo: 10 req/min por IP
- Alertas: Monitorar logs de auth failures

---

### 3. Correção (Hotfix)

```bash
# 3.1 Branch de hotfix
git checkout -b hotfix/cve-2024-1234

# 3.2 Atualizar dependência
npm install express-jwt@7.0.1
npm audit  # Verificar se corrigiu

# Output:
found 0 vulnerabilities ✅

# 3.3 Testar localmente
npm test
# Output: 142 tests passing ✅

# 3.4 Deploy para staging
npm run deploy:staging

# 3.5 Smoke test em staging
curl -H "Authorization: Bearer fake-token" https://staging.api.com/api/users
# Output: 401 Unauthorized ✅ (auth funcionando)

# 3.6 Validação de segurança (tentar exploit)
curl -H "Authorization: Bearer $(cat exploit-payload.txt)" https://staging.api.com/api/users
# Output: 401 Unauthorized ✅ (exploit não funciona)

# 3.7 Deploy para produção (fast-track)
git add package.json package-lock.json
git commit -m "fix(security): CVE-2024-1234 - atualizar express-jwt 7.0.0 → 7.0.1"
git push origin hotfix/cve-2024-1234

# 3.8 Merge direto para main (aprovação Security Lead)
gh pr create --title "HOTFIX: CVE-2024-1234" --base main --head hotfix/cve-2024-1234
gh pr merge --admin --squash

# 3.9 Deploy automático (CI/CD)
# GitHub Actions detecta merge → deploy produção

# 3.10 Validar produção
curl -I https://api.com/api/health
# Output: 200 OK ✅

# 3.11 Validar CVE corrigido
snyk test --severity-threshold=critical
# Output: ✓ no vulnerabilities found ✅
```

**Timeline real:**
- 09:00: CVE publicado
- 09:15: Impacto confirmado
- 09:30: War Room iniciado
- 10:00: Patch testado em staging
- 10:30: Deploy em produção
- 11:00: Validação completa
- **Total: 2h do CVE ao fix em produção** ⏱️

---

### 4. Comunicação

**4.1 Comunicação Interna** (Slack #incidents):

```
🔴 INCIDENT RESOLVED 🔴

CVE-2024-1234 (Critical) em express-jwt foi corrigido em produção.

Timeline:
- 09:00: CVE publicado
- 09:30: War Room iniciado
- 10:30: Hotfix deployado em produção
- 11:00: Validação completa

Impacto: Nenhum (nenhum exploit detectado nos logs)
RCA: Agendado para 16:00 hoje

Obrigado ao time de resposta rápida! 🎉
```

**4.2 Comunicação Externa** (se necessário):

```
Assunto: Security Update - Sistema XYZ

Prezados clientes,

Em 24/01/2024, identificamos e corrigimos uma vulnerabilidade de segurança em uma biblioteca de terceiros utilizada no Sistema XYZ.

**Ação tomada:**
- Vulnerabilidade corrigida em 2 horas após publicação
- Sistema auditado (nenhum exploit detectado)
- Patch aplicado em produção às 10:30

**Impacto:**
- Nenhum dado foi comprometido
- Nenhuma ação necessária por parte dos clientes

**Compromisso:**
- Continuaremos monitorando vulnerabilidades 24/7
- Processo de resposta rápida validado

Para dúvidas: security@empresa.com

Att,
Time de Segurança
```

---

### 5. Post-Mortem (mesmo dia)

```markdown
## Post-Mortem: CVE-2024-1234

**Data**: 24/01/2024  
**Severidade**: Critical  
**Duração**: 2h (09:00 - 11:00)  

### O que aconteceu?
CVE crítico publicado em express-jwt. Sistema afetado e exposto na internet.

### Timeline
- 09:00: CVE publicado
- 09:15: Impacto confirmado (sistema afetado)
- 09:30: War Room iniciado
- 10:00: Patch testado em staging
- 10:30: Deploy produção
- 11:00: Validação completa

### O que funcionou bem? ✅
1. Detecção rápida (15min)
2. War Room eficiente (roles claros)
3. Pipeline de deploy rápido (CI/CD)
4. Comunicação transparente

### O que não funcionou? ❌
1. Monitoramento proativo não detectou antes (dependemos de CVE público)
2. Não tínhamos SBOM atualizado (demoramos para validar impacto)
3. Workaround temporário não foi aplicado (WAF rules não prontas)

### Action Items
- [ ] Implementar Snyk monitoramento 24/7 (alerta antes de CVE público)
- [ ] Gerar SBOM automaticamente em cada release (CI/CD)
- [ ] Preparar WAF rules genéricas (playbook de workarounds)
- [ ] Drill de resposta a CVE (trimestral)
```

---

## 🎓 Pontos para Monitores

### Conceitos-Chave
1. **War Room**: Resposta coordenada a incidente crítico
2. **CVSS Score**: Sistema de scoring (10.0 = crítico)
3. **Hotfix**: Deploy emergencial (bypass de processo normal)
4. **Post-Mortem**: Análise blameless de incidente

### Erros Comuns

**Erro 1: "Não validou se sistema realmente afetado (assumiu que sim)"**
- **Feedback**: "Nem todo CVE afeta seu sistema. Valide: 1) Versão exata (`npm list lib`), 2) Funcionalidade vulnerável é usada? (leia CVE details), 3) Exposição (internet-facing?). Falso alarme gera fadiga de alerta."

**Erro 2: "Deployou patch direto em produção (sem testar)"**
- **Feedback**: "Mesmo em emergência, TESTE antes de produção. Staging test (5min) pode evitar downtime (30min). Se não tem staging: 1) Crie (mesmo que Docker Compose local), 2) Smoke test básico (health check), 3) Rollback plan (antes de deploy). Pressa ≠ imprudência."

**Erro 3: "War Room caótico (todos falando, ninguém decidindo)"**
- **Feedback**: "War Room precisa de Incident Commander (IC): pessoa que DECIDE. IC define: quem faz o quê, prioridades, timeline. Sem IC: reunião improdutiva. Nomeie IC no início (geralmente Security/SRE Lead)."

**Erro 4: "Não comunicou stakeholders (descobriram por Twitter)"**
- **Feedback**: "Comunicação é CRÍTICA. Comunique: 1) Interno (time aware), 2) Liderança (CEO/CTO cientes), 3) Clientes (se afeta eles). Silêncio = desconfiança. Seja transparente: 'Detectamos, estamos corrigindo, sem impacto detectado até agora'."

**Erro 5: "Não fez post-mortem (perdeu aprendizado)"**
- **Feedback**: "Post-mortem é onde você APRENDE. Não pule! Faça no mesmo dia (memória fresca). Focus: o que aprendemos? (não quem errou). Action items concretos: 'Implementar Snyk monitoring' (não 'ser mais cuidadoso')."

**Erro 6: "Patch disponível mas aplicou workaround (não corrigiu root cause)"**
- **Feedback**: "Workaround (WAF, rate limit) é TEMPORÁRIO. Se patch disponível: aplique! Workaround ≠ correção. Use workaround apenas se: 1) Patch não existe, 2) Patch tem breaking changes (precisa testar mais), 3) Enquanto testa patch. Sempre corrija root cause."

### Feedback Construtivo

**Para resposta profissional:**
> "Excelente resposta a incidente! War Room organizado, patch deployado em 2h, comunicação transparente, post-mortem completo. Isso é maturidade em security operations. Próximo nível: 1) Drill trimestral (simule CVE), 2) Playbooks de resposta (automatize), 3) Monitoramento proativo (Snyk/Dependabot alertas)."

**Para resposta funcional:**
> "Boa resposta! Patch aplicado, sistema seguro. Para profissionalizar: 1) War Room mais estruturado (IC, roles), 2) Comunicação aos stakeholders (não apenas técnico), 3) Post-mortem com action items (aprendizados), 4) Timeline documentado (para auditoria). Técnico correto, agora processo."

---

**Última atualização**: 2026-01-24  
**Elaborado por**: Joelma Prestes Ferreira e Yago Palhano  
**Revisado por**: [A definir]
