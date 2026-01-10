/**
 * Configuração do EmailJS para envio de exercícios
 * 
 * IMPORTANTE: Configure suas credenciais do EmailJS antes de usar
 * 
 * Passos para configuração:
 * 1. Criar conta no EmailJS (https://emailjs.com)
 * 2. Configurar um Service (Gmail, Outlook, etc.)
 * 3. Criar um Template de email
 * 4. Adicionar suas credenciais abaixo
 */

const EMAILJS_CONFIG = {
  // Substitua pelos seus valores do EmailJS
  serviceId: 'SEU_SERVICE_ID', // Ex: 'gmail_service'
  templateId: 'SEU_TEMPLATE_ID', // Ex: 'template_exercicio'
  publicKey: 'SEU_PUBLIC_KEY', // Ex: 'abc123xyz'
  
  // Email padrão para receber submissões (usado como fallback)
  defaultEmail: 'exercicios@cwi.com.br',
  
  // Configurações adicionais
  timeout: 15000, // Timeout em milissegundos (15 segundos)
  
  // Validações
  maxFileSize: 10 * 1024 * 1024, // 10MB em bytes
  allowedFileTypes: ['.pdf', '.docx', '.doc', '.md', '.txt'],
  
  // Mensagens de erro (em português)
  messages: {
    success: 'Exercício enviado com sucesso! Você receberá uma confirmação por email.',
    error: 'Erro ao enviar exercício. Por favor, tente novamente ou entre em contato com suporte.',
    validation: {
      required: 'Todos os campos são obrigatórios.',
      email: 'Por favor, insira um email válido.',
      fileSize: 'O arquivo deve ter no máximo 10MB.',
      fileType: 'Apenas arquivos .pdf, .docx, .doc, .md ou .txt são aceitos.',
      noFile: 'Por favor, selecione um arquivo para enviar.'
    }
  }
};

/**
 * Inicializa o EmailJS
 * Carrega o script do EmailJS se ainda não estiver carregado
 */
function initEmailJS() {
  if (typeof emailjs === 'undefined') {
    const script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js';
    script.async = true;
    script.onload = () => {
      if (EMAILJS_CONFIG.publicKey && EMAILJS_CONFIG.publicKey !== 'SEU_PUBLIC_KEY') {
        emailjs.init(EMAILJS_CONFIG.publicKey);
      }
    };
    document.head.appendChild(script);
  } else {
    if (EMAILJS_CONFIG.publicKey && EMAILJS_CONFIG.publicKey !== 'SEU_PUBLIC_KEY') {
      emailjs.init(EMAILJS_CONFIG.publicKey);
    }
  }
}

/**
 * Valida o formulário antes de enviar
 */
function validateSubmissionForm(formData) {
  const errors = [];
  
  // Validar email do aluno
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!formData.email || !emailRegex.test(formData.email)) {
    errors.push(EMAILJS_CONFIG.messages.validation.email);
  }
  
  // Validar nome do aluno
  if (!formData.nome || formData.nome.trim().length < 3) {
    errors.push('Nome deve ter pelo menos 3 caracteres.');
  }
  
  // Validar arquivo
  if (!formData.arquivo) {
    errors.push(EMAILJS_CONFIG.messages.validation.noFile);
  } else {
    // Validar tamanho do arquivo
    if (formData.arquivo.size > EMAILJS_CONFIG.maxFileSize) {
      errors.push(EMAILJS_CONFIG.messages.validation.fileSize);
    }
    
    // Validar tipo do arquivo
    const fileName = formData.arquivo.name.toLowerCase();
    const hasValidExtension = EMAILJS_CONFIG.allowedFileTypes.some(ext => 
      fileName.endsWith(ext.toLowerCase())
    );
    if (!hasValidExtension) {
      errors.push(EMAILJS_CONFIG.messages.validation.fileType);
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors: errors
  };
}

/**
 * Envia o exercício via EmailJS
 */
async function enviarExercicio(formData, exerciseInfo) {
  // Validar configuração
  if (EMAILJS_CONFIG.serviceId === 'SEU_SERVICE_ID' || 
      EMAILJS_CONFIG.templateId === 'SEU_TEMPLATE_ID' ||
      EMAILJS_CONFIG.publicKey === 'SEU_PUBLIC_KEY') {
    throw new Error('EmailJS não configurado. Por favor, configure EMAILJS_CONFIG em emailjs-config.js');
  }
  
  // Validar formulário
  const validation = validateSubmissionForm(formData);
  if (!validation.isValid) {
    throw new Error(validation.errors.join(' '));
  }
  
  // Garantir que EmailJS está inicializado
  if (typeof emailjs === 'undefined') {
    await new Promise((resolve) => {
      initEmailJS();
      // Aguardar até EmailJS estar disponível
      const checkInterval = setInterval(() => {
        if (typeof emailjs !== 'undefined') {
          clearInterval(checkInterval);
          resolve();
        }
      }, 100);
    });
  }
  
  // Ler arquivo como base64
  const fileBase64 = await readFileAsBase64(formData.arquivo);
  
  // Preparar template params
  const templateParams = {
    to_email: formData.monitorEmail || EMAILJS_CONFIG.defaultEmail,
    aluno_nome: formData.nome,
    aluno_email: formData.email,
    exercicio_titulo: exerciseInfo.titulo,
    exercicio_id: exerciseInfo.id,
    exercicio_modulo: exerciseInfo.modulo,
    exercicio_lesson: exerciseInfo.lesson,
    data_submissao: new Date().toLocaleString('pt-BR'),
    arquivo_nome: formData.arquivo.name,
    arquivo_base64: fileBase64,
    mensagem_adicional: formData.mensagem || ''
  };
  
  // Enviar email
  try {
    const response = await emailjs.send(
      EMAILJS_CONFIG.serviceId,
      EMAILJS_CONFIG.templateId,
      templateParams
    );
    return response;
  } catch (error) {
    console.error('Erro ao enviar email via EmailJS:', error);
    throw error;
  }
}

/**
 * Lê arquivo como base64
 */
function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const base64 = reader.result.split(',')[1]; // Remove data:type;base64, prefix
      resolve(base64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

// Inicializar EmailJS quando o script carregar
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initEmailJS);
} else {
  initEmailJS();
}

// Exportar funções para uso global (se necessário)
if (typeof window !== 'undefined') {
  window.EmailJSConfig = EMAILJS_CONFIG;
  window.enviarExercicio = enviarExercicio;
  window.validateSubmissionForm = validateSubmissionForm;
  window.initEmailJS = initEmailJS;
}
