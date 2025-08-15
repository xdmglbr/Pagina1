/* script.js */
// Verificar se CryptoJS está disponível
if (typeof CryptoJS === 'undefined') {
  console.error('CryptoJS não encontrado. Carregando de CDN...');
  const script = document.createElement('script');
  script.src = 'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js';
  script.async = true;
  document.head.appendChild(script);
}

async function getClientMac() {
  try {
    for (let i = 0; i < 2; i++) {
      const response = await fetch('/getClientMac', {
        method: 'GET',
      });
      if (response.ok) {
        const data = await response.json(); // Espera JSON com campos 'mac' e 'ipv6'
        const macAddress = data.mac || "unknown"; // Extrai MAC ou usa padrão
        const ipv6Address = data.ipv6 || "unknown"; // Extrai IPv6 ou usa padrão
        if (macAddress !== "unknown") {
          console.log(`MAC recebido do servidor: ${macAddress}, IPv6: ${ipv6Address}`);
          return { macAddress, ipv6Address };
        }
      }
      await new Promise(resolve => setTimeout(resolve, 500)); // Espera 500ms antes de tentar novamente
    }
    console.error("MAC não obtido após tentativas");
    return { macAddress: "unknown", ipv6Address: "unknown" };
  } catch (error) {
    console.error("Erro ao buscar o MAC e IPv6:", error);
    return { macAddress: "unknown", ipv6Address: "unknown" };
  }
}

// Função para formatar data e hora atuais
// - Retorna objeto com `time` (ex.: "21:04:00 GMT-0300") e `date` (ex.: "18-05-2025").
function getFormattedTime() {
  const currentDate = new Date();
  const timeZoneOffset = -currentDate.getTimezoneOffset() / 60;

  const hours = String(currentDate.getHours()).padStart(2, '0');
  const minutes = String(currentDate.getMinutes()).padStart(2, '0');
  const seconds = String(currentDate.getSeconds()).padStart(2, '0');
  const time = `${hours}:${minutes}:${seconds}`;

  const day = String(currentDate.getDate()).padStart(2, '0');
  const month = String(currentDate.getMonth() + 1).padStart(2, '0');
  const year = currentDate.getFullYear();
  const date = `${day}-${month}-${year}`;

  const timeZoneString = timeZoneOffset >= 0 ? `GMT+${timeZoneOffset * 100}` : `GMT${timeZoneOffset * 100}`;

  return {
    time: `${time} ${timeZoneString}`,
    date: date
  };
}

// Função para gerar UUID compatível com navegadores antigos
function generateUUID() {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        return crypto.randomUUID();
    }
    
    // Fallback para navegadores que não suportam crypto.randomUUID()
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Função para coletar informações do cliente
// - Combina MAC, IPv6, Canvas Fingerprint, geolocalização, e dados do navegador em um log.
// - Envia o log para o servidor em /log?file=log.txt.
async function getInfo(canvasFingerprint) {
  const dateTime = getFormattedTime();
  const { macAddress, ipv6Address } = await getClientMac();

  // Gera hash único combinando MAC e Canvas Fingerprint
  const uniqueString = `${macAddress}${canvasFingerprint}`;
  const uniqueHash = CryptoJS.MD5(uniqueString).toString(CryptoJS.enc.Base64).substring(0, 8);

  // Obtém localização via /getLocation
  let location = "N/A";
  try {
    const response = await fetch('/getLocation', { timeout: 2000 });
    if (response.ok) {
      const loc = await response.text();
      if (loc !== "N/A" && loc.includes(",")) {
        location = loc; // Formato: -22.961325,-47.202652
      }
    }
  } catch (error) {
    console.error("Erro ao obter localização:", error);
  }

  // Coleta informações do navegador
  const info = {
    time: dateTime.time,
    date: dateTime.date,
    localIP: location.hostname,
    ipv6: ipv6Address,
    userAgent: navigator.userAgent,
    screenResolution: `${screen.width}x${screen.height}`,
    webGLVendor: '',
    webGLRenderer: '',
    fonts: getFonts(),
    touchSupport: 'ontouchstart' in window ? 'Sim' : 'Não',
    hardwareConcurrency: navigator.hardwareConcurrency || 'Indisponível',
    plugins: navigator.plugins.length > 0 ? Array.from(navigator.plugins).map(p => p.name).join(', ') : 'Nenhum plugin',
    ip: '',
    hostname: '',
    city: '',
    region: '',
    country: '',
    loc: '',
    org: '',
    postal: '',
    timezone: ''
  };

  // Configura WebGL
  const canvas = document.createElement('canvas');
  const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
  if (gl) {
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (debugInfo) {
      info.webGLVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
      info.webGLRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    } else {
      console.warn("WEBGL_debug_renderer_info não está disponível.");
    }
  } else {
    console.warn("WebGL não é suportado neste navegador.");
  }

  // Captura geolocalização via ipinfo.io
  await captureGeolocation(info);

  // Formata o log
  const logContent = `ID:${uniqueHash}, Lat/Long: ${location}, MAC: ${macAddress}, Canvas Fingerprint: ${canvasFingerprint}, Time: ${info.time}, Date: ${info.date}, Local IP: ${info.localIP}, IPv6: ${info.ipv6}, User Agent: ${info.userAgent}, Screen Resolution: ${info.screenResolution}, WebGL Vendor: ${info.webGLVendor || 'Não disponível'}, WebGL Renderer: ${info.webGLRenderer || 'Não disponível'}, Fonts: ${info.fonts}, Touch Support: ${info.touchSupport}, Hardware Concurrency: ${info.hardwareConcurrency}, Plugins: ${info.plugins}, IP: ${info.ip}, Hostname: ${info.hostname}, City: ${info.city}, Region: ${info.region}, Country: ${info.country}, Location: ${info.loc}, Organization: ${info.org}, Postal: ${info.postal}, Timezone: ${info.timezone}`;

  // Criptografa e envia o log para o servidor
  try {
    // Gerar nonce único
    const nonce = generateNonce();
    const timestamp = Date.now();
    
    // Criptografar dados
    const encryptedData = await encryptData(logContent);
    
    const response = await fetch('/log?file=log.txt', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Security-Timestamp': timestamp,
        'X-Security-Nonce': btoa(String.fromCharCode(...nonce)),
        'X-Security-Mode': getOperationMode(),
        'X-Security-Version': SECURITY_CONFIG.ENCRYPTION_VERSION,
        'X-Request-ID': generateUUID()
      },
      body: encryptedData,
    });
    if (response.ok) {
      console.log("Log criptografado enviado e salvo com sucesso no servidor.");
    } else {
      console.error("Erro ao enviar o log:", response.statusText);
    }
  } catch (error) {
    console.error("Erro ao enviar o log:", error);
  }
}

// Função para inicializar o Canvas Fingerprint
// - Gera um hash único baseado no canvas e exibe no elemento #fingerprint.
// - Chama getInfo para coletar e enviar dados.
function initFingerprint() {
  const canvasFingerprint = generateCanvasFingerprint();
  const hash = CryptoJS.MD5(canvasFingerprint).toString(CryptoJS.enc.Base64).substring(0, 8);
  document.getElementById('fingerprint').innerText = `Canvas Fingerprint: ${hash}`;
  getInfo(hash);
}

// Função para gerar Canvas Fingerprint
// - Cria uma imagem de canvas e gera um hash MD5 baseado nos dados da imagem.
function generateCanvasFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const context = canvas.getContext('2d');
    context.clearRect(0, 0, canvas.width, canvas.height);
    context.textBaseline = "top";
    context.font = "14px Arial, sans-serif";
    context.fillStyle = "#000";
    context.fillText("Fingerprint Test", 2, 2);
    const dataUrl = canvas.toDataURL();
    return CryptoJS.MD5(dataUrl).toString(CryptoJS.enc.Base64).substring(0, 8);
  } catch (e) {
    return 'unknown';
  }
}

// Função para detectar fontes instaladas
// - Verifica a presença de fontes comuns comparando larguras de texto.
function getFonts() {
  const fontList = ['Arial', 'Verdana', 'Helvetica', 'Times New Roman', 'Courier New'];
  const detectedFonts = [];
  const baseSize = 16;

  fontList.forEach(font => {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    context.font = `16px ${font}`;
    if (context.measureText('m').width !== baseSize) {
      detectedFonts.push(font);
    }
  });

  return detectedFonts.join(', ');
}

// Função para capturar geolocalização via ipinfo.io
// - Preenche campos de IP público, cidade, país, etc., no objeto info.
async function captureGeolocation(info) {
  try {
    const response = await fetch('https://ipinfo.io/json?token=YOUR_API_TOKEN');
    const data = await response.json();
    const { ipv6Address } = await getClientMac();
    info.ipv6 = ipv6Address;

    if (data.error) {
      console.error("Erro ao obter geolocalização via ipinfo.io: ", data.error);
    } else {
      info.ip = data.ip;
      info.hostname = data.hostname || '';
      info.city = data.city;
      info.region = data.region;
      info.country = data.country;
      info.loc = data.loc;
      info.org = data.org;
      info.postal = data.postal || '';
      info.timezone = data.timezone;
      console.log(`Geolocalização obtida: IP=${info.ip}, Hostname=${info.hostname}, Cidade=${info.city}, País=${info.country}`);
    }
  } catch (error) {
    console.error("Erro ao acessar a API ipinfo.io: ", error.message);
  }
}

// Função para formatar data e hora
// - Usada no log de compras para formatar a data agendada (ex.: "21:04 18/05/2025").
function formatDateTime(dateTime) {
  const date = new Date(dateTime);
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const year = date.getFullYear();
  return `${hours}:${minutes} ${day}/${month}/${year}`;
}

// Evento para finalizar compra
// - Valida o carrinho e campos, coleta MAC/IPv6, e envia log para /log?file=agenda.txt.
document.getElementById('finalizar-compra-btn').addEventListener('click', async () => {
  const carrinhoItensElement = document.getElementById('carrinho-itens');
  if (carrinhoItensElement.children.length === 0) {
    showNotification('Seu carrinho está vazio.', false);
    return;
  }

  const userName = document.getElementById('usuario-nome').value.trim();
  const enderecoRua = document.getElementById('endereco-rua').value.trim();
  const dataAgendada = document.getElementById('data-agendada').value.trim();
  const cartItems = Array.from(document.getElementById('carrinho-itens').children).map(item => item.textContent).join(', ');
  const totalValue = document.getElementById('carrinho-total').textContent;

  if (!userName || !enderecoRua || !dataAgendada) {
    showNotification('Por favor, preencha todos os campos obrigatórios antes de finalizar a compra.', false);
    return;
  }

  let location = "N/A";
  try {
    const response = await fetch('/getLocation', { timeout: 2000 });
    if (response.ok) {
      const loc = await response.text();
      if (loc !== "N/A" && loc.includes(",")) {
        location = loc.replace(',', ' ');
      }
    }
  } catch (error) {
    console.error("Erro ao obter localização:", error);
  }

  const formattedDateTime = formatDateTime(dataAgendada);
  const { macAddress, ipv6Address } = await getClientMac();
  const canvasFingerprint = document.getElementById('fingerprint').innerText.split(': ')[1];

  const uniqueString = `${macAddress}${canvasFingerprint}`;
  const uniqueHash = CryptoJS.MD5(uniqueString).toString(CryptoJS.enc.Base64).substring(0, 8);

  const logContent = `
    ID:${uniqueHash},
    MAC: ${macAddress},
    IPv6: ${ipv6Address},
    Canvas Fingerprint: ${canvasFingerprint},
    Nome: ${userName},
    Endereço da Rua: ${enderecoRua},
    Lat/Long: ${location},
    Time e Data: ${new Date().toLocaleString()},
    Data Agendada: ${formattedDateTime},
    Itens no Carrinho: ${cartItems},
    Total: ${totalValue}
  `;

  console.log(logContent);

  try {
    // Gerar nonce único
    const nonce = generateNonce();
    const timestamp = Date.now();
    
    // Criptografar dados
    const encryptedData = await encryptData(logContent);
    
    const response = await fetch('/log?file=agenda.txt', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Security-Timestamp': timestamp,
        'X-Security-Nonce': btoa(String.fromCharCode(...nonce)),
        'X-Security-Mode': getOperationMode(),
        'X-Security-Version': SECURITY_CONFIG.ENCRYPTION_VERSION,
        'X-Request-ID': generateUUID()
      },
      body: encryptedData,
    });

    if (response.ok) {
      console.log("Log criptografado enviado e salvo com sucesso no servidor.");
      setTimeout(() => {
        const audio = new Audio('/success.mp3');
        audio.play().catch(error => {
          console.error("Erro ao tocar o áudio:", error);
        });
      }, 500);
    } else {
      console.error("Erro ao enviar o log:", response.statusText);
    }
  } catch (error) {
    console.error("Erro ao enviar o log:", error);
  }
});

// Função para exibir notificações
// - Mostra mensagens de erro ou sucesso na interface (usada em finalizar-compra-btn).
function showNotification(message, isSuccess) {
  const notification = document.createElement('div');
  notification.className = `notification ${isSuccess ? 'success' : 'error'}`;
  notification.textContent = message;
  document.body.appendChild(notification);
  setTimeout(() => notification.remove(), 3000);
}

// --- Funcionalidades do Chat (adaptadas de script2.js) ---

// Declara variáveis globais para o chat
// - `ws`: Objeto WebSocket para conexão com ws://4.3.2.1:81.
// - `username`: Nome do usuário, armazenado em localStorage.
let ws;
let username = localStorage.getItem('username');
// Áudio de notificação para novas mensagens
const notificationSound = new Audio('/sounds/notification.mp3');

// Chave base compartilhada entre todos os clientes (ainda segura devido ao salt e IV)
const SHARED_BASE_KEY = 'shared-key-v1-2024';

// Funções de criptografia com salt dinâmico e chave derivada
function generateSimpleKey() {
  const timestamp = Date.now().toString();
  const random = Math.random().toString(36).substring(2);
  return timestamp + '-' + random;
}

function generateSessionKey(messageKey) {
  // Usa uma combinação de SHARED_BASE_KEY e messageKey para derivar a chave
  const salt = CryptoJS.SHA256(messageKey).toString();
  const iterations = 1000;
  const derivedKey = CryptoJS.PBKDF2(SHARED_BASE_KEY, salt, {
    keySize: 256/32,
    iterations: iterations
  });
  return {
    key: derivedKey.toString(),
    salt: salt,
    iterations: iterations
  };
}

function simpleEncrypt(text, messageKey) {
  try {
    // Gera uma chave de sessão para esta mensagem específica
    const sessionData = generateSessionKey(messageKey);
    
    // Adiciona um IV (vetor de inicialização) aleatório
    const iv = CryptoJS.lib.WordArray.random(128/8);
    
    // Criptografa usando a chave de sessão e o IV
    const encrypted = CryptoJS.AES.encrypt(text, sessionData.key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });

    // Combina IV, messageKey e mensagem criptografada
    const combined = {
      iv: iv.toString(),
      messageKey: messageKey,
      content: encrypted.toString()
    };

    return btoa(JSON.stringify(combined));
  } catch (e) {
    console.error('Erro na criptografia:', e);
    return text;
  }
}

function simpleDecrypt(encryptedData) {
  try {
    console.log('Iniciando descriptografia simples...');
    // Decodifica os dados combinados
    const combined = JSON.parse(atob(encryptedData));
    console.log('Dados combinados decodificados:', combined);
    
    // Recria a chave de sessão usando o messageKey original
    const sessionData = generateSessionKey(combined.messageKey);
    console.log('Chave de sessão recriada');

    // Descriptografa usando a chave de sessão e o IV original
    const decrypted = CryptoJS.AES.decrypt(combined.content, sessionData.key, {
      iv: CryptoJS.enc.Hex.parse(combined.iv),
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });

    const result = decrypted.toString(CryptoJS.enc.Utf8);
    if (!result) {
      throw new Error('Resultado da descriptografia está vazio');
    }
    console.log('Mensagem descriptografada com sucesso:', result);
    return result;
  } catch (e) {
    console.error('Erro na descriptografia simples:', e);
    throw new Error('Falha na descriptografia');
  }
}

// Variáveis para gerenciamento de sessão
let sessionId = null;
let sessionRenewalInterval = null;
const SESSION_RENEWAL_TIME = 240000; // 4 minutos (antes do timeout de 5 minutos)

// Função para renovar a sessão
async function renewSession() {
  if (!ws || ws.readyState !== WebSocket.OPEN || !sessionId) {
    console.log('WebSocket não está conectado ou sessão inválida. Tentando reconectar...');
    await connectWebSocket();
    return;
  }

  try {
    const renewalData = {
      type: 'renew_session',
      sessionId: sessionId,
      timestamp: Date.now()
    };
    
    ws.send(JSON.stringify(renewalData));
    console.log('Solicitação de renovação de sessão enviada');
  } catch (error) {
    console.error('Erro ao renovar sessão:', error);
    // Tenta reconectar se houver erro
    await connectWebSocket();
  }
}

// Função para iniciar o intervalo de renovação
function startSessionRenewal() {
  if (sessionRenewalInterval) {
    clearInterval(sessionRenewalInterval);
  }
  sessionRenewalInterval = setInterval(renewSession, SESSION_RENEWAL_TIME);
}

// Função para parar o intervalo de renovação
function stopSessionRenewal() {
  if (sessionRenewalInterval) {
    clearInterval(sessionRenewalInterval);
    sessionRenewalInterval = null;
  }
}

// Função para conectar ao WebSocket
// - Estabelece conexão com ws://4.3.2.1:81 e configura eventos (open, message, error, close).
async function connectWebSocket() {
  try {
    // Gerar ID de sessão único
    sessionId = generateSimpleKey();

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//4.3.2.1:81`;
    
    console.log('Tentando conectar ao WebSocket:', wsUrl);
    ws = new WebSocket(wsUrl);

    ws.onopen = async () => {
      console.log('WebSocket conectado com sucesso');
      
      // Handshake com timestamp para prevenir replay attacks
      const handshakeData = {
        type: btoa('handshake'),
        sessionId: btoa(sessionId),
        username: btoa(username),
        timestamp: Date.now()
      };
      
      ws.send(JSON.stringify(handshakeData));
      console.log('Handshake enviado');
      
      // Iniciar renovação automática da sessão
      startSessionRenewal();
      
      const connectionMessage = document.createElement('div');
      connectionMessage.innerHTML = '<em>✅ Conexão estabelecida com criptografia</em>';
      document.getElementById('chatbox').appendChild(connectionMessage);
      scrollToBottom();

      // Habilitar envio de mensagens
      const sendButton = document.getElementById('send');
      const messageInput = document.getElementById('message');
      if (sendButton && messageInput.value.trim()) {
        sendButton.disabled = false;
        sendButton.style.display = 'block';
        adjustSendButtonPosition();
      }
    };

    ws.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data);

        // Caso novo: mensagem criptografada no campo payload
        if (data.payload) {
          console.log('Processando mensagem criptografada...');
          // Descriptografa o payload (JSON interno)
          const decryptedPayload = await decryptData(data.payload);
          console.log('Payload descriptografado:', decryptedPayload);
          const innerData = JSON.parse(decryptedPayload);

          // Renovação automática
          if (innerData.type === "reauthenticate") {
            console.warn("Sessão expirada. Reautenticando...");
            connectWebSocket();
            return;
          }

          // Decodificar metadados base64
          const type = innerData.type ? atob(innerData.type) : undefined;
          const sessionIdMsg = innerData.sessionId ? atob(innerData.sessionId) : undefined;
          const sender = innerData.sender ? atob(innerData.sender) : undefined;

          // Decodificar chave pública base64
          if (type === 'handshake_response' && innerData.publicKey) {
            const serverPublicKey = atob(innerData.publicKey);
            // ... use serverPublicKey ...
          }

          // Decodificar mensagem
          if (type === 'message' && innerData.message) {
            const decryptedMessage = simpleDecrypt(innerData.message);
            addMessageToChatbox(sender, decryptedMessage);
            notificationSound.play().catch(() => {});
            return;
          }
        } else {
          // Compatibilidade com formato antigo
          // 1º: Renovação automática
          if (data.type === "reauthenticate") {
            console.warn("Sessão expirada. Reautenticando...");
            connectWebSocket();
            return;
          }
          // 2º: Decodificar metadados base64
          const type = data.type ? atob(data.type) : undefined;
          const sessionIdMsg = data.sessionId ? atob(data.sessionId) : undefined;
          const sender = data.sender ? atob(data.sender) : undefined;
          // 3º: Decodificar chave pública base64
          if (type === 'handshake_response' && data.publicKey) {
            const serverPublicKey = atob(data.publicKey);
            // ... use serverPublicKey ...
          }
          // 4º: Decodificar mensagem
          if (type === 'message' && data.message) {
            const decryptedMessage = simpleDecrypt(data.message);
            addMessageToChatbox(sender, decryptedMessage);
            notificationSound.play().catch(() => {});
            return;
          }
        }
      } catch (error) {
        console.error('Erro ao processar mensagem:', error);
        console.error('Dados recebidos:', event.data);
      }
    };

    ws.onerror = (error) => {
      console.error('Erro na conexão WebSocket:', error);
      const errorMessage = document.createElement('div');
      errorMessage.innerHTML = '<em>Erro na conexão WebSocket</em>';
      document.getElementById('chatbox').appendChild(errorMessage);
      scrollToBottom();
    };

    ws.onclose = () => {
      console.log('Conexão WebSocket fechada');
      stopSessionRenewal(); // Parar renovação ao fechar conexão
      const closeMessage = document.createElement('div');
      closeMessage.innerHTML = '<em>Conexão fechada. Reconectando...</em>';
      document.getElementById('chatbox').appendChild(closeMessage);
      scrollToBottom();
      setTimeout(connectWebSocket, 1000);
    };
  } catch (error) {
    console.error('Erro ao inicializar WebSocket:', error);
    stopSessionRenewal(); // Parar renovação em caso de erro
    const errorMessage = document.createElement('div');
    errorMessage.innerHTML = '<em>Erro ao conectar ao chat. Tentando novamente em 5 segundos...</em>';
    document.getElementById('chatbox').appendChild(errorMessage);
    scrollToBottom();
    setTimeout(connectWebSocket, 5000);
  }
}

// Função para adicionar mensagem ao chat
// - Insere mensagem no #chatbox com formato "<strong>sender:</strong> message".
function addMessageToChatbox(sender, message) {
  const messageDiv = document.createElement('div');
  messageDiv.innerHTML = `<strong>${sender}:</strong> ${message}`;
  document.getElementById('chatbox').appendChild(messageDiv);
  scrollToBottom();
}

// Função para enviar mensagem
// - Envia JSON com `sender` e `message` via WebSocket e exibe localmente.
async function sendMessage() {
  if (!username) {
    const nameInputBtn = document.getElementById('name-input-btn');
    if (nameInputBtn) {
      nameInputBtn.style.display = 'block';
    }
    document.getElementById('message').blur();
    
    const warningMessage = document.createElement('div');
    warningMessage.innerHTML = '<em>Por favor, defina seu nome antes de enviar mensagens</em>';
    document.getElementById('chatbox').appendChild(warningMessage);
    scrollToBottom();
    return;
  }
  
  const messageInput = document.getElementById('message');
  const message = messageInput.value.trim();
  if (message === "") return;

  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.log('WebSocket não está conectado. Tentando reconectar...');
    const reconnectMessage = document.createElement('div');
    reconnectMessage.innerHTML = '<em>Reconectando ao chat...</em>';
    document.getElementById('chatbox').appendChild(reconnectMessage);
    scrollToBottom();
    
    try {
      await connectWebSocket();
      await new Promise(resolve => setTimeout(resolve, 1000));
    } catch (error) {
      console.error('Erro ao reconectar:', error);
      const errorMessage = document.createElement('div');
      errorMessage.innerHTML = '<em>Erro ao conectar ao chat. Tente novamente.</em>';
      document.getElementById('chatbox').appendChild(errorMessage);
      scrollToBottom();
      return;
    }
  }

  try {
    // Gerar uma chave única para esta mensagem
    const messageKey = generateSimpleKey();
    
    // Criptografar a mensagem
    const encryptedMessage = simpleEncrypt(message, messageKey);

    // Montar o JSON original
    const originalData = {
      type: btoa('message'),
      sessionId: btoa(sessionId),
      sender: btoa(username),
      message: encryptedMessage,
      timestamp: Date.now()
    };

    // Criptografar o JSON inteiro e enviar como payload
    const encryptedPayload = await encryptData(JSON.stringify(originalData));
    const finalMessage = JSON.stringify({ payload: encryptedPayload });
    console.log('Enviando mensagem criptografada:', finalMessage.substring(0, 100) + '...');
    ws.send(finalMessage);

    // Mostrar mensagem localmente
    addMessageToChatbox(username, message);

    // Limpar e focar o input
    messageInput.value = '';
    const sendButton = document.getElementById('send');
    if (sendButton) {
      sendButton.disabled = true;
      sendButton.style.display = "none";
    }
    messageInput.focus();
  } catch (error) {
    console.error('Erro ao enviar mensagem:', error);
    const errorMessage = document.createElement('div');
    errorMessage.innerHTML = '<em>Erro ao enviar mensagem. Tente novamente.</em>';
    document.getElementById('chatbox').appendChild(errorMessage);
    scrollToBottom();
  }
}

// Função para rolar o chat para a última mensagem
function scrollToBottom() {
  const chatbox = document.getElementById('chatbox');
  chatbox.scrollTop = chatbox.scrollHeight;
}

// Função para alternar visibilidade do chat
// - Mostra/esconde #chatbox-container e ajusta botão flutuante (☰/X).
function toggleChat() {
  const chatboxContainer = document.getElementById('chatbox-container');
  const floatButton = document.querySelector('.float-button');
  if (chatboxContainer.style.display === "none") {
    chatboxContainer.style.display = "block";
    document.getElementById('message').focus();
    floatButton.textContent = "X";
    document.getElementById('send').style.display = document.getElementById('message').value.trim() === "" ? "none" : "block";
    adjustSendButtonPosition();
    scrollToBottom();
  } else {
    chatboxContainer.style.display = "none";
    floatButton.textContent = "☰";
    document.getElementById('send').style.display = "none";
    document.getElementById('message').blur();
  }
}

// Função para ajustar posição do botão de envio
// - Posiciona o botão #send fixo no canto inferior direito.
function adjustSendButtonPosition() {
  const floatButton = document.querySelector('.float-button');
  const floatButtonRect = floatButton.getBoundingClientRect();
  const sendButton = document.getElementById('send');
  sendButton.style.position = "fixed";
  sendButton.style.bottom = '20px';
  sendButton.style.right = '20px';
  sendButton.style.top = '';
  sendButton.style.left = '';
}

// Inicialização do chat
(function () {
  const chatboxContainer = document.getElementById('chatbox-container');
  const messageInput = document.getElementById('message');
  const sendButton = document.getElementById('send');
  const floatButton = document.querySelector('.float-button');

  // Botão para limpar nome
  const clearNameButton = document.createElement('button');
  clearNameButton.id = 'clear-name-btn';
  clearNameButton.textContent = 'Limpar Nome';
  clearNameButton.onclick = () => {
    localStorage.removeItem('username');
    console.log('Nome limpo. Digite seu nome novamente.');
    username = null;
    messageInput.focus();
    // Mostrar botão de definir nome novamente
    nameInputButton.style.display = 'block';
  };
  document.body.appendChild(clearNameButton);

  // Botão para definir nome
  const nameInputButton = document.createElement('button');
  nameInputButton.id = 'name-input-btn';
  nameInputButton.textContent = 'Definir Nome';
  nameInputButton.className = 'name-input-btn';
  nameInputButton.style.display = username ? 'none' : 'block';
  nameInputButton.onclick = () => {
    const nameInputContainer = document.createElement('div');
    nameInputContainer.className = 'name-input-container';
    nameInputContainer.innerHTML = `
      <input type="text" id="name-input" placeholder="Digite seu nome" style="margin-right: 10px;">
      <button id="save-name-btn">Salvar</button>
    `;
    document.body.appendChild(nameInputContainer);

    const saveNameBtn = document.getElementById('save-name-btn');
    const nameInput = document.getElementById('name-input');
    
    saveNameBtn.onclick = () => {
      const newUsername = nameInput.value.trim();
      if (newUsername) {
        username = newUsername;
        localStorage.setItem('username', username);
        nameInputButton.style.display = 'none';
        nameInputContainer.remove();
        messageInput.focus();
        
        // Adicionar mensagem no chat informando que o nome foi definido
        const usernameMessage = document.createElement('div');
        usernameMessage.innerHTML = `<em>Nome definido como: ${username}</em>`;
        document.getElementById('chatbox').appendChild(usernameMessage);
        scrollToBottom();
        
        // Habilitar envio de mensagens
        if (ws && ws.readyState === WebSocket.OPEN) {
          sendButton.disabled = false;
          sendButton.style.display = 'block';
          adjustSendButtonPosition();
        } else {
          console.log('Reconectando WebSocket após definir nome...');
          connectWebSocket();
        }
      }
    };

    // Permitir envio com Enter
    nameInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        saveNameBtn.click();
      }
    });
  };
  document.body.appendChild(nameInputButton);

  // Eventos do chat
  sendButton.onclick = () => sendMessage();

  messageInput.addEventListener('input', () => {
    if (!username) {
      sendButton.disabled = true;
      sendButton.style.display = 'none';
      nameInputButton.style.display = 'block';
      return;
    }
    
    sendButton.disabled = messageInput.value.trim() === "";
    sendButton.style.display = sendButton.disabled ? "none" : "block";
    if (!sendButton.disabled) {
      adjustSendButtonPosition();
    }
  });

  messageInput.addEventListener('focus', () => {
    if (!username) {
      nameInputButton.style.display = 'block';
      messageInput.blur();
    }
  });

  floatButton.onclick = () => toggleChat();

  window.addEventListener('resize', () => {
    if (chatboxContainer.style.display !== "none") {
      adjustSendButtonPosition();
    }
  });

  // Verificar nome de usuário e estado da conexão
  if (username) {
    console.log('Nome de usuário encontrado:', username);
    nameInputButton.style.display = 'none';
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      console.log('Iniciando conexão WebSocket...');
      connectWebSocket();
    }
  } else {
    console.log('Nome de usuário não definido');
    sendButton.disabled = true;
    sendButton.style.display = 'none';
  }
})();

// Inicialização geral
// - Executa ao carregar a página, iniciando o Canvas Fingerprint.
document.addEventListener('DOMContentLoaded', () => {
  initFingerprint();
});

// Funções de criptografia para comunicação segura
const crypto = window.crypto || window.msCrypto;

// Converte array buffer para base64
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Converte base64 para array buffer
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Importa chave AES-256
async function importAESKey(keyData) {
    return await crypto.subtle.importKey(
        "raw",
        keyData,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
}

// Criptografa dados
async function encryptData(data) {
    try {
        const key = "log-secure-key-2024"; // Chave compartilhada com ESP32
        let encrypted = "";
        
        for (let i = 0; i < data.length; i++) {
            const keyChar = key.charCodeAt(i % key.length);
            const dataChar = data.charCodeAt(i);
            const encryptedChar = dataChar ^ keyChar;
            encrypted += String.fromCharCode(encryptedChar);
        }
        
        // Codificar em base64 para evitar problemas com caracteres especiais
        const base64Result = btoa(encrypted);
        console.log('Dados criptografados com sucesso, tamanho:', base64Result.length);
        return base64Result;
    } catch (error) {
        console.error('Erro na criptografia:', error);
        throw error;
    }
}

// Descriptografa dados
async function decryptData(encryptedBase64) {
    try {
        const key = "log-secure-key-2024"; // Chave compartilhada com ESP32
        const encrypted = atob(encryptedBase64);
        let decrypted = "";
        
        for (let i = 0; i < encrypted.length; i++) {
            const keyChar = key.charCodeAt(i % key.length);
            const encryptedChar = encrypted.charCodeAt(i);
            const decryptedChar = encryptedChar ^ keyChar;
            decrypted += String.fromCharCode(decryptedChar);
        }
        
        console.log('Dados descriptografados com sucesso:', decrypted.substring(0, 100));
        return decrypted;
    } catch (error) {
        console.error('Erro na descriptografia:', error);
        throw error;
    }
}

// Constantes de segurança otimizadas para cenários específicos
const SECURITY_CONFIG = {
    KEY_ROTATION_INTERVAL: 3600000, // 1 hora
    // Rate limiting otimizado por modo de operação
    AP_MODE_MAX_REQUESTS_PER_MINUTE: 120,    // 2-4 pessoas: 30-60 req/pessoa/min
    STA_MODE_MAX_REQUESTS_PER_MINUTE: 1800,  // 20-30 pessoas: 60-90 req/pessoa/min
    REQUEST_TIMEOUT: 10000, // 10 segundos
    COMPRESSION_LEVEL: 6, // Nível de compressão (0-9)
    ENCRYPTION_VERSION: 'v2',
    AP_MODE_KEY: 'ap-secure-key-2024',
    STA_MODE_KEY: 'sta-secure-key-2024',
    // Cache otimizado
    CACHE_CLEANUP_INTERVAL: 30000,  // Limpar cache a cada 30 segundos (mais frequente)
    CACHE_ENTRY_TTL: 90000,         // Entradas expiram em 90 segundos (mais longo)
    // Rate limiting por IP (para múltiplos usuários)
    MAX_REQUESTS_PER_IP_PER_MINUTE: 100
};

// Cache de chaves rotativas
let keyCache = {
    current: null,
    next: null,
    lastRotation: Date.now()
};

// Cache de requisições otimizado para múltiplos usuários
const requestCache = new Map();
const ipRequestCache = new Map(); // Cache por IP para rate limiting individual
let requestCount = 0;
let lastRequestReset = Date.now();

// Função para obter IP do cliente (melhorada)
async function getClientIP() {
    try {
        // Tentar obter IP via /getClientMac (que retorna informações do cliente)
        const response = await fetch('/getClientMac', {
            method: 'GET',
            timeout: 2000
        });
        
        if (response.ok) {
            const data = await response.json();
            // Usar uma combinação de MAC e timestamp como identificador único
            const identifier = (data.mac || 'unknown') + '_' + Date.now().toString(36);
            return identifier.substring(0, 16); // Limitar tamanho
        }
    } catch (error) {
        // Fallback em caso de erro
        console.debug('Não foi possível obter IP do cliente, usando fallback');
    }
    
    // Fallback: usar combinação de user agent e timestamp
    const fallbackId = navigator.userAgent.substring(0, 8) + '_' + Date.now().toString(36);
    return fallbackId.substring(0, 16);
}

// Função para verificar rate limiting otimizada
async function checkRateLimit() {
    const now = Date.now();
    const clientIP = await getClientIP();
    const mode = getOperationMode();
    
    // Reset contadores globais a cada minuto
    if (now - lastRequestReset >= 60000) {
        requestCount = 0;
        lastRequestReset = now;
    }
    
    // Rate limiting por IP
    if (!ipRequestCache.has(clientIP)) {
        ipRequestCache.set(clientIP, { count: 0, lastReset: now });
    }
    
    const ipData = ipRequestCache.get(clientIP);
    if (now - ipData.lastReset >= 60000) {
        ipData.count = 0;
        ipData.lastReset = now;
    }
    
    // Limites baseados no modo de operação
    const maxRequestsPerMinute = mode === 'AP' ? 
        SECURITY_CONFIG.AP_MODE_MAX_REQUESTS_PER_MINUTE : 
        SECURITY_CONFIG.STA_MODE_MAX_REQUESTS_PER_MINUTE;
    
    // Verificar limite global
    if (requestCount >= maxRequestsPerMinute) {
        throw new Error(`Limite global de requisições excedido (${maxRequestsPerMinute}/min)`);
    }
    
    // Verificar limite por IP
    if (ipData.count >= SECURITY_CONFIG.MAX_REQUESTS_PER_IP_PER_MINUTE) {
        throw new Error(`Limite de requisições por IP excedido (${SECURITY_CONFIG.MAX_REQUESTS_PER_IP_PER_MINUTE}/min)`);
    }
    
    // Incrementar contadores
    requestCount++;
    ipData.count++;
    
    // Adicionar entrada ao cache com timestamp
    const requestId = generateUUID();
    requestCache.set(requestId, {
        timestamp: now,
        clientIP: clientIP,
        mode: mode
    });
}

// Função para limpar cache otimizada
function cleanupCache() {
    const now = Date.now();
    let cleanedEntries = 0;
    
    // Limpar cache de requisições
    for (const [key, value] of requestCache.entries()) {
        if (now - value.timestamp > SECURITY_CONFIG.CACHE_ENTRY_TTL) {
            requestCache.delete(key);
            cleanedEntries++;
        }
    }
    
    // Limpar cache de IPs antigos (mais de 5 minutos)
    for (const [ip, data] of ipRequestCache.entries()) {
        if (now - data.lastReset > 300000) { // 5 minutos
            ipRequestCache.delete(ip);
        }
    }
    
    // Log de limpeza (apenas em debug)
    if (cleanedEntries > 0 && typeof console !== 'undefined' && console.debug) {
        console.debug(`Cache limpo: ${cleanedEntries} entradas removidas`);
    }
}

// Inicializar limpeza automática do cache
setInterval(cleanupCache, SECURITY_CONFIG.CACHE_CLEANUP_INTERVAL);

// Função para gerar valores aleatórios compatível
function getRandomValues(array) {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        return crypto.getRandomValues(array);
    }
    
    // Fallback para navegadores que não suportam crypto.getRandomValues()
    for (let i = 0; i < array.length; i++) {
        array[i] = Math.floor(Math.random() * 256);
    }
    return array;
}

// Função para verificar se crypto.subtle está disponível
function isCryptoSubtleSupported() {
    return typeof crypto !== 'undefined' && crypto.subtle;
}

// Função para gerar chave de criptografia
async function generateEncryptionKey() {
    if (!isCryptoSubtleSupported()) {
        console.warn('crypto.subtle não suportado, usando criptografia XOR');
        return null;
    }
    
    const keyMaterial = new Uint8Array(32);
    getRandomValues(keyMaterial);
    return await crypto.subtle.importKey(
        "raw",
        keyMaterial,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
}

// Função para gerar nonce único
function generateNonce() {
    const nonce = new Uint8Array(12);
    getRandomValues(nonce);
    return nonce;
}

// Função para rotacionar chaves
async function rotateKeys() {
    const now = Date.now();
    if (now - keyCache.lastRotation >= SECURITY_CONFIG.KEY_ROTATION_INTERVAL) {
        keyCache.next = await generateEncryptionKey();
        keyCache.current = keyCache.next;
        keyCache.lastRotation = now;
        console.log('Chaves de criptografia rotacionadas');
    }
}

// Função para comprimir dados
async function compressData(data) {
    const textEncoder = new TextEncoder();
    const dataBuffer = textEncoder.encode(JSON.stringify(data));
    
    // Usar CompressionStream se disponível
    if (typeof CompressionStream !== 'undefined') {
        const cs = new CompressionStream('deflate');
        const writer = cs.writable.getWriter();
        await writer.write(dataBuffer);
        await writer.close();
        
        const chunks = [];
        const reader = cs.readable.getReader();
        while (true) {
            const {value, done} = await reader.read();
            if (done) break;
            chunks.push(value);
        }
        return new Blob(chunks);
    }
    
    // Fallback para dados não comprimidos
    return new Blob([dataBuffer]);
}

// Função para descomprimir dados
async function decompressData(blob) {
    if (typeof DecompressionStream !== 'undefined') {
        const ds = new DecompressionStream('deflate');
        const writer = ds.writable.getWriter();
        const data = await blob.arrayBuffer();
        await writer.write(data);
        await writer.close();
        
        const chunks = [];
        const reader = ds.readable.getReader();
        while (true) {
            const {value, done} = await reader.read();
            if (done) break;
            chunks.push(value);
        }
        const decompressed = new Blob(chunks);
        return JSON.parse(await decompressed.text());
    }
    return JSON.parse(await blob.text());
}

// Função para verificar modo de operação
function getOperationMode() {
    return window.location.hostname === '4.3.2.1' ? 'AP' : 'STA';
}

// Função para obter chave de operação
function getOperationKey() {
    return getOperationMode() === 'AP' ? SECURITY_CONFIG.AP_MODE_KEY : SECURITY_CONFIG.STA_MODE_KEY;
}

// Função melhorada de requisição segura
async function secureHttpRequest(url, data) {
    try {
        // Verificar rate limiting
        await checkRateLimit();
        
        // Preparar dados seguros
        const secureData = {
            version: SECURITY_CONFIG.ENCRYPTION_VERSION,
            timestamp: Date.now(),
            nonce: generateNonce(),
            mode: getOperationMode(),
            data: data
        };
        
        // Criptografar dados usando XOR (mais compatível)
        const encryptedData = await encryptData(JSON.stringify(secureData));
        
        // Adicionar headers de segurança
        const headers = {
            'Content-Type': 'application/octet-stream',
            'X-Security-Timestamp': secureData.timestamp,
            'X-Security-Nonce': btoa(String.fromCharCode(...secureData.nonce)),
            'X-Security-Mode': secureData.mode,
            'X-Security-Version': secureData.version,
            'X-Request-ID': generateUUID()
        };
        
        // Configurar timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), SECURITY_CONFIG.REQUEST_TIMEOUT);
        
        // Enviar requisição
        const response = await fetch(url, {
            method: 'POST',
            headers: headers,
            body: encryptedData,
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        // Processar resposta
        const encryptedResponse = await response.text();
        const decryptedResponse = await decryptData(encryptedResponse);
        
        return JSON.parse(decryptedResponse);
        
    } catch (error) {
        console.error('Erro na requisição segura:', error);
        if (error.name === 'AbortError') {
            throw new Error('Timeout na requisição');
        }
        throw error;
    }
}
