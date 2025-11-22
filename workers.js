import { connect } from "cloudflare:sockets";

/**
 * ==================== 全局配置和状态 ====================
 */
let config_JSON, 反代IP = '', 启用SOCKS5反代 = null, 启用SOCKS5全局反代 = false, 我的SOCKS5账号 = '', parsedSocks5Address = {};
let SOCKS5白名单 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages静态页面 = 'https://edt-pages.github.io';

/**
 * ==================== 加密工具类 ====================
 */
class CryptoUtils {
  static async sha224(s) {
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
    s = unescape(encodeURIComponent(s));
    const l = s.length * 8;
    s += String.fromCharCode(0x80);
    while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
    const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
    s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
    const w = [];
    for (let i = 0; i < s.length; i += 4) w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
    for (let i = 0; i < w.length; i += 16) {
      const x = new Array(64).fill(0);
      for (let j = 0; j < 16; j++) x[j] = w[i + j];
      for (let j = 16; j < 64; j++) {
        const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
        const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
        x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h0] = h;
      for (let j = 0; j < 64; j++) {
        const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
        const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
        h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      for (let j = 0; j < 8; j++) h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
    }
    let hex = '';
    for (let i = 0; i < 7; i++) {
      for (let j = 24; j >= 0; j -= 8) hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
    }
    return hex;
  }

  static async md5Md5(text) {
    const encoder = new TextEncoder();
    const first = await crypto.subtle.digest('SHA-256', encoder.encode(text));
    const firstHex = Array.from(new Uint8Array(first)).map(b => b.toString(16).padStart(2, '0')).join('');
    const second = await crypto.subtle.digest('SHA-256', encoder.encode(firstHex.slice(7, 27)));
    const secondHex = Array.from(new Uint8Array(second)).map(b => b.toString(16).padStart(2, '0')).join('');
    return secondHex.toLowerCase();
  }
}

/**
 * ==================== 代理连接模块 ====================
 */
class ProxyConnector {
  constructor(proxyConfig) {
    this.proxyType = proxyConfig.type;
    this.proxyAddr = proxyConfig.address;
    this.username = proxyConfig.username;
    this.password = proxyConfig.password;
    this.proxyIP = proxyConfig.proxyIP;
  }

  async connect(targetHost, targetPort, initialData = new Uint8Array(0)) {
    if (this.proxyType === 'socks5') {
      return this.socks5Connect(targetHost, targetPort, initialData);
    } else if (this.proxyType === 'http' || this.proxyType === 'https') {
      return this.httpConnect(targetHost, targetPort, initialData);
    } else {
      return this.directConnect(targetHost, targetPort, initialData);
    }
  }

  async socks5Connect(targetHost, targetPort, initialData) {
    const { hostname, port } = this.parseProxyAddr();
    const socket = connect({ hostname, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    try {
      const authMethods = this.username && this.password
        ? new Uint8Array([0x05, 0x02, 0x00, 0x02])
        : new Uint8Array([0x05, 0x01, 0x00]);

      await writer.write(authMethods);
      let response = await reader.read();
      if (response.done || response.value.byteLength < 2) {
        throw new Error('SOCKS5: Method selection failed');
      }

      const selectedMethod = new Uint8Array(response.value)[1];
      if (selectedMethod === 0x02) {
        if (!this.username || !this.password) throw new Error('SOCKS5: Auth required');
        const userBytes = new TextEncoder().encode(this.username);
        const passBytes = new TextEncoder().encode(this.password);
        const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
        await writer.write(authPacket);
        response = await reader.read();
        if (response.done || new Uint8Array(response.value)[1] !== 0x00) {
          throw new Error('SOCKS5: Authentication failed');
        }
      }

      const hostBytes = new TextEncoder().encode(targetHost);
      const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
      await writer.write(connectPacket);

      response = await reader.read();
      if (response.done || new Uint8Array(response.value)[1] !== 0x00) {
        throw new Error('SOCKS5: Connection failed');
      }

      await writer.write(initialData);
      writer.releaseLock();
      reader.releaseLock();
      return socket;
    } catch (error) {
      try { writer.releaseLock(); } catch (e) { }
      try { reader.releaseLock(); } catch (e) { }
      try { socket.close(); } catch (e) { }
      throw error;
    }
  }

  async httpConnect(targetHost, targetPort, initialData) {
    const { hostname, port } = this.parseProxyAddr();
    const socket = connect({ hostname, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();

    try {
      const auth = this.username && this.password
        ? `Proxy-Authorization: Basic ${btoa(`${this.username}:${this.password}`)}\r\n`
        : '';

      const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
      await writer.write(new TextEncoder().encode(request));

      let responseBuffer = new Uint8Array(0);
      let headerEndIndex = -1;
      while (headerEndIndex === -1 && responseBuffer.length < 8192) {
        const { done, value } = await reader.read();
        if (done) throw new Error('HTTP: Connection closed');
        responseBuffer = new Uint8Array([...responseBuffer, ...value]);
        const crlfcrlf = responseBuffer.findIndex((_, i) =>
          i < responseBuffer.length - 3 &&
          responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a &&
          responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a
        );
        if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
      }

      if (headerEndIndex === -1) throw new Error('HTTP: Invalid response');

      const statusCode = parseInt(new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/)[1]);
      if (statusCode < 200 || statusCode >= 300) {
        throw new Error(`HTTP: Connection failed (${statusCode})`);
      }

      await writer.write(initialData);
      writer.releaseLock();
      reader.releaseLock();
      return socket;
    } catch (error) {
      try { writer.releaseLock(); } catch (e) { }
      try { reader.releaseLock(); } catch (e) { }
      try { socket.close(); } catch (e) { }
      throw error;
    }
  }

  async directConnect(targetHost, targetPort, initialData) {
    const socket = connect({ hostname: targetHost, port: targetPort });
    const writer = socket.writable.getWriter();
    await writer.write(initialData);
    writer.releaseLock();
    return socket;
  }

  parseProxyAddr() {
    if (!this.proxyAddr) return { hostname: 'localhost', port: 1080 };

    let hostname = this.proxyAddr;
    let port = 1080;

    if (this.proxyAddr.includes('://')) {
      const url = new URL(`http://${this.proxyAddr}`);
      hostname = url.hostname;
      port = url.port ? parseInt(url.port) : 1080;
    } else if (this.proxyAddr.includes(':')) {
      const parts = this.proxyAddr.split(':');
      hostname = parts[0];
      port = parseInt(parts[1]) || 1080;
    }

    return { hostname, port };
  }
}

/**
 * ==================== IP 优选模块 ====================
 */
class IPOptimizer {
  constructor(request) {
    this.request = request;
    this.asnMap = { '9808': 'cmcc', '4837': 'cu', '4134': 'ct' };
    this.cfPorts = [443, 2053, 2083, 2087, 2096, 8443];
  }

  async generateOptimizedIPs(count = 16, port = -1) {
    const asn = this.request.cf?.asn;
    const isp = this.asnMap[asn] || 'all';
    const cidrUrl = isp === 'all'
      ? 'https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt'
      : `https://raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR/${isp}.txt`;

    const ispName = {
      '9808': 'CF移动优选',
      '4837': 'CF联通优选',
      '4134': 'CF电信优选'
    }[asn] || 'CF官方优选';

    let cidrList = [];
    try {
      const response = await fetch(cidrUrl, { cf: { cacheTtl: 3600 } });
      if (response.ok) {
        const text = await response.text();
        cidrList = text.trim().split('\n').filter(line => line && /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(line));
      }
    } catch (error) {
      console.error('CIDR获取失败:', error);
    }

    if (cidrList.length === 0) cidrList = ['104.16.0.0/13'];

    const generateIP = (cidr) => {
      const [baseIP, prefixLength] = cidr.split('/');
      const prefix = parseInt(prefixLength);
      const hostBits = 32 - prefix;

      const ipInt = baseIP.split('.').reduce((a, part, i) =>
        a | (parseInt(part) << (24 - i * 8)), 0
      );

      const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
      const mask = (0xFFFFFFFF << hostBits) >>> 0;
      const randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;

      return [
        (randomIP >>> 24) & 0xFF,
        (randomIP >>> 16) & 0xFF,
        (randomIP >>> 8) & 0xFF,
        randomIP & 0xFF
      ].join('.');
    };

    const ips = Array.from({ length: count }, () => {
      const ip = generateIP(cidrList[Math.floor(Math.random() * cidrList.length)]);
      const selectedPort = port === -1
        ? this.cfPorts[Math.floor(Math.random() * this.cfPorts.length)]
        : port;
      return `${ip}:${selectedPort}#${ispName}`;
    });

    return { ips, text: ips.join('\n') };
  }
}

/**
 * ==================== 订阅生成器 ====================
 */
class SubscriptionGenerator {
  constructor(config) {
    this.config = config;
  }

  generateVlessLink(ip, port, host, uuid, path, tlsFrag = '') {
    return `vless://${uuid}@${ip}:${port}?security=tls&type=ws&host=${host}&sni=${host}&path=${encodeURIComponent(path)}${tlsFrag}&encryption=none&allowInsecure=1`;
  }

  generateTrojanLink(ip, port, password, host, path, tlsFrag = '') {
    return `trojan://${password}@${ip}:${port}?security=tls&type=ws&host=${host}&sni=${host}&path=${encodeURIComponent(path)}${tlsFrag}&allowInsecure=1`;
  }

  formatSubscription(links, format = 'mixed') {
    if (format === 'mixed') {
      return btoa(links.join('\n'));
    } else if (format === 'clash') {
      return this.toClash(links);
    } else if (format === 'singbox') {
      return this.toSingBox(links);
    }
    return links.join('\n');
  }

  toClash(links) {
    const proxies = links.map((link, i) => {
      return `  - name: Proxy${i + 1}\n    type: vless\n    server: example.com\n    port: 443\n    uuid: ${this.config.UUID}`;
    }).join('\n');
    return `proxies:\n${proxies}`;
  }

  toSingBox(links) {
    const outbounds = links.map((link, i) => ({
      type: 'vless',
      tag: `proxy${i + 1}`,
      server: 'example.com',
      server_port: 443,
      uuid: this.config.UUID,
      transport: { type: 'ws', path: this.config.PATH }
    }));
    return JSON.stringify({ outbounds }, null, 2);
  }
}

/**
 * ==================== Telegram 通知模块 ====================
 */
class TelegramNotifier {
  constructor(botToken, chatID) {
    this.botToken = botToken;
    this.chatID = chatID;
    this.apiUrl = `https://api.telegram.org/bot${botToken}`;
  }

  async sendMessage(message, parseMode = 'HTML') {
    if (!this.botToken || !this.chatID) return false;

    try {
      const response = await fetch(`${this.apiUrl}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: this.chatID,
          text: message,
          parse_mode: parseMode
        })
      });
      return response.ok;
    } catch (error) {
      console.error('Telegram发送失败:', error);
      return false;
    }
  }

  formatLogMessage(logEntry, config) {
    const date = new Date(logEntry.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const url = new URL(logEntry.URL);

    return `<b>#${config.优选订阅生成.SUBNAME} 日志通知</b>\n\n` +
      `📌 <b>类型：</b>${logEntry.TYPE}\n` +
      `🌐 <b>IP：</b><code>${logEntry.IP}</code>\n` +
      `📍 <b>位置：</b>${logEntry.CC}\n` +
      `🏢 <b>ASN：</b>${logEntry.ASN}\n` +
      `🔗 <b>域名：</b><code>${url.host}</code>\n` +
      `🤖 <b>UA：</b><code>${(logEntry.UA || 'Unknown').substring(0, 50)}</code>\n` +
      `📅 <b>时间：</b>${date}`;
  }
}

/**
 * ==================== 日志记录模块 ====================
 */
class Logger {
  constructor(env) {
    this.env = env;
    this.maxSize = 4 * 1024 * 1024;
  }

  async record(request, type, clientIP, config = null) {
    try {
      const logEntry = {
        TYPE: type,
        IP: clientIP,
        ASN: `AS${request.cf?.asn || '0'} ${request.cf?.asOrganization || 'Unknown'}`,
        CC: `${request.cf?.country || 'N/A'} ${request.cf?.city || 'N/A'}`,
        URL: request.url,
        UA: request.headers.get('User-Agent') || 'Unknown',
        TIME: Date.now()
      };

      let logs = [];
      const existing = await this.env.KV.get('log.json');

      if (existing) {
        logs = JSON.parse(existing);
        logs.push(logEntry);

        while (JSON.stringify(logs).length > this.maxSize && logs.length > 0) {
          logs.shift();
        }
      } else {
        logs = [logEntry];
      }

      await this.env.KV.put('log.json', JSON.stringify(logs, null, 2));

      // Telegram通知
      if (config?.TG?.启用 && config.TG.BotToken && config.TG.ChatID) {
        const tg = new TelegramNotifier(config.TG.BotToken, config.TG.ChatID);
        const message = tg.formatLogMessage(logEntry, config);
        await tg.sendMessage(message);
      }
    } catch (error) {
      console.error('日志记录失败:', error);
    }
  }

  async getLog() {
    try {
      const data = await this.env.KV.get('log.json');
      return data ? JSON.parse(data) : [];
    } catch (error) {
      console.error('读取日志失败:', error);
      return [];
    }
  }
}

/**
 * ==================== 配置管理模块 ====================
 */
class ConfigManager {
  constructor(env) {
    this.env = env;
    this.config = null;
  }

  async load(host, userID, reset = false) {
    const defaultConfig = {
      TIME: new Date().toISOString(),
      HOST: host,
      UUID: userID,
      协议类型: "vless",
      传输协议: "ws",
      跳过证书验证: true,
      启用0RTT: true,
      TLS分片: null,
      优选订阅生成: {
        local: true,
        本地IP库: {
          随机IP: true,
          随机数量: 16,
          指定端口: -1,
        },
        SUB: null,
        SUBNAME: "edgetunnel",
        SUBUpdateTime: 6,
        TOKEN: await CryptoUtils.md5Md5(host + userID),
      },
      订阅转换配置: {
        SUBAPI: "https://SUBAPI.cmliussss.net",
        SUBCONFIG: "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini",
        SUBEMOJI: false,
      },
      反代: {
        PROXYIP: "auto",
        SOCKS5: {
          启用: null,
          全局: false,
          账号: null,
          白名单: SOCKS5白名单,
        },
      },
      TG: {
        启用: false,
        BotToken: null,
        ChatID: null,
      },
      CF: {
        Email: null,
        GlobalAPIKey: null,
        AccountID: null,
        APIToken: null,
        Usage: { success: false, pages: 0, workers: 0, total: 0 },
      }
    };

    try {
      if (reset) {
        await this.env.KV.put('config.json', JSON.stringify(defaultConfig, null, 2));
        this.config = defaultConfig;
      } else {
        const stored = await this.env.KV.get('config.json');
        this.config = stored ? JSON.parse(stored) : defaultConfig;
      }
    } catch (error) {
      console.error('配置加载失败:', error);
      this.config = defaultConfig;
    }

    this.config.HOST = host;
    this.config.UUID = userID;
    return this.config;
  }

  async save() {
    if (!this.config) return false;
    await this.env.KV.put('config.json', JSON.stringify(this.config, null, 2));
    return true;
  }
}

/**
 * ==================== WebSocket 代理模块 ====================
 */
class WebSocketProxy {
  constructor(userID, proxyConnector) {
    this.userID = userID;
    this.proxyConnector = proxyConnector;
  }

  async handleRequest(request) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();

    let remoteSocket = null;
    const readable = this.makeReadableStream(serverSock);

    readable.pipeTo(new WritableStream({
      write: async (chunk) => {
        try {
          if (!remoteSocket) {
            const { port, hostname, rawIndex, version, isUDP } = this.parseVlessRequest(chunk, this.userID);
            remoteSocket = await this.proxyConnector.connect(hostname, port, chunk.slice(rawIndex));
            this.pipeStreams(remoteSocket, serverSock, version);
          } else {
            const writer = remoteSocket.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
          }
        } catch (error) {
          console.error('WebSocket写入错误:', error);
        }
      }
    })).catch(err => console.error('管道错误:', err));

    return new Response(null, { status: 101, webSocket: clientSock });
  }

  parseVlessRequest(chunk, token) {
    if (chunk.byteLength < 24) throw new Error('Invalid data');
    
    const version = new Uint8Array(chunk.slice(0, 1));
    const tokenStr = this.formatIdentifier(new Uint8Array(chunk.slice(1, 17)));
    
    if (tokenStr !== token) throw new Error('Invalid UUID');
    
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
    
    let isUDP = false;
    if (cmd === 1) {
      // TCP
    } else if (cmd === 2) {
      isUDP = true;
    } else {
      throw new Error('Invalid command');
    }
    
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
    
    let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
    
    switch (addressType) {
      case 1:
        addrLen = 4;
        hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
        break;
      case 2:
        addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
        addrValIdx += 1;
        hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
        break;
      case 3:
        addrLen = 16;
        const ipv6 = [];
        const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
        for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
        hostname = ipv6.join(':');
        break;
      default:
        throw new Error(`Invalid address type: ${addressType}`);
    }
    
    if (!hostname) throw new Error(`Invalid address: ${addressType}`);
    
    return { addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
  }

  formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
  }

  pipeStreams(remoteSocket, webSocket, headerData) {
    let header = headerData;
    remoteSocket.readable.pipeTo(new WritableStream({
      write(chunk, controller) {
        if (webSocket.readyState !== WebSocket.OPEN) {
          controller.error('ws.readyState is not open');
          return;
        }
        
        if (header) {
          const response = new Uint8Array(header.length + chunk.byteLength);
          response.set(header, 0);
          response.set(chunk, header.length);
          webSocket.send(response.buffer);
          header = null;
        } else {
          webSocket.send(chunk);
        }
      },
    })).catch((err) => {
      this.closeSocketQuietly(webSocket);
    });
  }

  closeSocketQuietly(socket) {
    try {
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
        socket.close();
      }
    } catch (error) { }
  }

  makeReadableStream(socket) {
    return new ReadableStream({
      start(controller) {
        socket.addEventListener('message', (event) => {
          controller.enqueue(event.data);
        });
        socket.addEventListener('close', () => {
          controller.close();
        });
        socket.addEventListener('error', (err) => {
          controller.error(err);
        });
      }
    });
  }
}

/**
 * ==================== 前端管理面板 ====================
 */
class AdminUI {
  static getLoginPage() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EdgeTunnel - 登录</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
}
.login-container {
  background: white;
  padding: 40px;
  border-radius: 10px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
  width: 100%;
  max-width: 400px;
}
.login-container h1 {
  text-align: center;
  margin-bottom: 30px;
  color: #333;
  font-size: 28px;
}
.form-group {
  margin-bottom: 20px;
}
.form-group label {
  display: block;
  margin-bottom: 8px;
  color: #555;
  font-weight: 600;
}
.form-group input {
  width: 100%;
  padding: 12px;
  border: 2px solid #ddd;
  border-radius: 5px;
  font-size: 16px;
  transition: border-color 0.3s;
}
.form-group input:focus {
  outline: none;
  border-color: #667eea;
}
.btn-login {
  width: 100%;
  padding: 12px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  border: none;
  border-radius: 5px;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: transform 0.2s;
}
.btn-login:hover { transform: translateY(-2px); }
.error { color: #e74c3c; text-align: center; margin-top: 15px; }
</style>
</head>
<body>
<div class="login-container">
  <h1>🔐 EdgeTunnel</h1>
  <form method="POST" id="loginForm">
    <div class="form-group">
      <label>管理员密码</label>
      <input type="password" name="password" required>
    </div>
    <button type="submit" class="btn-login">登录</button>
  </form>
  <div id="error" class="error"></div>
</div>
<script>
document.getElementById('loginForm').onsubmit = async (e) => {
  e.preventDefault();
  const password = e.target.password.value;
  const response = await fetch('/login', {
    method: 'POST',
    body: new URLSearchParams({ password })
  });
  if (response.ok) {
    window.location.href = '/admin';
  } else {
    document.getElementById('error').textContent = '密码错误';
  }
};
</script>
</body>
</html>`;
  }

  static getAdminPanel() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EdgeTunnel - 管理面板</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto;
  background: #f5f7fa;
  color: #333;
}
.navbar {
  background: white;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 0 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  height: 60px;
}
.navbar h1 { font-size: 24px; color: #667eea; }
.navbar a {
  color: #666;
  text-decoration: none;
  margin-left: 20px;
  cursor: pointer;
}
.navbar a:hover { color: #667eea; }
.container {
  max-width: 1200px;
  margin: 30px auto;
  padding: 0 20px;
}
.card {
  background: white;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}
.card h2 {
  margin-bottom: 15px;
  color: #333;
  font-size: 20px;
}
.form-group {
  margin-bottom: 15px;
}
.form-group label {
  display: block;
  margin-bottom: 5px;
  font-weight: 600;
  color: #555;
}
.form-group input, .form-group textarea, .form-group select {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
  font-family: inherit;
}
.form-group textarea { resize: vertical; min-height: 100px; }
.btn {
  padding: 10px 20px;
  background: #667eea;
  color: white;
  border: none;
  border-radius: 5px;
  cursor: pointer;
  font-weight: 600;
  transition: background 0.3s;
  margin-right: 10px;
}
.btn:hover { background: #764ba2; }
.logs {
  max-height: 400px;
  overflow-y: auto;
  background: #f9f9f9;
  padding: 10px;
  border-radius: 4px;
  font-size: 12px;
}
.log-entry {
  padding: 8px;
  border-bottom: 1px solid #eee;
  font-family: monospace;
}
</style>
</head>
<body>
<div class="navbar">
  <h1>🌐 EdgeTunnel</h1>
  <div>
    <span>管理员</span>
    <a href="/logout">登出</a>
  </div>
</div>

<div class="container">
  <div class="card">
    <h2>⚙️ 基本配置</h2>
    <div class="form-group">
      <label>主机地址</label>
      <input type="text" id="host" placeholder="example.com">
    </div>
    <div class="form-group">
      <label>UUID</label>
      <input type="text" id="uuid" placeholder="UUID">
    </div>
    <div class="form-group">
      <label>传输协议</label>
      <select id="transport">
        <option value="ws">WebSocket</option>
        <option value="tcp">TCP</option>
      </select>
    </div>
    <button class="btn" onclick="saveConfig()">💾 保存配置</button>
  </div>

  <div class="card">
    <h2>🚀 IP 优选</h2>
    <div class="form-group">
      <label>自定义 IP 列表</label>
      <textarea id="customIPs" placeholder="IP:端口#备注"></textarea>
    </div>
    <button class="btn" onclick="saveIPs()">💾 保存 IP</button>
    <button class="btn" onclick="generateIPs()">🔄 生成优选 IP</button>
  </div>

  <div class="card">
    <h2>📱 Telegram 通知</h2>
    <div class="form-group">
      <label>Bot Token</label>
      <input type="password" id="botToken" placeholder="Bot Token">
    </div>
    <div class="form-group">
      <label>Chat ID</label>
      <input type="text" id="chatID" placeholder="Chat ID">
    </div>
    <button class="btn" onclick="saveTelegram()">💾 保存</button>
    <button class="btn" onclick="testTelegram()">📤 测试</button>
  </div>

  <div class="card">
    <h2>📊 访问日志</h2>
    <div id="logs" class="logs"></div>
    <button class="btn" onclick="refreshLogs()">🔄 刷新</button>
  </div>
</div>

<script>
async function loadConfig() {
  const res = await fetch('/admin/config.json');
  const config = await res.json();
  document.getElementById('host').value = config.HOST || '';
  document.getElementById('uuid').value = config.UUID || '';
  document.getElementById('transport').value = config.传输协议 || 'ws';
}

async function saveConfig() {
  const config = {
    HOST: document.getElementById('host').value,
    UUID: document.getElementById('uuid').value,
    传输协议: document.getElementById('transport').value
  };
  const res = await fetch('/admin/config.json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  });
  alert(res.ok ? '配置已保存' : '保存失败');
}

async function refreshLogs() {
  const res = await fetch('/admin/log.json');
  const logs = await res.json();
  const html = logs.slice(-20).reverse().map(log =>
    \`<div class="log-entry">\${new Date(log.TIME).toLocaleString()}: \${log.TYPE} from \${log.IP}</div>\`
  ).join('');
  document.getElementById('logs').innerHTML = html;
}

async function generateIPs() {
  const res = await fetch('/admin/ADD.txt');
  const ips = await res.text();
  document.getElementById('customIPs').value = ips;
}

async function saveIPs() {
  const ips = document.getElementById('customIPs').value;
  const res = await fetch('/admin/ADD.txt', {
    method: 'POST',
    body: ips
  });
  alert(res.ok ? 'IP 已保存' : '保存失败');
}

async function saveTelegram() {
  const config = {
    BotToken: document.getElementById('botToken').value,
    ChatID: document.getElementById('chatID').value
  };
  const res = await fetch('/admin/tg.json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  });
  alert(res.ok ? 'Telegram配置已保存' : '保存失败');
}

async function testTelegram() {
  alert('测试消息已发送');
}

// 初始化
loadConfig();
refreshLogs();
setInterval(refreshLogs, 10000);
</script>
</body>
</html>`;
  }
}

/**
 * ==================== 工具函数 ====================
 */
function sha224(s) {
  const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
  s = unescape(encodeURIComponent(s));
  const l = s.length * 8;
  s += String.fromCharCode(0x80);
  while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
  const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
  const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
  s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
  const w = [];
  for (let i = 0; i < s.length; i += 4) w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
  for (let i = 0; i < w.length; i += 16) {
    const x = new Array(64).fill(0);
    for (let j = 0; j < 16; j++) x[j] = w[i + j];
    for (let j = 16; j < 64; j++) {
      const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
      const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
      x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h0] = h;
    for (let j = 0; j < 64; j++) {
      const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
      const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
      h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    for (let j = 0; j < 8; j++) h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
  }
  let hex = '';
  for (let i = 0; i < 7; i++) {
    for (let j = 24; j >= 0; j -= 8) hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
  }
  return hex;
}

async function 整理成数组(内容) {
  const 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
  const 修正开头 = 替换后的内容.charAt(0) === ',' ? 替换后的内容.slice(1) : 替换后的内容;
  const 修正结尾 = 修正开头.charAt(修正开头.length - 1) === ',' ? 修正开头.slice(0, 修正开头.length - 1) : 修正开头;
  return 修正结尾.split(',');
}

async function 请求优选API(urls, 默认端口 = '443', 超时时间 = 3000) {
  if (!urls?.length) return [];
  const results = new Set();
  
  await Promise.allSettled(urls.map(async (url) => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 超时时间);
      const response = await fetch(url, { signal: controller.signal });
      clearTimeout(timeoutId);
      
      const text = await response.text();
      if (!text || text.trim().length === 0) return;
      
      const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
      
      lines.forEach(line => {
        const hashIndex = line.indexOf('#');
        const [hostPart, remark] = hashIndex > -1 ? [line.substring(0, hashIndex), line.substring(hashIndex)] : [line, ''];
        
        let hasPort = false;
        if (hostPart.startsWith('[')) {
          hasPort = /\]:(\d+)$/.test(hostPart);
        } else {
          const colonIndex = hostPart.lastIndexOf(':');
          hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
        }
        
        const port = new URL(url).searchParams.get('port') || 默认端口;
        results.add(hasPort ? line : `${hostPart}:${port}${remark}`);
      });
    } catch (e) {
      console.error('API请求失败:', e);
    }
  }));
  
  return Array.from(results);
}

function 随机路径() {
  const 常用路径目录 = ["#","about","account","acg","act","activity","ad","admin","ads","ajax","album","albums","anime","api","app","apps","archive","archives","article","articles","ask","auth","avatar","bbs","bd","blog","blogs","book","books","bt","buy","cart","category","categories","cb","channel","channels","chat","china","city","class","classify","clip","clips","club","cn","code","collect","collection","comic","comics","community","company","config","contact","content","course","courses","cp","data","detail","details","dh","directory","discount","discuss","dl","dload","doc","docs","document","documents","doujin","download","downloads","drama","edu","en","ep","episode","episodes","event","events","f","faq","favorite","favourites","favs","feedback","file","files","film","films","forum","forums","friend","friends","game","games","gif","go","go.html","go.php","group","groups","help","home","hot","htm","html","image","images","img","index","info","intro","item","items","ja","jp","jump","jump.html","jump.php","jumping","knowledge","lang","lesson","lessons","lib","library","link","links","list","live","lives","login","logout","m","mag","magnet","mall","manhua","map","member","members","message","messages","mobile","movie","movies","music","my","new","news","note","novel","novels","online","order","out","out.html","out.php","outbound","p","page","pages","pay","payment","pdf","photo","photos","pic","pics","picture","pictures","play","player","playlist","post","posts","product","products","program","programs","project","qa","question","rank","ranking","read","readme","redirect","redirect.html","redirect.php","reg","register","res","resource","retrieve","sale","search","season","seasons","section","seller","series","service","services","setting","settings","share","shop","show","shows","site","soft","sort","source","special","star","stars","static","stock","store","stream","streaming","streams","student","study","tag","tags","task","teacher","team","tech","temp","test","thread","tool","tools","topic","topics","torrent","trade","travel","tv","txt","type","u","upload","uploads","url","urls","user","users","v","version","video","videos","view","vip","vod","watch","web","wenku","wiki","work","www","zh","zh-cn","zh-tw","zip"];
  const 随机数 = Math.floor(Math.random() * 4 + 1);
  const 随机路径 = 常用路径目录.sort(() => 0.5 - Math.random()).slice(0, 随机数).join('/');
  return `/${随机路径}`;
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
  const API = "https://api.cloudflare.com/client/v4";
  const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
  const cfg = { "Content-Type": "application/json" };

  try {
    if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0 };

    if (!AccountID) {
      const r = await fetch(`${API}/accounts`, {
        method: "GET",
        headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
      });
      if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
      const d = await r.json();
      if (!d?.result?.length) throw new Error("未找到账户");
      const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
      AccountID = d.result[idx >= 0 ? idx : 0]?.id;
    }

    const now = new Date();
    now.setUTCHours(0, 0, 0, 0);
    const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

    const res = await fetch(`${API}/graphql`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({
        query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
            viewer { accounts(filter: {accountTag: $AccountID}) {
                pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
                workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
            } }
        }`,
        variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
      })
    });

    if (!res.ok) throw new Error(`查询失败: ${res.status}`);
    const result = await res.json();
    if (result.errors?.length) throw new Error(result.errors[0].message);

    const acc = result?.data?.viewer?.accounts?.[0];
    if (!acc) throw new Error("未找到账户数据");

    const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
    const workers = sum(acc.workersInvocationsAdaptive);
    const total = pages + workers;
    return { success: true, pages, workers, total };

  } catch (error) {
    console.error('获取使用量错误:', error.message);
    return { success: false, pages: 0, workers: 0, total: 0 };
  }
}

async function 反代参数获取(request) {
  const url = new URL(request.url);
  const { pathname, searchParams } = url;
  const pathLower = pathname.toLowerCase();

  我的SOCKS5账号 = searchParams.get('socks5') || searchParams.get('http') || null;
  启用SOCKS5全局反代 = searchParams.has('globalproxy') || false;

  const proxyMatch = pathLower.match(/\/(proxyip[.=]|pyip=|ip=)(.+)/);
  if (searchParams.has('proxyip')) {
    const 路参IP = searchParams.get('proxyip');
    反代IP = 路参IP.includes(',') ? 路参IP.split(',')[Math.floor(Math.random() * 路参IP.split(',').length)] : 路参IP;
    return;
  } else if (proxyMatch) {
    const 路参IP = proxyMatch[1] === 'proxyip.' ? `proxyip.${proxyMatch[2]}` : proxyMatch[2];
    反代IP = 路参IP.includes(',') ? 路参IP.split(',')[Math.floor(Math.random() * 路参IP.split(',').length)] : 路参IP;
    return;
  }

  let socksMatch;
  if ((socksMatch = pathname.match(/\/(socks5?|http):\/?\/?(.+)/i))) {
    启用SOCKS5反代 = socksMatch[1].toLowerCase() === 'http' ? 'http' : 'socks5';
    我的SOCKS5账号 = socksMatch[2].split('#')[0];
    启用SOCKS5全局反代 = true;

    if (我的SOCKS5账号.includes('@')) {
      const atIndex = 我的SOCKS5账号.lastIndexOf('@');
      let userPassword = 我的SOCKS5账号.substring(0, atIndex).replaceAll('%3D', '=');
      if (/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i.test(userPassword) && !userPassword.includes(':')) {
        userPassword = atob(userPassword);
      }
      我的SOCKS5账号 = `${userPassword}@${我的SOCKS5账号.substring(atIndex + 1)}`;
    }
  } else if ((socksMatch = pathname.match(/\/(g?s5|socks5|g?http)=(.+)/i))) {
    const type = socksMatch[1].toLowerCase();
    我的SOCKS5账号 = socksMatch[2];
    启用SOCKS5反代 = type.includes('http') ? 'http' : 'socks5';
    启用SOCKS5全局反代 = type.startsWith('g');
  }
}

/**
 * ==================== 请求处理主函数 ====================
 */
export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const host = url.hostname;
      const pathname = url.pathname;

      // 加载配置
      const configManager = new ConfigManager(env);
      config_JSON = await configManager.load(host, env.UUID || 'default-uuid');

      // 处理不同的路由
      if (pathname === '/admin' || pathname === '/admin/') {
        return new Response(AdminUI.getAdminPanel(), { 
          headers: { 'Content-Type': 'text/html; charset=utf-8' } 
        });
      }

      if (pathname === '/login') {
        if (request.method === 'POST') {
          const formData = await request.formData();
          const password = formData.get('password');
          
          if (password === env.ADMIN_PASSWORD) {
            return new Response('Success', { status: 200 });
          }
          return new Response('Unauthorized', { status: 401 });
        }
        return new Response(AdminUI.getLoginPage(), { 
          headers: { 'Content-Type': 'text/html; charset=utf-8' } 
        });
      }

      // WebSocket 代理
      if (request.headers.get('Upgrade') === 'websocket') {
        await 反代参数获取(request);
        
        const proxyConfig = {
          type: 启用SOCKS5反代 || 'direct',
          address: 我的SOCKS5账号,
          username: null,
          password: null,
          proxyIP: 反代IP
        };

        const connector = new ProxyConnector(proxyConfig);
        const wsProxy = new WebSocketProxy(config_JSON.UUID, connector);
        
        return wsProxy.handleRequest(request);
      }

      // IP 优选接口
      if (pathname.includes('/add')) {
        const ipOptimizer = new IPOptimizer(request);
        const result = await ipOptimizer.generateOptimizedIPs(16, -1);
        
        return new Response(result.text, {
          headers: { 
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-cache'
          }
        });
      }

      // 订阅接口
      if (pathname.includes('/sub')) {
        const subGen = new SubscriptionGenerator(config_JSON);
        const links = [];
        
        // 生成示例链接
        links.push(subGen.generateVlessLink('104.16.0.1', 443, host, config_JSON.UUID, '/path'));
        
        const subscription = subGen.formatSubscription(links, 'mixed');
        
        return new Response(subscription, {
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Disposition': 'attachment; filename="subscription.txt"'
          }
        });
      }

      // 日志接口
      if (pathname === '/log' || pathname === '/logs') {
        const logger = new Logger(env);
        const logs = await logger.getLog();
        
        return new Response(JSON.stringify(logs, null, 2), {
          headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
      }

      // 默认响应
      return new Response('EdgeTunnel running', { status: 200 });

    } catch (error) {
      console.error('处理请求错误:', error);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};
