// api/sendSSRNotification.js
// Vercel Serverless Function: 处理 Memfire Webhook，查 push_token 并发 APNs
// APNs 要求 HTTP/2，用 http2 模块代替 fetch
const crypto = require('crypto');
const http2 = require('http2');
const jwt = require('jsonwebtoken');

/**
 * 辅助：统一返回 JSON
 */
function sendJson(res, status, obj) {
  res.status(status).setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(obj));
}

/**
 * 用 HTTP/2 请求 APNs（Apple 要求 HTTP/2）
 */
function apnsRequestHttp2(apnsHost, path, bearerToken, topic, body) {
  return new Promise((resolve, reject) => {
    let status = 0;
    let data = '';

    const client = http2.connect(apnsHost);
    client.on('error', (err) => {
      try { client.close(); } catch (_) {}
      reject(err);
    });

    const req = client.request({
      ':path': path,
      ':method': 'POST',
      authorization: `Bearer ${bearerToken}`,
      'apns-topic': topic,
      'content-type': 'application/json',
    });

    req.on('response', (headers) => { status = headers[':status'] || 0; });
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      try { client.close(); } catch (_) {}
      let result = null;
      if (data) {
        try { result = JSON.parse(data); } catch { result = data; }
      }
      resolve({ status, result });
    });
    req.on('error', (err) => {
      try { client.close(); } catch (_) {}
      reject(err);
    });

    req.write(JSON.stringify(body));
    req.end();
  });
}

/**
 * Vercel 入口函数（外层兜底，避免未捕获错误导致 FUNCTION_INVOCATION_FAILED）
 */
module.exports = async (req, res) => {
  try {
    await handler(req, res);
  } catch (e) {
    try {
      res.status(500).setHeader('Content-Type', 'application/json');
      res.send(JSON.stringify({
        success: false,
        error: e && e.message ? e.message : String(e),
        stack: e && e.stack ? e.stack : undefined,
      }));
    } catch (_) {}
  }
};

async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      sendJson(res, 405, { success: false, error: 'Method Not Allowed' });
      return;
    }

    const data = req.body || {};
    const payload = data.record || data;
    const { push_token: pushToken, user_id: userId, title, body } = payload || {};

    console.log('[sendSSRNotification] 收到请求', {
      userId,
      title: title && String(title).slice(0, 30),
      hasPushTokenInBody: !!pushToken,
    });

    // 1. 拿到 push_token：优先用 body 里的 push_token，其次用 user_id 查 profiles
    let tokenToUse = pushToken;

    if (!tokenToUse && userId) {
      const memfireUrl = process.env.MEMFIRE_URL;
      const memfireKey = process.env.MEMFIRE_ANON_KEY;
      if (!memfireUrl || !memfireKey) {
        sendJson(res, 500, {
          success: false,
          error: 'MEMFIRE_URL / MEMFIRE_ANON_KEY 未配置',
        });
        return;
      }

      const profileUrl =
        `${memfireUrl.replace(/\/$/, '')}` +
        `/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}&select=push_token`;

      const profileRes = await fetch(profileUrl, {
        headers: {
          apikey: memfireKey,
          Authorization: `Bearer ${memfireKey}`,
        },
      });

      const profiles = await profileRes.json();
      tokenToUse = profiles?.[0]?.push_token || '';
      console.log('[sendSSRNotification] 从 profiles 查 push_token', {
        userId,
        found: !!tokenToUse,
      });
    }

    if (!tokenToUse || typeof tokenToUse !== 'string') {
      sendJson(res, 400, {
        success: false,
        error: '缺少 push_token 或 user_id 查无 push_token',
      });
      return;
    }

    // 2. 读取 APNs 相关环境变量
    const APNS_KEY_ID = process.env.APNS_KEY_ID;
    const APNS_TEAM_ID = process.env.APNS_TEAM_ID;
    const APNS_BUNDLE_ID = process.env.APNS_BUNDLE_ID;
    const APNS_PRIVATE_KEY = process.env.APNS_PRIVATE_KEY;

    if (!APNS_KEY_ID || !APNS_TEAM_ID || !APNS_BUNDLE_ID || !APNS_PRIVATE_KEY) {
      sendJson(res, 500, {
        success: false,
        error: 'APNs 环境变量未配齐',
      });
      return;
    }

    // 3. 处理 .p8 PEM：支持多行或单行带 \n 的写法
    let pem = (APNS_PRIVATE_KEY || '').trim();
    if (pem.charCodeAt(0) === 0xfeff) pem = pem.slice(1); // 去 BOM
    if (pem.includes('\\n') && !pem.includes('\n')) {
      pem = pem.replace(/\\n/g, '\n');
    }
    if (
      !pem.includes('-----BEGIN PRIVATE KEY-----') ||
      !pem.includes('-----END PRIVATE KEY-----')
    ) {
      sendJson(res, 500, {
        success: false,
        error:
          'APNS_PRIVATE_KEY 必须包含 -----BEGIN PRIVATE KEY----- 和 -----END PRIVATE KEY-----',
      });
      return;
    }

    let privateKeyObj;
    try {
      privateKeyObj = crypto.createPrivateKey(pem);
    } catch (e) {
      sendJson(res, 500, {
        success: false,
        error:
          'APNS_PRIVATE_KEY 解析失败（请用 Apple 下载的 .p8 完整复制，不要手打）: ' +
          e.message,
      });
      return;
    }

    // 4. 生成 APNs JWT
    const apnsToken = jwt.sign(
      {},
      privateKeyObj,
      {
        algorithm: 'ES256',
        expiresIn: '1h',
        issuer: APNS_TEAM_ID,
        header: { alg: 'ES256', kid: APNS_KEY_ID },
      }
    );

    // 5. 调 APNs（HTTP/2）：开发用 sandbox，生产用正式
    const isProduction = process.env.APNS_PRODUCTION === 'true';
    const apnsHost = isProduction
      ? 'https://api.push.apple.com'
      : 'https://api.development.push.apple.com';
    const path = `/3/device/${tokenToUse}`;
    const payload = {
      aps: {
        alert: {
          title: title || '你有SSR活动卡待查收',
          body: body || '你的黑卡可兑换商家线下活动，点击查看',
        },
        sound: 'default',
        badge: 1,
        'content-available': 1,
      },
      type: 'ssr_invite',
    };

    console.log('[sendSSRNotification] APNs 请求', {
      env: isProduction ? 'production' : 'development',
      path,
    });

    const { status, result } = await apnsRequestHttp2(apnsHost, path, apnsToken, APNS_BUNDLE_ID, payload);

    console.log('[sendSSRNotification] APNs 响应', { status, result });

    sendJson(res, status === 200 ? 200 : 500, {
      success: status === 200,
      status,
      result,
    });
  } catch (error) {
    console.error('[sendSSRNotification] 异常', error.message, error.stack);
    const detail =
      error.cause && (error.cause.message || String(error.cause));
    sendJson(res, 500, {
      success: false,
      error: error.message,
      detail,
    });
  }
}