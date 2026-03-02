// api/sendSSRNotification.js
// Vercel Serverless Function: 处理 Memfire Webhook，查 push_token 并发 APNs
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

/**
 * 辅助：统一返回 JSON
 */
function sendJson(res, status, obj) {
  res.status(status).setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(obj));
}

/**
 * Vercel 入口函数
 */
module.exports = async (req, res) => {
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

    // 5. 调 APNs：开发环境用 sandbox，生产环境用正式环境
    const isProduction = process.env.APNS_PRODUCTION === 'true';
    const apnsHost = isProduction
      ? 'https://api.push.apple.com'
      : 'https://api.development.push.apple.com';
    const apnsUrl = `${apnsHost}/3/device/${tokenToUse}`;

    console.log('[sendSSRNotification] APNs 请求', {
      env: isProduction ? 'production' : 'development',
      url: apnsUrl,
    });

    const response = await fetch(apnsUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apnsToken}`,
        'apns-topic': APNS_BUNDLE_ID,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
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
      }),
    });

    const resultText = await response.text();
    let result = null;
    if (resultText) {
      try {
        result = JSON.parse(resultText);
      } catch {
        result = resultText;
      }
    }

    console.log('[sendSSRNotification] APNs 响应', {
      status: response.status,
      ok: response.ok,
      result,
    });

    sendJson(res, response.ok ? 200 : 500, {
      success: response.ok,
      status: response.status,
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
};