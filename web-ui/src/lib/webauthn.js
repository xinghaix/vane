// 浏览器原生 WebAuthn / Passkey (FIDO2) 辅助封装（零第三方依赖）

export function isPasskeySupported() {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    Boolean(navigator.credentials && navigator.credentials.create && navigator.credentials.get)
  );
}

export function isIpHostname() {
  if (typeof location === 'undefined') return false;
  const h = (location.hostname || '').replace(/^\[|\]$/g, '');
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || h.includes(':');
}

export function detectPasskeyDefaultName() {
  if (typeof navigator === 'undefined') return 'Passkey';
  const ua = navigator.userAgent || '';
  let os = 'Device';
  if (/iPhone/i.test(ua)) os = 'iPhone';
  else if (/iPad/i.test(ua)) os = 'iPad';
  else if (/Macintosh|Mac OS X/i.test(ua)) os = 'macOS';
  else if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/Linux/i.test(ua)) os = 'Linux';

  let browser = 'Passkey';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/Chrome\//i.test(ua) && !/Edg\//i.test(ua)) browser = 'Chrome';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';
  else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = 'Safari';

  return `${os} · ${browser}`;
}

export function b64urlToUint8(str) {
  const clean = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = clean.length % 4 === 0 ? '' : '='.repeat(4 - (clean.length % 4));
  const bin = atob(clean + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bufToB64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function friendlyWebAuthnError(err, lang = 'zh') {
  const name = err?.name || '';
  if (name === 'NotAllowedError') {
    return lang === 'en'
      ? 'Passkey prompt was cancelled or timed out.'
      : '已取消通行密钥验证或等待超时';
  }
  if (name === 'InvalidStateError') {
    return lang === 'en'
      ? 'This authenticator already has a Passkey registered for Vane.'
      : '当前设备或密码器已绑定过该通行密钥';
  }
  if (name === 'SecurityError') {
    return lang === 'en'
      ? 'WebAuthn requires a valid HTTPS domain name (raw IP addresses are rejected by browsers).'
      : '浏览器 WebAuthn 规范要求通过域名 HTTPS 访问（不支持纯 IP 地址）';
  }
  return err?.message || (lang === 'en' ? 'Passkey operation failed' : '通行密钥操作失败');
}

export async function createPasskeyCredential(opts, lang = 'zh') {
  if (!isPasskeySupported()) {
    throw new Error(lang === 'en' ? 'Passkey (WebAuthn) is not supported in this browser.' : '当前浏览器不支持通行密钥 (WebAuthn)');
  }
  const publicKey = {
    ...opts,
    challenge: b64urlToUint8(opts.challenge),
    user: {
      ...opts.user,
      id: b64urlToUint8(opts.user.id),
    },
    excludeCredentials: (opts.excludeCredentials || []).map((c) => ({
      ...c,
      id: b64urlToUint8(c.id),
    })),
  };
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey });
  } catch (err) {
    throw new Error(friendlyWebAuthnError(err, lang));
  }
  if (!cred || !cred.response) {
    throw new Error(lang === 'en' ? 'No credential returned by authenticator' : '验证器未返回通行密钥凭据');
  }
  return {
    challenge: opts.challenge,
    client_data_json: bufToB64url(cred.response.clientDataJSON),
    attestation_object: bufToB64url(cred.response.attestationObject),
  };
}

export async function getPasskeyAssertion(opts, lang = 'zh') {
  if (!isPasskeySupported()) {
    throw new Error(lang === 'en' ? 'Passkey (WebAuthn) is not supported in this browser.' : '当前浏览器不支持通行密钥 (WebAuthn)');
  }
  const publicKey = {
    ...opts,
    challenge: b64urlToUint8(opts.challenge),
    allowCredentials: (opts.allowCredentials || []).map((c) => ({
      ...c,
      id: b64urlToUint8(c.id),
    })),
  };
  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey });
  } catch (err) {
    throw new Error(friendlyWebAuthnError(err, lang));
  }
  if (!cred || !cred.response) {
    throw new Error(lang === 'en' ? 'No assertion returned by authenticator' : '验证器未返回通行密钥签名');
  }
  return {
    challenge: opts.challenge,
    credential_id: cred.id || bufToB64url(cred.rawId),
    client_data_json: bufToB64url(cred.response.clientDataJSON),
    authenticator_data: bufToB64url(cred.response.authenticatorData),
    signature: bufToB64url(cred.response.signature),
  };
}
