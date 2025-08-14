// server.js
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.use(express.json());
app.use(cookieParser());

// ===== Demo store (ganti dengan DB di produksi) =====
const users = new Map(); // email -> { id, email, passwordHash }
const devices = new Map(); // userId -> { deviceId, fingerprintHash, ua, revokedAt, lastSeenAt }
const refreshIndex = new Map(); // refreshTokenHash -> { userId, deviceId, exp }

// seed demo user
const demoUser = { id:'u_1', email:'user@leap.com', passwordHash: hash('12345') };
users.set(demoUser.email, demoUser);

// ===== Utils =====
function hash(s){ return crypto.createHash('sha256').update(String(s)).digest('hex'); }
function signAccess(payload){ return jwt.sign(payload, process.env.ACCESS_SECRET, { expiresIn:'20m' }); }
function signRefresh(payload){ return jwt.sign(payload, process.env.REFRESH_SECRET, { expiresIn:'15d' }); }

function setRefreshCookie(res, token){
  res.cookie('leap_refresh', token, { httpOnly:true, secure:false, sameSite:'lax', path:'/' });
}

// ===== Auth: Login + Device Binding =====
app.post('/auth/login', (req, res)=>{
  const { email, password, deviceId, fingerprint } = req.body || {};
  const ua = req.headers['user-agent'] || 'unknown';
  const dIdFromHeader = req.headers['x-device-id'];

  if(!email || !password || !deviceId || !fingerprint){
    return res.status(400).json({ message:'Bad request' });
  }
  if(dIdFromHeader !== deviceId){
    return res.status(400).json({ message:'Device header mismatch' });
  }

  const user = users.get(email);
  if(!user || user.passwordHash !== hash(password)){
    return res.status(401).json({ message:'Email atau password salah' });
  }

  const bound = devices.get(user.id);
  if(!bound){
    // Bind pertama kali
    devices.set(user.id, {
      deviceId,
      fingerprintHash: hash(fingerprint),
      ua,
      revokedAt: null,
      lastSeenAt: Date.now()
    });
  }else{
    const sameDevice = bound.deviceId === deviceId;
    const notRevoked = !bound.revokedAt;
    if(!sameDevice || !notRevoked){
      return res.status(403).json({ code:'DEVICE_MISMATCH', message:'Akun terikat pada perangkat lain' });
    }
    bound.lastSeenAt = Date.now();
  }

  // Issue tokens
  const accessToken = signAccess({ sub:user.id, deviceId });
  const refreshToken = signRefresh({ sub:user.id, deviceId });
  setRefreshCookie(res, refreshToken);
  refreshIndex.set(hash(refreshToken), { userId:user.id, deviceId, exp:Date.now()+15*24*60*60*1000 });

  return res.json({ accessToken, message:'Kamu berhasil masuk' });
});

// ===== Token refresh (opsional tapi disarankan) =====
app.post('/auth/refresh', (req,res)=>{
  const token = req.cookies.leap_refresh;
  if(!token) return res.status(401).json({ message:'No refresh' });

  try{
    const payload = jwt.verify(token, process.env.REFRESH_SECRET);
    // cek indeks + device binding
    const rec = refreshIndex.get(hash(token));
    const bound = devices.get(payload.sub);
    if(!rec || !bound || bound.deviceId !== payload.deviceId || bound.revokedAt){
      return res.status(403).json({ message:'Invalid refresh' });
    }
    const accessToken = signAccess({ sub:payload.sub, deviceId: payload.deviceId });
    return res.json({ accessToken });
  }catch(e){
    return res.status(403).json({ message:'Invalid refresh' });
  }
});

// ===== Lepas perangkat (simulasi OTP '123456') =====
app.post('/devices/release', (req,res)=>{
  const { email, otp } = req.body || {};
  const user = users.get(email);
  if(!user) return res.status(404).json({ message:'User tidak ditemukan' });
  if(otp !== '123456') return res.status(401).json({ message:'OTP salah' });

  const bound = devices.get(user.id);
  if(bound){ bound.revokedAt = Date.now(); }
  return res.json({ message:'Perangkat dilepaskan. Silakan login dari perangkat baru untuk bind ulang.' });
});

// ===== Middleware proteksi (cek access + device) =====
function authRequired(req,res,next){
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  const deviceId = req.headers['x-device-id'];

  if(!token) return res.status(401).json({ message:'No token' });

  try{
    const payload = jwt.verify(token, process.env.ACCESS_SECRET);
    const bound = devices.get(payload.sub);
    if(!bound || bound.deviceId !== deviceId || bound.revokedAt){
      return res.status(403).json({ message:'DEVICE_INVALID' });
    }
    bound.lastSeenAt = Date.now();
    req.user = { id: payload.sub, deviceId };
    next();
  }catch(e){
    return res.status(401).json({ message:'Token invalid/expired' });
  }
}

// ===== Contoh rute terlindungi =====
app.get('/me', authRequired, (req,res)=>{
  const userId = req.user.id;
  const user = [...users.values()].find(u=>u.id===userId);
  const bound = devices.get(userId);
  res.json({ id:user.id, email:user.email, device: bound });
});

app.use(express.static('.')); // supaya bisa serve login.html lokal
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log('Server running on http://localhost:'+PORT));
