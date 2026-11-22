'use strict';
/*
 * ============================================================================
 *  APK FORGE  —  gerador de APK (embute payload + troca ícone + troca nome)
 * ----------------------------------------------------------------------------
 *  Node puro: nenhuma dependência de Java/apktool/apksigner no servidor.
 *  Assinatura APK Signature Scheme v2 feita na mão (RSA-2048 / SHA-256).
 *  Roda no Render (Web Service, Node), porta = process.env.PORT.
 * ============================================================================
 */

const http = require('http');
const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');
const Jimp = require('jimp');

/* ==========================================================================
 * 0. CONFIGURAÇÃO (pode sobrescrever por variável de ambiente no Render)
 * ========================================================================== */

const AES_KEY_HEX =
  process.env.AES_KEY_HEX ||
  '21e41d688988803be751468f4a19129f335e7adee76184ac59df2b7134e22f2f';

const ASSET_NAME = process.env.ASSET_NAME || '';

const ICON_SIZE = Math.min(Math.max(parseInt(process.env.ICON_SIZE || '400', 10) || 400, 32), 1024);

// Limite padrão mais seguro para instâncias com RAM limitada no Render (ex.: 45 MB).
// Pode aumentar via env MAX_BODY_MB se usar instância com mais RAM.
const MAX_BODY_MB = parseInt(process.env.MAX_BODY_MB || '45', 10);
const MAX_BODY = (Number.isFinite(MAX_BODY_MB) && MAX_BODY_MB > 0 ? MAX_BODY_MB : 45) * 1024 * 1024;

const DEFAULT_BASE = process.env.BASE_APK_PATH || path.join(__dirname, 'base.apk');

const SIGN_KEY_HEX_OBF = process.env.SIGN_KEY_HEX ||
  '9725a31ba5a6a797aaa1ae8d21ef2150aaa6a6a6a2a7a325a3019725a305a5a6a7a525a6a6a731eb06b2bb42bebc40fc93a976d535cdbdcfd4a5819ff636c28f678ecd57c479ad3fe1b2d4021820c2214f2a0bc983831366939580cf73fccf68f284074a774d92f11cbe2ba297fba3e04a0806dd52bc4b7d546dcaf0d9d9812804360f00e456fb4eb2f3111e1f48ee904682947dd4ce73f38f79a01cde777b5e4d79b1afe7c96d05c76c31b50716519ac87406bf754d2a0c344391185f81692353f6528ef7d40009c9fc7d66e8ca270ef81c9cf03c7b06dc733bea63ce10b4ece8c9cabdf9912d4079826df44f606bc748a6b115e7e41b8e012b1a49003811545a7a3379ca9229ee035a0ecb46b59bafcbcb36cc616a501ed2b089250aef69c7ec2f36efb1f4a5a4a6a7a6a525a6a7aa9defe1f24e888413abc3f6f1925e0e73358fc1c596b614f8e9ea58908cfe511fe55b43ad64c268a030e3de5024dafa70030cfc8ce8b2c2d560dc914ba2b5b9cfb60920d328b9fe3a258c1878812d5b4efe18bba6967ae3e50192533f0fc93e9639052a6c49d426c067ce18b3eff811ed7d6302f3d92b5579a07bb00a5eaa3c7d0291907e71dacd82b30a2ea3854b43a6368f16592874c92834ba54496eaad470bfd614e330bbebd6e55dd897524fc679735f4d852328983ba4b964c3865e4ca8dd47d9438b87233a3f891f525a940722dfd893492a58b751cde14039794d7e55433321ae437330eab54c0f9820dd256141fbe8983bf67e511ed3b15b8e3986a52626a775cddb914c756f5983d0ccf578cc84a0c1a4baaaa3ecf493398d87801a1efb4da3c88e8cb6469970b09424c903e703b360494162ac4428ffd58c7a4a0366e3c6b60feec08898761f5c4102f7a8fb992f32e2358028981de36177a18ef41a6d9b2069fb9f55447fa71ac317d624da4358bfe6a405e88c6208881fac3159cfd9d4a52626a7117bb91bc5434b4216ed68e4f1a93cbbdf17eabeb36b7a2f2baae3978e8aa19bee531f151f366dd96a4e3fce4777289b2361601e31492d24451d84008533f5c52a2929c51971875cf484dca85b22c954eaa3bbb236c663df6895c12635a581f6282c1260877426f3ba252a4f485ccd7b1e20468d3cee6dd1761cd7deb35e9706a5262796eef9b284e65ed7218b896fd00d6e611178ca743e1f408626b16950c7bdc18f890010b249309c905f0feef1a1e2fe4e679091df7cc4a89206d704afe59d98a6be1f1f374646cda036260586f6006565aacaa6c5876b623a6b285036273caeb8ad332b602982e9dfe2430d4c1c4f81f131c76b97ba0efb86184312fde250e258a526279688cb82afa36404737fc1d83d9d9c2107584d5aa7b0ed68fc1b2261792bde6b42000e112f41698b42d9bc1b59503de83750f14e3f0cdeb93fd6175af07462229361e829e0593f6f26effa42054d769e8ff5b90c19dc8e1e62860acf731e90eac74cb0c9a3cdf814bbcb4ad141d1ba5bff5c883e05e4cd49854443b74a28ee26a526279fdd923834979ab9b20281ae8bdb0e214e6bfa2a2515c273b32fca8678fa3885705d53c6b8b6eb6841a4aeee207fe7cdce3eb55833d55abae152fcefdb1cf319250763d437684c04ea985d8129e09276164c19847dd977b43da1874ea33d6e43164251efe4103e1597f465a4a92cb45997d8d7546384c7ea603841acee6e78e9';

function signKeyObject() {
  const raw = Buffer.from(SIGN_KEY_HEX_OBF.trim(), 'hex');
  for (let i = 0; i < raw.length; i++) raw[i] ^= 0xa7;
  return crypto.createPrivateKey({ key: raw, format: 'der', type: 'pkcs8' });
}

/* ==========================================================================
 * 1. UTILITÁRIOS BINÁRIOS
 * ========================================================================== */

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = 0 ^ -1;
  for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ CRC_TABLE[(c ^ buf[i]) & 0xff];
  return (c ^ -1) >>> 0;
}

const le32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0, 0); return b; };
const le64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n), 0); return b; };
const be32 = (n) => { const b = Buffer.alloc(4); b.writeInt32BE(n | 0, 0); return b; };
const lp = (buf) => Buffer.concat([le32(buf.length), buf]);

/* ==========================================================================
 * 2. LEITOR DE ZIP (APK)
 * ========================================================================== */

function readZip(buf) {
  const maxScan = Math.min(buf.length, 0xffff + 22);
  let eocd = -1;
  for (let i = buf.length - 22; i >= buf.length - maxScan; i--) {
    if (i < 0) break;
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('ZIP inválido: não achei o diretório central (arquivo corrompido?)');

  const total = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOff = buf.readUInt32LE(eocd + 16);
  if (cdOff + cdSize > buf.length || buf.readUInt32LE(cdOff) !== 0x02014b50) {
    throw new Error('ZIP inválido: offsets do diretório central inválidos');
  }

  const entries = [];
  let p = cdOff;
  for (let i = 0; i < total; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) {
      throw new Error('ZIP inválido: entrada ' + i + ' corrompida');
    }
    const e = {
      versionMade: buf.readUInt16LE(p + 4),
      versionNeed: buf.readUInt16LE(p + 6),
      flags: buf.readUInt16LE(p + 8),
      method: buf.readUInt16LE(p + 10),
      mtime: buf.readUInt16LE(p + 12),
      mdate: buf.readUInt16LE(p + 14),
      crc: buf.readUInt32LE(p + 16),
      csize: buf.readUInt32LE(p + 20),
      usize: buf.readUInt32LE(p + 24),
      diskStart: buf.readUInt16LE(p + 34),
      intAttr: buf.readUInt16LE(p + 36),
      extAttr: buf.readUInt32LE(p + 38),
      off: buf.readUInt32LE(p + 42),
    };
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const cmtLen = buf.readUInt16LE(p + 32);
    e.name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    p += 46 + nameLen + extraLen + cmtLen;

    const lo = e.off;
    if (lo + 30 > buf.length || buf.readUInt32LE(lo) !== 0x04034b50) {
      throw new Error('ZIP inválido: cabeçalho local corrompido em ' + e.name);
    }
    const lNameLen = buf.readUInt16LE(lo + 26);
    const lExtraLen = buf.readUInt16LE(lo + 28);
    const dataStart = lo + 30 + lNameLen + lExtraLen;
    if (dataStart + e.csize > buf.length) {
      throw new Error('ZIP inválido: dados truncados em ' + e.name);
    }
    e.dataStart = dataStart;
    e.raw = buf.subarray(dataStart, dataStart + e.csize);
    entries.push(e);
  }
  return { entries, cdOff, cdSize, eocd, comment: buf.subarray(eocd + 22) };
}

function readEntryData(e) {
  if (e.method === 0) return e.raw;
  if (e.method === 8) return zlib.inflateRawSync(e.raw);
  throw new Error('Método de compressão não suportado: ' + e.method + ' (' + e.name + ')');
}

/* ==========================================================================
 * 3. ESCRITOR DE ZIP (com alinhamento de 4 bytes para entradas "stored")
 * ========================================================================== */

function buildZip(items) {
  const chunks = [];
  const central = [];
  let offset = 0;
  const now = new Date();
  const dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1);
  const dosDate = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();

  for (const it of items) {
    let crc, csize, usize, raw;
    if (it.data) {
      usize = it.data.length;
      crc = crc32(it.data);
      if (it.method === 0) {
        raw = it.data;
        csize = raw.length;
      } else {
        raw = zlib.deflateRawSync(it.data, { level: 6 });
        csize = raw.length;
      }
    } else {
      raw = it.raw;
      crc = it.crc;
      csize = it.csize;
      usize = it.usize;
    }

    const nameBuf = Buffer.from(it.name, 'utf8');
    let flags = (it.flags || 0) & ~0x0008;
    if (/[^\x00-\x7f]/.test(it.name)) flags |= 0x0800;

    let extra = Buffer.alloc(0);
    const baseLen = offset + 30 + nameBuf.length;
    const pad = (4 - (baseLen % 4)) % 4;
    if (pad > 0) {
      const field = Buffer.alloc(4 + pad);
      field.writeUInt16LE(0xd935, 0);
      field.writeUInt16LE(pad, 2);
      extra = field;
    }

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(it.versionNeed || 20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(it.method, 8);
    local.writeUInt16LE(it.mtime != null ? it.mtime : dosTime, 10);
    local.writeUInt16LE(it.mdate != null ? it.mdate : dosDate, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(csize, 18);
    local.writeUInt32LE(usize, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(extra.length, 28);

    chunks.push(local, nameBuf, extra, raw);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(it.versionMade || 20, 4);
    cd.writeUInt16LE(it.versionNeed || 20, 6);
    cd.writeUInt16LE(flags, 8);
    cd.writeUInt16LE(it.method, 10);
    cd.writeUInt16LE(it.mtime != null ? it.mtime : dosTime, 12);
    cd.writeUInt16LE(it.mdate != null ? it.mdate : dosDate, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(csize, 20);
    cd.writeUInt32LE(usize, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(it.diskStart || 0, 34);
    cd.writeUInt16LE(it.intAttr || 0, 36);
    cd.writeUInt32LE(it.extAttr != null ? it.extAttr : 0, 38);
    cd.writeUInt32LE(offset, 42);
    central.push(cd, nameBuf);

    offset += local.length + nameBuf.length + extra.length + raw.length;
  }

  const cdBuf = Buffer.concat(central);
  const entriesBuf = Buffer.concat(chunks);
  return { entriesBuf, cdBuf, cdOffset: entriesBuf.length };
}

/* ==========================================================================
 * 4. ASSINATURA — APK Signature Scheme v2 (puro Node)
 * ========================================================================== */

const SIG_ALGO_RSA_SHA256 = 0x0103;

function chunkedDigest(sections) {
  const CHUNK = 1024 * 1024;
  const digests = [];
  for (const s of sections) {
    for (let off = 0; off < s.length; off += CHUNK) {
      const part = s.subarray(off, Math.min(off + CHUNK, s.length));
      const h = crypto.createHash('sha256');
      h.update(Buffer.from([0xa5]));
      h.update(le32(part.length));
      h.update(part);
      digests.push(h.digest());
    }
  }
  const h = crypto.createHash('sha256');
  h.update(Buffer.from([0x5a]));
  h.update(le32(digests.length));
  for (const d of digests) h.update(d);
  return h.digest();
}

function buildSigningBlock({ privateKey, certDer, digest }) {
  const publicKeyDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });

  const digestRecord = Buffer.concat([le32(SIG_ALGO_RSA_SHA256), lp(digest)]);
  const digestsSeq = lp(lp(digestRecord));
  const certsSeq = lp(lp(certDer));
  const attrsSeq = lp(Buffer.alloc(0));
  const signedData = Buffer.concat([digestsSeq, certsSeq, attrsSeq]);

  const signature = crypto.sign('sha256', signedData, privateKey);
  const sigRecord = Buffer.concat([le32(SIG_ALGO_RSA_SHA256), lp(signature)]);
  const sigsSeq = lp(sigRecord);

  const signer = Buffer.concat([lp(signedData), lp(sigsSeq), lp(publicKeyDer)]);
  const value = lp(lp(signer));

  const pair = Buffer.concat([le64(value.length + 4), le32(0x7109871a), value]);
  const blockSize = pair.length + 8 + 16;
  return Buffer.concat([le64(blockSize), pair, le64(blockSize), Buffer.from('APK Sig Block 42')]);
}

function signApk(zipParts, privateKey, certDer) {
  const { entriesBuf, cdBuf, cdOffset } = zipParts;

  const eocdForDigest = Buffer.alloc(22);
  eocdForDigest.writeUInt32LE(0x06054b50, 0);
  eocdForDigest.writeUInt16LE(0, 4);
  eocdForDigest.writeUInt16LE(0, 6);
  const totalEntries = (() => {
    let n = 0, p = 0;
    while (p < cdBuf.length) {
      const nameLen = cdBuf.readUInt16LE(p + 28);
      const extraLen = cdBuf.readUInt16LE(p + 30);
      const cmtLen = cdBuf.readUInt16LE(p + 32);
      n++;
      p += 46 + nameLen + extraLen + cmtLen;
    }
    return n;
  })();
  eocdForDigest.writeUInt16LE(totalEntries, 8);
  eocdForDigest.writeUInt16LE(totalEntries, 10);
  eocdForDigest.writeUInt32LE(cdBuf.length, 12);
  eocdForDigest.writeUInt32LE(cdOffset, 16);
  eocdForDigest.writeUInt16LE(0, 20);

  const digest = chunkedDigest([entriesBuf, cdBuf, eocdForDigest]);
  const block = buildSigningBlock({ privateKey, certDer, digest });

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(totalEntries, 8);
  eocd.writeUInt16LE(totalEntries, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(cdOffset + block.length, 16);
  eocd.writeUInt16LE(0, 20);

  return { apk: Buffer.concat([entriesBuf, block, cdBuf, eocd]), digest };
}

/* ==========================================================================
 * 5. CONTÊINER CIFRADO
 * ========================================================================== */

function aesKey() {
  const k = Buffer.from(AES_KEY_HEX, 'hex');
  if (k.length !== 32) throw new Error('AES_KEY_HEX inválida (precisa de 64 dígitos hex)');
  return k;
}

function decryptContainer(buf, key) {
  if (buf.length < 8 || buf[0] !== 0x9e || buf[1] !== 0x02) return null;
  const total = buf.readInt32BE(2);
  let off = 6;
  if (off >= buf.length) return null;
  const skipLen = buf[off]; off += 1;
  if (off + skipLen + 16 > buf.length) return null;
  const skip = buf.subarray(off, off + skipLen); off += skipLen;
  if (off + total !== buf.length) return null;
  const iv = buf.subarray(off, off + 16);
  const ct = buf.subarray(off + 16);
  try {
    const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const plain = Buffer.concat([d.update(ct), d.final()]);
    const gz = zlib.gunzipSync(plain);
    return { skip, skipLen, inner: gz };
  } catch (_) {
    return null;
  }
}

function buildContainer(payloadApk, skip, skipLen, key) {
  const inner = buildInnerZip(payloadApk);
  const gz = zlib.gzipSync(inner, { level: 6 });
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  const ct = Buffer.concat([c.update(gz), c.final()]);
  const body = Buffer.concat([iv, ct]);
  return Buffer.concat([Buffer.from([0x9e, 0x02]), be32(body.length), Buffer.from([skipLen]), skip, body]);
}

function buildInnerZip(payloadApk) {
  const name = Buffer.from('base.apk', 'utf8');
  const data = payloadApk;
  const comp = zlib.deflateRawSync(data, { level: 6 });
  const crc = crc32(data);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(8, 8);
  local.writeUInt16LE(0, 10);
  local.writeUInt16LE(0x21, 12);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(comp.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  local.writeUInt16LE(0, 28);
  const cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0);
  cd.writeUInt16LE(20, 4);
  cd.writeUInt16LE(20, 6);
  cd.writeUInt16LE(0, 8);
  cd.writeUInt16LE(8, 10);
  cd.writeUInt16LE(0, 12);
  cd.writeUInt16LE(0x21, 14);
  cd.writeUInt32LE(crc, 16);
  cd.writeUInt32LE(comp.length, 20);
  cd.writeUInt32LE(data.length, 24);
  cd.writeUInt16LE(name.length, 28);
  cd.writeUInt32LE(0, 38);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cd.length + name.length, 12);
  eocd.writeUInt32LE(local.length + name.length + comp.length, 16);
  return Buffer.concat([local, name, comp, cd, name, eocd]);
}

function extractInnerApk(inner) {
  const z = readZip(inner);
  const e = z.entries.find((x) => /\.apk$/i.test(x.name)) || z.entries[0];
  if (!e) throw new Error('zip interno vazio');
  return { name: e.name, data: readEntryData(e) };
}

/* ==========================================================================
 * 6. resources.arsc — troca o texto de app_name (launcher label)
 * ========================================================================== */

function parseStringPool(buf, off) {
  if (buf.readUInt16LE(off) !== 0x0001) throw new Error('arsc: pool esperado em ' + off);
  const hdrSize = buf.readUInt16LE(off + 2);
  const size = buf.readUInt32LE(off + 4);
  const count = buf.readUInt32LE(off + 8);
  const flags = buf.readUInt32LE(off + 16);
  const stringsStart = buf.readUInt32LE(off + 20);
  const utf8 = (flags & 0x100) !== 0;
  const strings = [];
  for (let i = 0; i < count; i++) {
    const o = buf.readUInt32LE(off + hdrSize + i * 4);
    let p = off + stringsStart + o;
    if (utf8) {
      let n = buf[p++];
      if (n & 0x80) n = ((n & 0x7f) << 8) | buf[p++];
      let bl = buf[p++];
      if (bl & 0x80) bl = ((bl & 0x7f) << 8) | buf[p++];
      strings.push(buf.subarray(p, p + bl).toString('utf8'));
    } else {
      let n = buf.readUInt16LE(p); p += 2;
      if (n & 0x8000) { n = ((n & 0x7fff) << 16) | buf.readUInt16LE(p); p += 2; }
      strings.push(buf.subarray(p, p + n * 2).toString('utf16le'));
    }
  }
  return { off, hdrSize, size, flags, utf8, strings, end: off + size };
}

function encodeUtf8StringPool(strings) {
  const parts = [];
  const offsets = [];
  let cursor = 0;
  for (const s of strings) {
    offsets.push(cursor);
    const b = Buffer.from(s, 'utf8');
    const charLen = s.length;
    const head = [];
    if (charLen > 0x7f) head.push((charLen >> 8) | 0x80, charLen & 0xff);
    else head.push(charLen);
    if (b.length > 0x7f) head.push((b.length >> 8) | 0x80, b.length & 0xff);
    else head.push(b.length);
    const seg = Buffer.concat([Buffer.from(head), b, Buffer.from([0])]);
    parts.push(seg);
    cursor += seg.length;
  }
  let body = Buffer.concat(parts);
  const pad = (4 - (body.length % 4)) % 4;
  if (pad) body = Buffer.concat([body, Buffer.alloc(pad)]);

  const count = strings.length;
  const hdrSize = 28;
  const stringsStart = hdrSize + count * 4;
  const total = stringsStart + body.length;
  const head = Buffer.alloc(hdrSize);
  head.writeUInt16LE(0x0001, 0);
  head.writeUInt16LE(hdrSize, 2);
  head.writeUInt32LE(total, 4);
  head.writeUInt32LE(count, 8);
  head.writeUInt32LE(0, 12);
  head.writeUInt32LE(0x100, 16);
  head.writeUInt32LE(stringsStart, 20);
  head.writeUInt32LE(0, 24);
  const offs = Buffer.alloc(count * 4);
  offsets.forEach((o, i) => offs.writeUInt32LE(o, i * 4));
  return Buffer.concat([head, offs, body]);
}

function patchArsc(arsc, { keyNames, newValue }) {
  if (arsc.readUInt16LE(0) !== 0x0002) throw new Error('resources.arsc inválido');
  const rootHdr = arsc.readUInt16LE(2);
  const rootSize = arsc.readUInt32LE(4);

  const global = parseStringPool(arsc, rootHdr);
  let pkgOff = global.end;
  if (arsc.readUInt16LE(pkgOff) !== 0x0200) throw new Error('arsc: pacote não encontrado');

  const pkgHdr = arsc.readUInt16LE(pkgOff + 2);
  const pkgSize = arsc.readUInt32LE(pkgOff + 4);
  const keyStringsOff = arsc.readUInt32LE(pkgOff + 276);

  const keyPool = parseStringPool(arsc, pkgOff + keyStringsOff);

  const hits = new Set();
  let p = pkgOff + pkgHdr;
  const pkgEnd = pkgOff + pkgSize;
  while (p + 8 <= pkgEnd) {
    const type = arsc.readUInt16LE(p);
    const hdr = arsc.readUInt16LE(p + 2);
    const size = arsc.readUInt32LE(p + 4);
    if (size <= 0) break;
    if (type === 0x0201) {
      const entryCount = arsc.readUInt32LE(p + 12);
      const entriesStart = arsc.readUInt32LE(p + 16);
      for (let i = 0; i < entryCount; i++) {
        const eOff = arsc.readUInt32LE(p + hdr + i * 4);
        if (eOff === 0xffffffff) continue;
        const ep = p + entriesStart + eOff;
        const entrySize = arsc.readUInt16LE(ep);
        const entryFlags = arsc.readUInt16LE(ep + 2);
        const keyIdx = arsc.readUInt32LE(ep + 4);
        if (entryFlags & 0x0001) continue;
        const vp = ep + entrySize;
        const dataType = arsc[vp + 3];
        const data = arsc.readUInt32LE(vp + 4);
        if (dataType !== 0x03) continue;
        const key = keyPool.strings[keyIdx];
        if (keyNames.includes(key)) hits.add(data);
      }
    }
    p += size;
  }

  if (!hits.size) throw new Error('arsc: não achei a string do nome (' + keyNames.join(',') + ')');

  const oldStrings = global.strings.slice();
  for (const idx of hits) oldStrings[idx] = newValue;

  const newPool = encodeUtf8StringPool(oldStrings);
  const rest = arsc.subarray(global.end, rootSize);

  const root = Buffer.alloc(rootHdr);
  root.writeUInt16LE(0x0002, 0);
  root.writeUInt16LE(rootHdr, 2);
  root.writeUInt32LE(rootHdr + newPool.length + rest.length, 4);
  root.writeUInt32LE(1, 8);

  return {
    arsc: Buffer.concat([root, newPool, rest]),
    oldValues: [...hits].map((i) => global.strings[i]),
  };
}

/* ==========================================================================
 * 7. IMAGEM DO ÍCONE
 * ========================================================================== */

async function makeIcon(buf) {
  let img;
  try {
    img = await Jimp.read(buf);
  } catch (_) {
    throw new Error('Não consegui ler a imagem. Manda um PNG ou JPG válido.');
  }
  if (img.bitmap.width < 32 || img.bitmap.height < 32) {
    throw new Error('Imagem muito pequena (mínimo 32x32).');
  }
  img.cover(ICON_SIZE, ICON_SIZE, Jimp.HORIZONTAL_ALIGN_CENTER | Jimp.VERTICAL_ALIGN_CENTER);
  const out = await img.getBufferAsync(Jimp.MIME_PNG);
  img = null;
  return out;
}

/* ==========================================================================
 * 8. PIPELINE
 * ========================================================================== */

const META_SIG_RE = /^META-INF\/(MANIFEST\.MF|[^/]+\.(SF|RSA|DSA|EC))$/i;

async function buildApk({ baseBuf, payloadBuf, imageBuf, appName, privateKey, certDer }) {
  const log = [];

  if (baseBuf.length < 22 || baseBuf.readUInt32LE(0) !== 0x04034b50) {
    throw new Error('O APK base não é um ZIP válido.');
  }
  const baseZip = readZip(baseBuf);

  if (payloadBuf.length < 22 || payloadBuf.readUInt32LE(0) !== 0x04034b50) {
    throw new Error('O payload não é um APK/ZIP válido.');
  }
  readZip(payloadBuf);

  const key = aesKey();
  let container = null;
  for (const e of baseZip.entries) {
    if (ASSET_NAME) {
      if (e.name !== ASSET_NAME) continue;
    } else {
      if (!e.name.startsWith('assets/') && !e.name.startsWith('res/raw/')) continue;
      if (e.usize < 100000 || e.usize > 60 * 1024 * 1024) continue;
    }
    let data;
    try { data = readEntryData(e); } catch (_) { continue; }
    const dec = decryptContainer(data, key);
    if (dec) { container = { entry: e, dec }; break; }
  }
  if (!container) {
    throw new Error('Não achei o contêiner cifrado no APK base (a chave AES pode ser outra).');
  }
  const innerOld = extractInnerApk(container.dec.inner);
  log.push(`contêiner: ${container.entry.name} (${innerOld.data.length} bytes dentro)`);

  let newContainer = buildContainer(payloadBuf, container.dec.skip, container.dec.skipLen, key);
  container.dec = null;

  const check = decryptContainer(newContainer, key);
  if (!check) throw new Error('Falha na verificação do contêiner (não decifrou de volta).');
  const innerNew = extractInnerApk(check.inner);
  if (!innerNew.data.equals(payloadBuf)) throw new Error('Falha na verificação: o payload decifrado não bate.');

  const iconPng = await makeIcon(imageBuf);
  const iconNames = ['res/mipmap-hdpi-v4/ic_launcher.png', 'assets/app_icon.png'];
  const foundIcons = baseZip.entries.filter((e) => iconNames.includes(e.name));
  if (!foundIcons.length) {
    const any = baseZip.entries.filter((e) => /mipmap.*\/ic_launcher/i.test(e.name));
    if (!any.length) throw new Error('Não achei o ícone do app dentro do APK base.');
    any.forEach((e) => foundIcons.push(e));
  }

  const arscEntry = baseZip.entries.find((e) => e.name === 'resources.arsc');
  if (!arscEntry) throw new Error('resources.arsc não encontrado no APK base.');
  const arscOld = readEntryData(arscEntry);
  const { arsc: arscNew, oldValues } = patchArsc(arscOld, { keyNames: ['app_name'], newValue: appName });
  const oldLabel = oldValues[0] || '';
  log.push(`nome antigo: "${oldLabel}" → "${appName}"`);

  const htmlEntry = baseZip.entries.find((e) => e.name === 'assets/main_ui.html');
  let htmlNew = null;
  if (htmlEntry && oldLabel) {
    const html = readEntryData(htmlEntry).toString('utf8');
    if (html.includes(oldLabel)) {
      htmlNew = Buffer.from(html.split(oldLabel).join(appName), 'utf8');
      log.push('nome trocado também no main_ui.html');
    }
  }

  const items = [];
  for (const e of baseZip.entries) {
    if (META_SIG_RE.test(e.name)) continue;
    if (e.name === 'resources.arsc') {
      items.push({ name: e.name, method: 0, flags: e.flags, mtime: e.mtime, mdate: e.mdate, data: arscNew });
      continue;
    }
    if (foundIcons.includes(e)) {
      items.push({ name: e.name, method: 0, flags: 0, mtime: e.mtime, mdate: e.mdate, data: iconPng });
      continue;
    }
    if (container.entry === e) {
      items.push({ name: e.name, method: 8, flags: 0, mtime: e.mtime, mdate: e.mdate, data: newContainer });
      continue;
    }
    if (htmlNew && htmlEntry === e) {
      items.push({ name: e.name, method: 8, flags: e.flags, mtime: e.mtime, mdate: e.mdate, data: htmlNew });
      continue;
    }
    items.push({
      name: e.name, method: e.method, flags: e.flags, mtime: e.mtime, mdate: e.mdate,
      versionMade: e.versionMade, versionNeed: e.versionNeed,
      diskStart: e.diskStart, intAttr: e.intAttr, extAttr: e.extAttr,
      raw: e.raw, crc: e.crc, csize: e.csize, usize: e.usize,
    });
  }
  items.sort((a, b) => (a.name === 'resources.arsc' ? -1 : b.name === 'resources.arsc' ? 1 : 0));

  const zipParts = buildZip(items);
  const { apk } = signApk(zipParts, privateKey, certDer);
  newContainer = null;

  const outZip = readZip(apk);
  const outAsset = outZip.entries.find((e) => e.name === container.entry.name);
  if (!outAsset) throw new Error('Verificação final: o asset do contêiner sumiu.');
  const outDec = decryptContainer(readEntryData(outAsset), key);
  if (!outDec) throw new Error('Verificação final: o asset não decifra.');
  const outInner = extractInnerApk(outDec.inner);
  if (!outInner.data.equals(payloadBuf)) throw new Error('Verificação final: o payload não confere.');
  log.push('verificação final: OK (asset decifra de volta no payload exato)');

  return {
    apk,
    log,
    info: {
      base: baseZip.entries.length,
      payloadSize: payloadBuf.length,
      apkSize: apk.length,
      asset: container.entry.name,
      iconSize: iconPng.length,
      oldLabel,
      newLabel: appName,
      sha256: crypto.createHash('sha256').update(apk).digest('hex'),
    },
  };
}

/* ==========================================================================
 * 9. MULTIPART PARSER (sem dependências)
 * ========================================================================== */

function parseMultipart(body, contentType) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || '');
  if (!m) throw new Error('Requisição sem boundary.');
  const boundary = Buffer.from('--' + (m[1] || m[2]).trim());
  const fields = {};
  const files = {};

  let pos = body.indexOf(boundary);
  while (pos >= 0) {
    pos += boundary.length;
    if (body.subarray(pos, pos + 2).toString('utf8') === '--') break;
    if (body.subarray(pos, pos + 2).toString('utf8') === '\r\n') pos += 2;
    const next = body.indexOf(boundary, pos);
    if (next < 0) break;
    const part = body.subarray(pos, next - 2);
    const sep = part.indexOf('\r\n\r\n');
    if (sep < 0) { pos = next; continue; }
    const head = part.subarray(0, sep).toString('utf8');
    const data = part.subarray(sep + 4);
    const nameM = /name="([^"]*)"/i.exec(head);
    const fileM = /filename="([^"]*)"/i.exec(head);
    if (nameM) {
      if (fileM && fileM[1]) files[nameM[1]] = { filename: fileM[1], data };
      else fields[nameM[1]] = data.toString('utf8');
    }
    pos = next;
  }
  return { fields, files };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error(`Arquivos grandes demais (limite ${MAX_BODY_MB} MB no servidor).`));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
    req.on('aborted', () => reject(new Error('Envio interrompido pelo cliente ou rede.')));
  });
}

const CERT_DER_B64 = 'MIIC8jCCAdqgAwIBAgIIP5ocd7LkTRAwDQYJKoZIhvcNAQELBQAwKzENMAsGA1UEAxMEWmFrYTENMAsGA1UEChMEWmFrYTELMAkGA1UEBhMCQlIwHhcNMjQwMTAxMDAwMDAwWhcNNDQwMTAxMDAwMDAwWjArMQ0wCwYDVQQDEwRaYWthMQ0wCwYDVQQKEwRaYWthMQswCQYDVQQGEwJCUjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJZMoRUc5Rkb51s0DtFykmoaaHMCJjhRkWUowClq8GPeCphGFXOlv4dlhuiNrG4kJLTBNDInaNRbaM9VI6Dt0Oo1VrsZjAUwXARH7a+hevUb7Nrzym1Xfn4mj6ORqKdD8VzpFVS2ubjvSTfhJTPac2nUVCjeB7t50Nz56t4WCEBuyqJgy5YSoLH2PW/ToRjS6o2rk+Q2v/gmzoT0UfUpUHOnrm5b2sFPbYCpX7s7V5vcoXvUnE3EabcTS09ubRpeNorn3iXKU+jHzGDvARayQEO8KaaMve6nn7bz/d2U3m01jkmk/als4RI8CGxskWvGzfe5dRcugq1IzmBLiJFIFlMCAwEAAaMaMBgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwDQYJKoZIhvcNAQELBQADggEBAHHwApsGE6Kc8qsnf610KIcfKPe3ilSMixfMzUSmqsHOemh03DVjuXyANUKa4xSkGDf1WrZfbD/g/I9jwTHnhXQ10ghH+IdC9XfkbduhcKulX8RULGvlDc7knpXv+7q/pgtwD51FUsy/IR/gz7LW6BfY7WdQCjg4Xbx6HBm4wpl/qcMoY8qyDgWHf8ioc38ckfMshrnsGyZJ1rpcjMDqZ486rXOZnSI7AHnJ8Gmbky+haa2RfFvVYycmvG1pnQuCFrI2YH0ynBsEddHxRdAI6urpGKhBS7v3KinJl75sNJCSXcEoUvxEh8wKNH6QtGazYAhZaIfPD9x/38N1gs0Gnuc=';

/* ==========================================================================
 * 10. SERVIDOR HTTP + INTERFACE
 * ========================================================================== */

let CERT_DER = null;
function certDer() {
  if (CERT_DER) return CERT_DER;
  const b64 = (process.env.SIGN_CERT_B64 || '').trim() || CERT_DER_B64;
  CERT_DER = Buffer.from(b64, 'base64');
  return CERT_DER;
}

function json(res, status, obj) {
  if (res.writableEnded || res.destroyed) return;
  const b = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': b.length,
    'cache-control': 'no-store',
  });
  res.end(b);
}

const PAGE = `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APK Forge</title>
<style>
  :root{
    --bg:#0b0d12; --card:#131722; --card2:#181d2b; --line:#242b3d;
    --txt:#e8ecf5; --dim:#8b95ab; --acc:#5b8cff; --acc2:#22d3a8; --err:#ff5b6e;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
       background:radial-gradient(1200px 600px at 50% -200px,#1a2440 0%,var(--bg) 60%);
       color:var(--txt);min-height:100vh;padding:28px 16px 60px}
  .wrap{max-width:760px;margin:0 auto}
  h1{font-size:26px;margin:0 0 4px;letter-spacing:-.4px}
  h1 span{background:linear-gradient(90deg,var(--acc),var(--acc2));-webkit-background-clip:text;background-clip:text;color:transparent}
  .sub{color:var(--dim);font-size:14px;margin:0 0 22px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;margin-bottom:14px}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  @media(max-width:640px){.row{grid-template-columns:1fr}}
  label{display:block;font-size:13px;color:var(--dim);margin-bottom:6px}
  .drop{border:1.5px dashed var(--line);border-radius:12px;padding:16px;text-align:center;cursor:pointer;
        transition:.15s;background:var(--card2);font-size:13px;color:var(--dim);min-height:96px;
        display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px}
  .drop:hover,.drop.over{border-color:var(--acc);background:#18213a;color:var(--txt)}
  .drop.has{border-style:solid;border-color:var(--acc2);color:var(--txt)}
  .drop b{font-size:13px;color:var(--txt);font-weight:600;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .drop small{font-size:11.5px;color:var(--dim)}
  input[type=text]{width:100%;background:var(--card2);border:1px solid var(--line);border-radius:10px;
        padding:11px 13px;color:var(--txt);font-size:14px;outline:none}
  input[type=text]:focus{border-color:var(--acc)}
  button{width:100%;margin-top:16px;padding:14px;border:0;border-radius:12px;font-size:15px;font-weight:600;
        cursor:pointer;color:#08111f;background:linear-gradient(90deg,var(--acc),var(--acc2));transition:.15s}
  button:disabled{opacity:.55;cursor:wait}
  .bar{height:3px;background:var(--line);border-radius:3px;overflow:hidden;margin-top:14px;display:none}
  .bar.on{display:block}
  .bar i{display:block;height:100%;width:35%;background:linear-gradient(90deg,var(--acc),var(--acc2));animation:run 1.1s infinite}
  @keyframes run{0%{margin-left:-35%}100%{margin-left:100%}}
  .msg{border-radius:12px;padding:13px 15px;font-size:13.5px;line-height:1.5;display:none;margin-top:14px;white-space:pre-wrap;word-break:break-word}
  .msg.err{display:block;background:#2a1418;border:1px solid #5b2530;color:#ffb3bd}
  .msg.ok{display:block;background:#0f2a24;border:1px solid #1c5a4a;color:#a8f0dc}
  .msg.ok a{color:#7ef2cf}
  code{background:#0d1220;padding:2px 6px;border-radius:6px;font-size:12px}
  .foot{color:var(--dim);font-size:12px;text-align:center;margin-top:22px;line-height:1.6}
  .tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:20px;background:#1c2437;color:var(--dim);margin-left:6px}
</style>
</head>
<body>
<div class="wrap">
  <h1>APK <span>Forge</span></h1>
  <p class="sub">Embute o payload, troca o ícone e o nome — devolve o APK assinado pronto pra instalar.</p>

  <div class="card">
    <div class="row">
      <div>
        <label>1) APK base (o seu APK de teste)</label>
        <div class="drop" id="d-base" data-k="base">
          <b id="t-base">Arraste ou clique</b><small id="s-base">opcional se o base.apk já estiver no servidor</small>
        </div>
      </div>
      <div>
        <label>2) Payload (o APK que vai ser embutido)</label>
        <div class="drop" id="d-payload" data-k="payload">
          <b id="t-payload">Arraste ou clique</b><small id="s-payload">obrigatório · .apk</small>
        </div>
      </div>
    </div>
    <div class="row" style="margin-top:12px">
      <div>
        <label>3) Imagem do ícone / tela inicial</label>
        <div class="drop" id="d-image" data-k="image">
          <b id="t-image">Arraste ou clique</b><small id="s-image">obrigatório · PNG ou JPG</small>
        </div>
      </div>
      <div>
        <label>4) Nome do app</label>
        <input type="text" id="name" placeholder="Ex.: ZAP STREAMING" maxlength="60">
        <label style="margin-top:10px">Nome do arquivo</label>
        <input type="text" id="fname" placeholder="app.apk">
      </div>
    </div>
    <button id="go">Gerar APK</button>
    <div class="bar" id="bar"><i></i></div>
    <div class="msg" id="msg"></div>
  </div>

  <div class="foot">
    Assinatura APK Signature Scheme v2 (RSA-2048) · troca de assinatura exige desinstalar a versão antiga<br>
    <span class="tag">Node puro</span><span class="tag">sem Java</span><span class="tag">Render</span>
  </div>
</div>

<script>
const files = {};
const input = document.createElement('input');
input.type = 'file';
let pickTarget = null;

function human(n){
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  return (n/1048576).toFixed(2) + ' MB';
}

document.querySelectorAll('.drop').forEach(z => {
  z.addEventListener('click', () => { pickTarget = z.dataset.k; input.value=''; input.click(); });
  z.addEventListener('dragover', e => { e.preventDefault(); z.classList.add('over'); });
  z.addEventListener('dragleave', () => z.classList.remove('over'));
  z.addEventListener('drop', e => {
    e.preventDefault(); z.classList.remove('over');
    if (e.dataTransfer.files[0]) setFile(z.dataset.k, e.dataTransfer.files[0]);
  });
});
input.addEventListener('change', () => { if (input.files[0] && pickTarget) setFile(pickTarget, input.files[0]); });

function setFile(k, f){
  files[k] = f;
  const z = document.getElementById('d-' + k);
  z.classList.add('has');
  document.getElementById('t-' + k).textContent = f.name;
  document.getElementById('s-' + k).textContent = human(f.size);
  if (k === 'payload' && !document.getElementById('fname').value){
    document.getElementById('fname').value = f.name.replace(/\\.apk$/i,'') + '-novo.apk';
  }
}

const msg = document.getElementById('msg');
const bar = document.getElementById('bar');
const go = document.getElementById('go');

go.addEventListener('click', async () => {
  msg.className = 'msg'; msg.textContent = '';
  const name = document.getElementById('name').value.trim();
  if (!files.payload) return showErr('Falta o payload (o APK que vai ser embutido).');
  if (!files.image) return showErr('Falta a imagem do ícone.');
  if (!name) return showErr('Falta o nome do app.');

  const fd = new FormData();
  if (files.base) fd.append('base', files.base);
  fd.append('payload', files.payload);
  fd.append('image', files.image);
  fd.append('name', name);
  fd.append('filename', document.getElementById('fname').value.trim() || name + '.apk');

  go.disabled = true; bar.classList.add('on');
  const t0 = Date.now();
  try {
    const res = await fetch('/build', { method: 'POST', body: fd });
    if (!res.ok){
      let e = 'erro ' + res.status;
      try { e = (await res.json()).error || e; } catch(_) {}
      throw new Error(e);
    }
    const blob = await res.blob();
    const cd = res.headers.get('content-disposition') || '';
    const m = /filename="([^"]+)"/.exec(cd);
    const outName = m ? m[1] : 'app.apk';
    const sha = res.headers.get('x-apk-sha256') || '';
    const asset = decodeURIComponent(res.headers.get('x-apk-asset') || '');
    const log = decodeURIComponent(res.headers.get('x-apk-log') || '');

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = outName; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);

    const secs = ((Date.now()-t0)/1000).toFixed(1);
    msg.className = 'msg ok';
    msg.innerHTML =
      'APK gerado em ' + secs + 's ✅\\n' +
      'Arquivo: <b>' + outName + '</b> — ' + human(blob.size) + '\\n' +
      'SHA-256: <code>' + sha.slice(0,32) + '…</code>\\n' +
      'Asset: <code>' + asset + '</code>\\n' +
      (log ? '\\n' + log.split(' | ').join('\\n') + '\\n' : '') +
      '\\n<a href="' + url + '" download="' + outName + '">Baixar de novo</a>';
  } catch (e) {
    showErr(e.message || 'Falha de rede ao comunicar com o servidor.');
  } finally {
    go.disabled = false; bar.classList.remove('on');
  }
});

function showErr(t){ msg.className = 'msg err'; msg.textContent = t; }
</script>
</body>
</html>
`;

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', 'http://localhost');

    if (url.pathname === '/health') {
      return json(res, 200, { ok: true, uptime: process.uptime() });
    }

    if (url.pathname === '/' || url.pathname === '/index.html') {
      const html = Buffer.from(PAGE, 'utf8');
      if (res.writableEnded || res.destroyed) return;
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'content-length': html.length,
        'cache-control': 'no-store',
      });
      return res.end(html);
    }

    if (url.pathname === '/build' && req.method === 'POST') {
      const body = await readBody(req);
      const { fields, files } = parseMultipart(body, req.headers['content-type']);

      const appName = (fields.name || '').trim();
      if (!appName) throw new Error('Falta o nome do app.');
      if (appName.length > 60) throw new Error('Nome muito longo (máx. 60 caracteres).');

      if (!files.payload || !files.payload.data.length) {
        throw new Error('Falta o APK de payload.');
      }
      if (!files.image || !files.image.data.length) {
        throw new Error('Falta a imagem do ícone.');
      }

      let baseBuf;
      if (files.base && files.base.data.length > 0) {
        baseBuf = files.base.data;
      } else if (fs.existsSync(DEFAULT_BASE)) {
        baseBuf = fs.readFileSync(DEFAULT_BASE);
      } else {
        throw new Error('Manda o APK base (ou coloca um base.apk junto do server.js).');
      }

      const r = await buildApk({
        baseBuf,
        payloadBuf: files.payload.data,
        imageBuf: files.image.data,
        appName,
        privateKey: signKeyObject(),
        certDer: certDer(),
      });

      if (res.writableEnded || res.destroyed) return;

      const safe = (fields.filename || appName).replace(/[^\w.\- ]+/g, '').trim() || 'app';
      const outName = /\.apk$/i.test(safe) ? safe : safe + '.apk';

      res.writeHead(200, {
        'content-type': 'application/vnd.android.package-archive',
        'content-length': r.apk.length,
        'content-disposition': `attachment; filename="${outName}"`,
        'x-apk-name': encodeURIComponent(appName),
        'x-apk-sha256': r.info.sha256,
        'x-apk-size': String(r.info.apkSize),
        'x-apk-asset': encodeURIComponent(r.info.asset),
        'x-apk-log': encodeURIComponent(r.log.join(' | ')),
        'access-control-expose-headers': 'x-apk-name,x-apk-sha256,x-apk-size,x-apk-asset,x-apk-log',
      });
      return res.end(r.apk);
    }

    return json(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('[build/error]', e && e.stack ? e.stack : e);
    const msg = (e && e.message) || String(e);
    const status = /grandes demais/i.test(msg) ? 413 : 400;
    return json(res, status, { error: msg });
  }
});

server.requestTimeout = 5 * 60 * 1000;
server.headersTimeout = 60 * 1000;
server.keepAliveTimeout = 65 * 1000;

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log('APK Forge ouvindo em 0.0.0.0:' + PORT);
});
