#pragma once
// AUTO-GENERATED from include/network/covenant_client.js by scripts/sync-embedded-js.py — do not edit.
#include <string>
namespace veld {
inline const std::string& GetCovenantClientJS() {
    static const std::string s = R"VELDCJS(
// Transaction hashing and address helpers used by the browser wallet.
// Pure byte arithmetic keeps local verification independent from node responses.
(function (global) {
  'use strict';

  // ---- RIPEMD-160 (pure JS; the browser has no native ripemd160) -----------
  function _rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
  var _ZL = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8, 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2, 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
  var _ZR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2, 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14, 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
  var _SL = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12, 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12, 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
  var _SR = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11, 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8, 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
  var _KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
  var _KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];
  function _rf(j, x, y, z) {
    if (j < 16) return (x ^ y ^ z);
    if (j < 32) return ((x & y) | (~x & z));
    if (j < 48) return ((x | ~y) ^ z);
    if (j < 64) return ((x & z) | (y & ~z));
    return (x ^ (y | ~z));
  }
  function ripemd160(data) {
    var bytes = (data instanceof Uint8Array) ? data : new Uint8Array(data);
    var len = bytes.length;
    var padLen = (((len + 8) >> 6) + 1) << 6;
    var p = new Uint8Array(padLen);
    p.set(bytes); p[len] = 0x80;
    var bitLen = len * 8;
    for (var i = 0; i < 4; i++) p[padLen - 8 + i] = (bitLen >>> (8 * i)) & 0xFF;  // high 4 length bytes stay 0 (sizes < 2^32 bits)
    var h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    for (var off = 0; off < padLen; off += 64) {
      var X = [];
      for (var k = 0; k < 16; k++) X[k] = (p[off+k*4] | (p[off+k*4+1]<<8) | (p[off+k*4+2]<<16) | (p[off+k*4+3]<<24)) >>> 0;
      var al=h0, bl=h1, cl=h2, dl=h3, el=h4, ar=h0, br=h1, cr=h2, dr=h3, er=h4;
      for (var j = 0; j < 80; j++) {
        var r = j >> 4;
        var t = (_rotl((al + _rf(j, bl, cl, dl) + X[_ZL[j]] + _KL[r]) >>> 0, _SL[j]) + el) >>> 0;
        al = el; el = dl; dl = _rotl(cl, 10); cl = bl; bl = t;
        var t2 = (_rotl((ar + _rf(79 - j, br, cr, dr) + X[_ZR[j]] + _KR[r]) >>> 0, _SR[j]) + er) >>> 0;
        ar = er; er = dr; dr = _rotl(cr, 10); cr = br; br = t2;
      }
      var tt = (h1 + cl + dr) >>> 0;
      h1 = (h2 + dl + er) >>> 0;
      h2 = (h3 + el + ar) >>> 0;
      h3 = (h4 + al + br) >>> 0;
      h4 = (h0 + bl + cr) >>> 0;
      h0 = tt;
    }
    var hs = [h0, h1, h2, h3, h4], out = new Array(20);
    for (var m = 0; m < 5; m++) { out[m*4] = hs[m] & 0xFF; out[m*4+1] = (hs[m]>>>8) & 0xFF; out[m*4+2] = (hs[m]>>>16) & 0xFF; out[m*4+3] = (hs[m]>>>24) & 0xFF; }
    return out;
  }
  // hash160(x) = ripemd160(sha256(x)). sha256: function(byteArray)->32-byte array.
  function hash160(bytes, sha256) { return ripemd160(sha256(bytes)); }

  // ---- Base58Check address encoding ----------------------------------------
  var _B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function base58Encode(bytes) {
    var digits = [0];
    for (var i = 0; i < bytes.length; i++) {
      var carry = bytes[i] & 0xFF;
      for (var j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; }
      while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
    }
    var s = '';
    for (var k = 0; k < bytes.length && bytes[k] === 0; k++) s += '1';
    for (var q = digits.length - 1; q >= 0; q--) s += _B58[digits[q]];
    return s;
  }
  // version: P2SH (0x05 on the public mainnet). payload: 20-byte hash160.
  // sha256d: function(byteArray)->32-byte array.
  function base58CheckEncode(version, payload, sha256d) {
    var data = [version & 0xFF];
    for (var i = 0; i < payload.length; i++) data.push(payload[i] & 0xFF);
    var chk = sha256d(data);
    var full = data.concat([chk[0], chk[1], chk[2], chk[3]]);
    return base58Encode(full);
  }

  // Byte-exact mirror of veld_signing.h::ComputeSighash.
  function _le32(out, v) { out.push(v & 0xFF, (v >>> 8) & 0xFF, (v >>> 16) & 0xFF, (v >>> 24) & 0xFF); }
  function _varint(out, v) {
    if (v < 0xFD) out.push(v);
    else if (v <= 0xFFFF) out.push(0xFD, v & 0xFF, (v >> 8) & 0xFF);
    else if (v <= 0xFFFFFFFF) out.push(0xFE, v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF);
    else { out.push(0xFF); var b = BigInt(v); for (var i = 0; i < 8; ++i) { out.push(Number(b & 0xFFn)); b >>= 8n; } }
  }
  function _value8(out, val) { var b = BigInt(val); for (var i = 0; i < 8; ++i) { out.push(Number(b & 0xFFn)); b >>= 8n; } }
  function computeSighash(tx, inputIndex, subscript, opts) {
    if (!opts || typeof opts.sha256d !== 'function') throw new Error('computeSighash: opts.sha256d required');
    if (typeof opts.genesisAscii !== 'string' || opts.genesisAscii.length === 0) throw new Error('computeSighash: genesisAscii required');
    if (opts.networkByte !== 0x4D && opts.networkByte !== 0x54) throw new Error('computeSighash: networkByte must be 0x4D or 0x54');
    var pre = [0x56, 0x45, 0x4C, 0x44, 0x5F, 0x53, 0x49, 0x47]; // "VELD_SIG"
    pre.push(0x03);                                             // sighash format version
    pre.push(opts.networkByte & 0xFF);                         // network-id
    for (var g = 0; g < opts.genesisAscii.length; ++g) pre.push(opts.genesisAscii.charCodeAt(g) & 0xFF);
    pre.push((opts.schemeId === undefined ? 0x01 : opts.schemeId) & 0xFF);
    _le32(pre, tx.version >>> 0);
    _varint(pre, tx.inputs.length);
    for (var i = 0; i < tx.inputs.length; ++i) {
      var inp = tx.inputs[i];
      for (var p = 0; p < 32; ++p) pre.push(inp.prevTxHash[p] & 0xFF);
      _le32(pre, inp.prevOutIndex >>> 0);
      if (i === inputIndex) { _varint(pre, subscript.length); for (var s = 0; s < subscript.length; ++s) pre.push(subscript[s] & 0xFF); }
      else { _varint(pre, 0); }
      _le32(pre, inp.sequence >>> 0);
    }
    _varint(pre, tx.outputs.length);
    for (var o = 0; o < tx.outputs.length; ++o) {
      _value8(pre, tx.outputs[o].value);
      _varint(pre, tx.outputs[o].scriptPubKey.length);
      for (var sp = 0; sp < tx.outputs[o].scriptPubKey.length; ++sp) pre.push(tx.outputs[o].scriptPubKey[sp] & 0xFF);
    }
    _le32(pre, tx.locktime >>> 0);
    _le32(pre, 0x00000001);                                    // SIGHASH_ALL
    return opts.sha256d(pre);
  }

  var api = {
    computeSighash: computeSighash,
    ripemd160: ripemd160,
    hash160: hash160,
    base58Encode: base58Encode,
    base58CheckEncode: base58CheckEncode
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else global.VeldCovenant = api;
})(typeof window !== 'undefined' ? window : this);


)VELDCJS";
    return s;
}
}  // namespace veld
