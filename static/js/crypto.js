/**
 * Obsidian Secure V2 - Web Crypto Engine
 * Handles AES-256-GCM encryption/decryption, Base64URL encoding/decoding,
 * and strict metadata format validation.
 */
(function (global) {
  'use strict';

  // Constants
  const PROTOCOL_VERSION = 1;
  const SHARE_ID_REGEX = /^[a-f0-9]{32}$/;
  const FILE_ID_REGEX = /^[a-zA-Z0-9_-]{8,64}$/;
  const MAX_FILE_COUNT = 10;
  const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB
  const KEY_BYTES_LENGTH = 32; // 256 bits
  const NONCE_BYTES_LENGTH = 12; // 96 bits

  /**
   * Convert an ArrayBuffer or Uint8Array to a Base64URL string.
   */
  function bufferToBase64Url(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = typeof btoa === 'function' ? btoa(binary) : Buffer.from(bytes).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Convert a Base64URL string to a Uint8Array.
   */
  function base64UrlToBuffer(base64url) {
    if (typeof base64url !== 'string' || !/^[A-Za-z0-9_-]+$/.test(base64url)) {
      throw new Error('Invalid Base64URL string.');
    }
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    if (typeof atob === 'function') {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } else {
      return new Uint8Array(Buffer.from(base64, 'base64'));
    }
  }

  /**
   * Generate cryptographically secure random opaque hex identifier.
   */
  function randomOpaqueId(byteLength = 16) {
    const cryptoObj = global.crypto || (typeof require !== 'undefined' ? require('crypto').webcrypto : null);
    if (!cryptoObj) {
      throw new Error('Cryptographic random source unavailable.');
    }
    const bytes = new Uint8Array(byteLength);
    cryptoObj.getRandomValues(bytes);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  /**
   * Calculate SHA-256 hash of buffer as lowercase hex string.
   */
  async function sha256Hex(buffer) {
    const cryptoSubtle = getSubtleCrypto();
    const hashBuffer = await cryptoSubtle.digest('SHA-256', buffer);
    const hashBytes = new Uint8Array(hashBuffer);
    let hex = '';
    for (let i = 0; i < hashBytes.length; i++) {
      hex += hashBytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  function getSubtleCrypto() {
    if (global.crypto && global.crypto.subtle) {
      return global.crypto.subtle;
    }
    if (typeof require !== 'undefined') {
      const nodeCrypto = require('crypto');
      if (nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle) {
        return nodeCrypto.webcrypto.subtle;
      }
    }
    throw new Error('Web Crypto API (crypto.subtle) is not available in this environment.');
  }

  /**
   * Generate an independent 256-bit AES-GCM CryptoKey.
   */
  async function generateFileKey() {
    const subtle = getSubtleCrypto();
    return await subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Export CryptoKey to raw 32 bytes.
   */
  async function exportRawKey(key) {
    const subtle = getSubtleCrypto();
    const rawBuffer = await subtle.exportKey('raw', key);
    return new Uint8Array(rawBuffer);
  }

  /**
   * Import raw 32 bytes as AES-GCM CryptoKey.
   */
  async function importRawKey(rawKeyBytes) {
    if (rawKeyBytes.byteLength !== KEY_BYTES_LENGTH) {
      throw new Error(`Invalid key length: expected ${KEY_BYTES_LENGTH} bytes, got ${rawKeyBytes.byteLength}`);
    }
    const subtle = getSubtleCrypto();
    return await subtle.importKey(
      'raw',
      rawKeyBytes,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
  }

  /**
   * Generate a fresh 96-bit (12 bytes) initialization vector (nonce).
   */
  function generateNonce() {
    const cryptoObj = global.crypto || (typeof require !== 'undefined' ? require('crypto').webcrypto : null);
    const nonce = new Uint8Array(NONCE_BYTES_LENGTH);
    cryptoObj.getRandomValues(nonce);
    return nonce;
  }

  /**
   * Build canonical Authenticated Additional Data (AAD) binding ciphertext to its metadata.
   * Cryptographically authenticates collection ID, file ID, original filename, MIME type, and size.
   */
  function buildAdditionalData(shareId, fileId, filename, mimeType, originalSize) {
    const payload = JSON.stringify([
      PROTOCOL_VERSION,
      String(shareId),
      String(fileId),
      String(filename),
      String(mimeType || ''),
      Number(originalSize),
    ]);
    return new TextEncoder().encode(payload);
  }

  /**
   * Encrypt plaintext ArrayBuffer using AES-256-GCM.
   * Returns ciphertext ArrayBuffer containing ciphertext and 16-byte authentication tag.
   */
  async function encryptFile(plaintextBuffer, key, iv, additionalData) {
    if (iv.byteLength !== NONCE_BYTES_LENGTH) {
      throw new Error(`Invalid nonce length: expected ${NONCE_BYTES_LENGTH} bytes.`);
    }
    const subtle = getSubtleCrypto();
    const algorithm = { name: 'AES-GCM', iv: iv, tagLength: 128 };
    if (additionalData) {
      algorithm.additionalData = additionalData;
    }
    return await subtle.encrypt(
      algorithm,
      key,
      plaintextBuffer
    );
  }

  /**
   * Decrypt ciphertext ArrayBuffer using AES-256-GCM.
   * Verifies both ciphertext integrity and additionalData authentication tag.
   * Throws OperationError if ciphertext, nonce, key, or additionalData has been tampered with.
   */
  async function decryptFile(ciphertextBuffer, key, iv, additionalData) {
    if (iv.byteLength !== NONCE_BYTES_LENGTH) {
      throw new Error(`Invalid nonce length: expected ${NONCE_BYTES_LENGTH} bytes.`);
    }
    const subtle = getSubtleCrypto();
    const algorithm = { name: 'AES-GCM', iv: iv, tagLength: 128 };
    if (additionalData) {
      algorithm.additionalData = additionalData;
    }
    return await subtle.decrypt(
      algorithm,
      key,
      ciphertextBuffer
    );
  }

  /**
   * Encode client metadata object to Base64URL string for URL fragment.
   */
  function encodeMetadata(metadataObj) {
    const jsonStr = JSON.stringify(metadataObj);
    const utf8Bytes = new TextEncoder().encode(jsonStr);
    return bufferToBase64Url(utf8Bytes);
  }

  /**
   * Decode Base64URL URL fragment to client metadata object.
   */
  function decodeMetadata(encodedFragment) {
    if (!encodedFragment || typeof encodedFragment !== 'string') {
      throw new Error('Missing or empty decryption fragment.');
    }
    const cleanFragment = encodedFragment.startsWith('#') ? encodedFragment.slice(1) : encodedFragment;
    const utf8Bytes = base64UrlToBuffer(cleanFragment);
    const jsonStr = new TextDecoder('utf-8', { fatal: true }).decode(utf8Bytes);
    return JSON.parse(jsonStr);
  }

  /**
   * Validate metadata object against schema, integrity, and cryptographic constraints.
   */
  function validateMetadata(meta, expectedShareId) {
    if (!meta || typeof meta !== 'object') {
      return { valid: false, error: 'Metadata is not a valid JSON object.' };
    }
    if (meta.v !== PROTOCOL_VERSION) {
      return { valid: false, error: `Unsupported protocol version: ${meta.v}. Expected: ${PROTOCOL_VERSION}.` };
    }
    if (!meta.share_id || typeof meta.share_id !== 'string' || !SHARE_ID_REGEX.test(meta.share_id)) {
      return { valid: false, error: 'Metadata share_id is invalid or malformed.' };
    }
    if (expectedShareId && meta.share_id !== expectedShareId) {
      return { valid: false, error: `Collection ID mismatch: URL path has '${expectedShareId}', but metadata specifies '${meta.share_id}'.` };
    }
    if (!Array.isArray(meta.files) || meta.files.length === 0) {
      return { valid: false, error: 'Metadata must contain at least one file entry.' };
    }
    if (meta.files.length > MAX_FILE_COUNT) {
      return { valid: false, error: `File count ${meta.files.length} exceeds maximum limit of ${MAX_FILE_COUNT}.` };
    }

    const seenFileIds = new Set();
    for (let i = 0; i < meta.files.length; i++) {
      const fileEntry = meta.files[i];
      if (!fileEntry || typeof fileEntry !== 'object') {
        return { valid: false, error: `File entry at index ${i} is not a valid object.` };
      }
      if (!fileEntry.file_id || typeof fileEntry.file_id !== 'string' || !FILE_ID_REGEX.test(fileEntry.file_id)) {
        return { valid: false, error: `File entry at index ${i} has invalid file_id format.` };
      }
      if (seenFileIds.has(fileEntry.file_id)) {
        return { valid: false, error: `Duplicate file_id '${fileEntry.file_id}' found in metadata.` };
      }
      seenFileIds.add(fileEntry.file_id);

      if (!fileEntry.name || typeof fileEntry.name !== 'string' || fileEntry.name.trim().length === 0) {
        return { valid: false, error: `File entry at index ${i} has missing or empty filename.` };
      }
      if (typeof fileEntry.size !== 'number' || fileEntry.size < 0 || fileEntry.size > MAX_FILE_SIZE) {
        return { valid: false, error: `File entry '${fileEntry.name}' has invalid original size.` };
      }

      // Check key length
      try {
        const rawKey = base64UrlToBuffer(fileEntry.key);
        if (rawKey.byteLength !== KEY_BYTES_LENGTH) {
          return { valid: false, error: `File entry '${fileEntry.name}' has invalid key length (${rawKey.byteLength} bytes).` };
        }
      } catch (err) {
        return { valid: false, error: `File entry '${fileEntry.name}' has malformed Base64URL key.` };
      }

      // Check nonce length
      try {
        const nonce = base64UrlToBuffer(fileEntry.iv);
        if (nonce.byteLength !== NONCE_BYTES_LENGTH) {
          return { valid: false, error: `File entry '${fileEntry.name}' has invalid nonce length (${nonce.byteLength} bytes).` };
        }
      } catch (err) {
        return { valid: false, error: `File entry '${fileEntry.name}' has malformed Base64URL nonce.` };
      }
    }

    return { valid: true };
  }

  const ObsidianCrypto = {
    PROTOCOL_VERSION,
    MAX_FILE_COUNT,
    MAX_FILE_SIZE,
    bufferToBase64Url,
    base64UrlToBuffer,
    randomOpaqueId,
    sha256Hex,
    generateFileKey,
    exportRawKey,
    importRawKey,
    generateNonce,
    buildAdditionalData,
    encryptFile,
    decryptFile,
    encodeMetadata,
    decodeMetadata,
    validateMetadata,
  };

  // Export to global scope or CommonJS
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = ObsidianCrypto;
  }
  global.ObsidianCrypto = ObsidianCrypto;

})(typeof window !== 'undefined' ? window : globalThis);

