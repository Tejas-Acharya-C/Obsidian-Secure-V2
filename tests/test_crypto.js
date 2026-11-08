/**
 * Automated Test Suite for Obsidian Secure V2 Browser Cryptography & Sharing
 * Tests AES-256-GCM encryption/decryption, nonces, key independence, tamper detection,
 * Authenticated Additional Data (AAD) cryptographic binding of metadata, cross-file substitution,
 * Base64URL encoding, metadata validation, deduplication, and ZIP packaging.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const ObsidianCrypto = require('../static/js/crypto.js');
const JSZip = require('../static/vendor/jszip.min.js');

async function runTests() {
  console.log('--- Starting Browser Cryptography & Security Audit Tests ---');

  const shareIdA = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
  const shareIdB = 'ffffffffffffffffffffffffffffffff';
  const fileId1 = '11223344556677889900aabbccddeeff';
  const fileId2 = '223344556677889900aabbccddeeff11';

  // Test 1: Independent keys for separate files
  console.log('Test 1: Independent keys for separate files');
  const key1 = await ObsidianCrypto.generateFileKey();
  const key2 = await ObsidianCrypto.generateFileKey();
  const rawKey1 = await ObsidianCrypto.exportRawKey(key1);
  const rawKey2 = await ObsidianCrypto.exportRawKey(key2);
  assert.strictEqual(rawKey1.byteLength, 32, 'Key 1 must be 256 bits (32 bytes)');
  assert.strictEqual(rawKey2.byteLength, 32, 'Key 2 must be 256 bits (32 bytes)');
  assert.notDeepStrictEqual(rawKey1, rawKey2, 'Keys generated for separate files must be distinct');

  // Test 2: Correct nonce generation
  console.log('Test 2: Correct nonce sizes');
  const iv1 = ObsidianCrypto.generateNonce();
  const iv2 = ObsidianCrypto.generateNonce();
  assert.strictEqual(iv1.byteLength, 12, 'Nonce must be 96 bits (12 bytes)');
  assert.strictEqual(iv2.byteLength, 12, 'Nonce must be 96 bits (12 bytes)');
  assert.notDeepStrictEqual(iv1, iv2, 'Nonces must be distinct');

  // Test 3: Encrypt and decrypt known byte sequences with AAD
  console.log('Test 3: Encrypt and decrypt known byte sequence with Authenticated Additional Data (AAD)');
  const encoder = new TextEncoder();
  const originalBytes1 = encoder.encode('CONFIDENTIAL_CONTENT_OBSIDIAN_SECURE_2026');
  const aad1 = ObsidianCrypto.buildAdditionalData(shareIdA, fileId1, 'report.pdf', 'application/pdf', originalBytes1.byteLength);

  const ciphertext1 = await ObsidianCrypto.encryptFile(originalBytes1.buffer, key1, iv1, aad1);
  assert(ciphertext1.byteLength > originalBytes1.byteLength, 'Ciphertext must include GCM tag');
  assert.strictEqual(ciphertext1.byteLength, originalBytes1.byteLength + 16, 'AES-GCM ciphertext length must be plaintext + 16 bytes');

  const decrypted1 = await ObsidianCrypto.decryptFile(ciphertext1, key1, iv1, aad1);
  const decryptedBuf1 = Buffer.from(decrypted1);
  assert.deepStrictEqual(decryptedBuf1, Buffer.from(originalBytes1), 'Decrypted bytes must match original bytes exactly');

  // Test 4: Wrong key fails decryption
  console.log('Test 4: Wrong key fails authentication');
  let wrongKeyFailed = false;
  try {
    await ObsidianCrypto.decryptFile(ciphertext1, key2, iv1, aad1);
  } catch (err) {
    wrongKeyFailed = true;
  }
  assert(wrongKeyFailed, 'Decryption with wrong key must throw an error');

  // Test 5: Modified ciphertext fails authentication
  console.log('Test 5: Modified ciphertext fails authentication');
  const tamperedCipher = new Uint8Array(ciphertext1);
  tamperedCipher[5] ^= 0x55; // Flip bits
  let tamperCaught = false;
  try {
    await ObsidianCrypto.decryptFile(tamperedCipher.buffer, key1, iv1, aad1);
  } catch (err) {
    tamperCaught = true;
  }
  assert(tamperCaught, 'Tampered ciphertext must fail AES-GCM tag verification');

  // Test 6: Modified nonce fails authentication
  console.log('Test 6: Modified nonce fails authentication');
  const tamperedIv = new Uint8Array(iv1);
  tamperedIv[0] ^= 0xaa;
  let ivTamperCaught = false;
  try {
    await ObsidianCrypto.decryptFile(ciphertext1, key1, tamperedIv, aad1);
  } catch (err) {
    ivTamperCaught = true;
  }
  assert(ivTamperCaught, 'Tampered nonce must fail AES-GCM tag verification');

  // Test 7: Tampered filename fails AES-GCM authentication via AAD
  console.log('Test 7: Tampered filename in metadata fails AES-GCM authentication');
  const forgedAadName = ObsidianCrypto.buildAdditionalData(shareIdA, fileId1, 'malicious.exe', 'application/pdf', originalBytes1.byteLength);
  let nameTamperCaught = false;
  try {
    await ObsidianCrypto.decryptFile(ciphertext1, key1, iv1, forgedAadName);
  } catch (err) {
    nameTamperCaught = true;
  }
  assert(nameTamperCaught, 'Tampered filename must fail AES-GCM authentication tag verification');

  // Test 8: Tampered MIME type fails AES-GCM authentication via AAD
  console.log('Test 8: Tampered MIME type in metadata fails AES-GCM authentication');
  const forgedAadType = ObsidianCrypto.buildAdditionalData(shareIdA, fileId1, 'report.pdf', 'application/x-msdownload', originalBytes1.byteLength);
  let typeTamperCaught = false;
  try {
    await ObsidianCrypto.decryptFile(ciphertext1, key1, iv1, forgedAadType);
  } catch (err) {
    typeTamperCaught = true;
  }
  assert(typeTamperCaught, 'Tampered MIME type must fail AES-GCM authentication tag verification');

  // Test 9: Tampered file size fails AES-GCM authentication via AAD
  console.log('Test 9: Tampered file size in metadata fails AES-GCM authentication');
  const forgedAadSize = ObsidianCrypto.buildAdditionalData(shareIdA, fileId1, 'report.pdf', 'application/pdf', originalBytes1.byteLength + 100);
  let sizeTamperCaught = false;
  try {
    await ObsidianCrypto.decryptFile(ciphertext1, key1, iv1, forgedAadSize);
  } catch (err) {
    sizeTamperCaught = true;
  }
  assert(sizeTamperCaught, 'Tampered file size must fail AES-GCM authentication tag verification');

  // Test 10: Cross-file substitution fails AES-GCM authentication
  console.log('Test 10: Cross-file ciphertext substitution fails AES-GCM authentication');
  const originalBytes2 = encoder.encode('SECONDARY_FILE_CONTENT_OTHER_DOCUMENT');
  const aad2 = ObsidianCrypto.buildAdditionalData(shareIdA, fileId2, 'other.txt', 'text/plain', originalBytes2.byteLength);
  const ciphertext2 = await ObsidianCrypto.encryptFile(originalBytes2.buffer, key2, iv2, aad2);

  // Attempt to decrypt file 2's ciphertext using file 1's AAD & key
  let fileSubstitutionCaught = false;
  try {
    await ObsidianCrypto.decryptFile(ciphertext2, key1, iv1, aad1);
  } catch (err) {
    fileSubstitutionCaught = true;
  }
  assert(fileSubstitutionCaught, 'Substituting ciphertext between different files must fail authentication');

  // Test 11: Cross-collection substitution fails AES-GCM authentication
  console.log('Test 11: Cross-collection substitution fails AES-GCM authentication');
  const crossCollectionAad = ObsidianCrypto.buildAdditionalData(shareIdB, fileId1, 'report.pdf', 'application/pdf', originalBytes1.byteLength);
  let collectionSubCaught = false;
  try {
    await ObsidianCrypto.decryptFile(ciphertext1, key1, iv1, crossCollectionAad);
  } catch (err) {
    collectionSubCaught = true;
  }
  assert(collectionSubCaught, 'Substituting ciphertext across different collections must fail authentication');

  // Test 12: Base64URL encode/decode round trip
  console.log('Test 12: Base64URL encode/decode round trip');
  const sampleBytes = new Uint8Array([0, 255, 128, 64, 32, 16, 8, 4, 2, 1]);
  const b64url = ObsidianCrypto.bufferToBase64Url(sampleBytes);
  assert(!b64url.includes('+') && !b64url.includes('/') && !b64url.includes('='), 'Base64URL must not contain +, /, or =');
  const roundTripBytes = ObsidianCrypto.base64UrlToBuffer(b64url);
  assert.deepStrictEqual(Buffer.from(roundTripBytes), Buffer.from(sampleBytes), 'Base64URL round trip failed');

  // Test 13: Metadata serialization and validation
  console.log('Test 13: Metadata serialization and validation');
  const metadata = {
    v: 1,
    share_id: shareIdA,
    files: [
      {
        file_id: fileId1,
        name: 'report.pdf',
        type: 'application/pdf',
        size: originalBytes1.byteLength,
        key: ObsidianCrypto.bufferToBase64Url(rawKey1),
        iv: ObsidianCrypto.bufferToBase64Url(iv1),
      }
    ]
  };

  const fragment = ObsidianCrypto.encodeMetadata(metadata);
  const decodedMeta = ObsidianCrypto.decodeMetadata(fragment);
  assert.deepStrictEqual(decodedMeta, metadata, 'Decoded metadata must match original');

  const validResult = ObsidianCrypto.validateMetadata(decodedMeta, shareIdA);
  assert.strictEqual(validResult.valid, true, 'Valid metadata was rejected');

  // Test 14: Metadata validation edge cases
  console.log('Test 14: Metadata validation edge cases');
  // Mismatched share ID
  const mismatchResult = ObsidianCrypto.validateMetadata(decodedMeta, shareIdB);
  assert.strictEqual(mismatchResult.valid, false, 'Mismatched share ID must be rejected');

  // Unsupported protocol version
  const badVersion = { ...metadata, v: 2 };
  assert.strictEqual(ObsidianCrypto.validateMetadata(badVersion).valid, false, 'Unsupported version must be rejected');

  // Duplicate file_id
  const duplicateFileMeta = {
    ...metadata,
    files: [metadata.files[0], metadata.files[0]]
  };
  assert.strictEqual(ObsidianCrypto.validateMetadata(duplicateFileMeta).valid, false, 'Duplicate file_id must be rejected');

  // Invalid key length
  const badKeyMeta = {
    ...metadata,
    files: [{ ...metadata.files[0], key: ObsidianCrypto.bufferToBase64Url(new Uint8Array(16)) }]
  };
  assert.strictEqual(ObsidianCrypto.validateMetadata(badKeyMeta).valid, false, '16-byte key must be rejected');

  // Invalid nonce length
  const badIvMeta = {
    ...metadata,
    files: [{ ...metadata.files[0], iv: ObsidianCrypto.bufferToBase64Url(new Uint8Array(8)) }]
  };
  assert.strictEqual(ObsidianCrypto.validateMetadata(badIvMeta).valid, false, '8-byte nonce must be rejected');

  // Test 15: Client-side ZIP packaging and duplicate filename handling
  console.log('Test 15: JSZip packaging and filename deduplication');
  const zip = new JSZip();
  const usedNames = new Set();

  function deduplicateFilename(filename, existing) {
    if (!existing.has(filename)) { existing.add(filename); return filename; }
    const dot = filename.lastIndexOf('.');
    const base = dot !== -1 ? filename.slice(0, dot) : filename;
    const ext = dot !== -1 ? filename.slice(dot) : '';
    let c = 1;
    let candidate = `${base} (${c})${ext}`;
    while (existing.has(candidate)) { c++; candidate = `${base} (${c})${ext}`; }
    existing.add(candidate);
    return candidate;
  }

  const name1 = deduplicateFilename('invoice.pdf', usedNames);
  const name2 = deduplicateFilename('invoice.pdf', usedNames);
  const name3 = deduplicateFilename('invoice.pdf', usedNames);
  assert.strictEqual(name1, 'invoice.pdf');
  assert.strictEqual(name2, 'invoice (1).pdf');
  assert.strictEqual(name3, 'invoice (2).pdf');

  zip.file(name1, Buffer.from('PDF_ONE'));
  zip.file(name2, Buffer.from('PDF_TWO'));
  zip.file(name3, Buffer.from('PDF_THREE'));

  const zipBuffer = await zip.generateAsync({ type: 'nodebuffer' });
  assert(zipBuffer.byteLength > 0, 'Generated ZIP must not be empty');

  // Read back ZIP
  const unzipped = await JSZip.loadAsync(zipBuffer);
  assert(unzipped.file('invoice.pdf'), 'ZIP must contain invoice.pdf');
  assert(unzipped.file('invoice (1).pdf'), 'ZIP must contain invoice (1).pdf');
  assert(unzipped.file('invoice (2).pdf'), 'ZIP must contain invoice (2).pdf');

  const content1 = await unzipped.file('invoice.pdf').async('string');
  assert.strictEqual(content1, 'PDF_ONE');

  console.log('ALL 15 BROWSER CRYPTO & SECURITY AUDIT TESTS PASSED SUCCESSFULLY!');
}

runTests().catch(err => {
  console.error('Test failed with error:', err);
  process.exit(1);
});
