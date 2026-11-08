/**
 * Obsidian Secure V2 — Recipient Controller (Technical Instrument Redesign)
 * Handles client-side URL fragment decoding, server manifest cross-checking,
 * AES-256-GCM authenticated decryption with AAD binding,
 * two-tier responsive file list rendering, and JSZip verified collection packaging.
 */
(function () {
  'use strict';

  // Extract share_id from URL path: /s/<share_id>
  const pathParts = window.location.pathname.split('/');
  const shareIdIndex = pathParts.indexOf('s') + 1;
  const shareId = shareIdIndex > 0 && shareIdIndex < pathParts.length ? pathParts[shareIdIndex] : null;

  // DOM Elements
  const errorBanner = document.getElementById('errorBanner');
  const errorTitle = document.getElementById('errorTitle');
  const errorMessage = document.getElementById('errorMessage');
  const loadingSection = document.getElementById('loadingSection');
  const loadingText = document.getElementById('loadingText');
  const recipientContent = document.getElementById('recipientContent');
  const collectionInfo = document.getElementById('collectionInfo');
  const recipientFileList = document.getElementById('recipientFileList');
  const decryptBtn = document.getElementById('decryptBtn');
  const downloadAllBtn = document.getElementById('downloadAllBtn');
  const statusDot = document.getElementById('statusDot');
  const statusLabel = document.getElementById('statusLabel');

  const decryptedFiles = [];

  function setStatus(state, label) {
    if (statusDot && statusLabel) {
      statusDot.className = `status-dot ${state}`;
      statusLabel.textContent = label;
    }
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function showError(title, msg) {
    if (loadingSection) loadingSection.classList.add('hidden');
    if (recipientContent) recipientContent.classList.add('hidden');
    if (errorBanner && errorMessage) {
      if (errorTitle) errorTitle.textContent = title;
      errorMessage.textContent = msg;
      errorBanner.classList.remove('hidden');
    } else {
      alert(`${title}: ${msg}`);
    }
    setStatus('error', 'Error');
  }

  function getFileSvgIcon() {
    return `<svg class="file-row-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>`;
  }

  function deduplicateFilename(filename, existingNames) {
    if (!existingNames.has(filename)) {
      existingNames.add(filename);
      return filename;
    }
    const dotIndex = filename.lastIndexOf('.');
    const base = dotIndex !== -1 ? filename.slice(0, dotIndex) : filename;
    const ext = dotIndex !== -1 ? filename.slice(dotIndex) : '';

    let counter = 1;
    let candidate = `${base} (${counter})${ext}`;
    while (existingNames.has(candidate)) {
      counter++;
      candidate = `${base} (${counter})${ext}`;
    }
    existingNames.add(candidate);
    return candidate;
  }

  async function init() {
    if (!shareId) {
      showError('Invalid URL', 'Share ID missing in path.');
      return;
    }

    // 1. Read URL fragment
    const hash = window.location.hash;
    if (!hash || hash.length <= 1) {
      showError(
        'Decryption Key Missing',
        'This link is missing the decryption fragment (#...). Without the decryption keys, the encrypted files cannot be opened.'
      );
      return;
    }

    // 2. Decode and validate fragment metadata
    let metadata;
    try {
      metadata = ObsidianCrypto.decodeMetadata(hash);
    } catch (err) {
      showError('Malformed Decryption Fragment', err.message);
      return;
    }

    const validation = ObsidianCrypto.validateMetadata(metadata, shareId);
    if (!validation.valid) {
      showError('Invalid Share Metadata', validation.error);
      return;
    }

    // 3. Fetch server collection manifest
    loadingText.textContent = 'Contacting server to verify encrypted collection...';
    let serverManifest;
    try {
      const resp = await fetch(`/api/files/${shareId}`);
      if (resp.status === 404) {
        showError(
          'Transfer unavailable',
          'The requested collection was not found on the server. Files may have become unavailable due to an instance restart or redeployment.'
        );
        return;
      }
      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        showError('Server Error', errJson.error || `Failed to retrieve collection (${resp.status}).`);
        return;
      }
      serverManifest = await resp.json();
    } catch (err) {
      showError('Network Error', `Network failure while fetching collection: ${err.message}`);
      return;
    }

    // 4. Cross-check client metadata with server manifest
    if (serverManifest.file_count !== metadata.files.length) {
      showError(
        'Collection Integrity Mismatch',
        `Server reports ${serverManifest.file_count} files, but link metadata specifies ${metadata.files.length}.`
      );
      return;
    }

    const serverFileMap = new Map();
    (serverManifest.files || []).forEach(f => serverFileMap.set(f.file_id, f));

    for (let i = 0; i < metadata.files.length; i++) {
      const metaFile = metadata.files[i];
      const sFile = serverFileMap.get(metaFile.file_id);
      if (!sFile) {
        showError('Missing Ciphertext', `Server does not contain file ID "${metaFile.file_id}".`);
        return;
      }
      // AES-GCM tag is 16 bytes. Check expected ciphertext size
      const expectedCipherSize = metaFile.size + 16;
      if (sFile.size !== expectedCipherSize) {
        showError(
          'Ciphertext Size Mismatch',
          `Size mismatch for "${metaFile.name}": Expected ${expectedCipherSize} bytes, server reported ${sFile.size} bytes.`
        );
        return;
      }
      metaFile.download_url = sFile.download_url || `/api/files/${shareId}/${metaFile.file_id}`;
    }

    // 5. Display collection info and unverified manifest
    const totalPlaintextBytes = metadata.files.reduce((sum, f) => sum + f.size, 0);
    collectionInfo.textContent = `${metadata.files.length} file(s) · ${formatBytes(totalPlaintextBytes)}`;

    renderFilesList(metadata.files);

    loadingSection.classList.add('hidden');
    recipientContent.classList.remove('hidden');

    // Automatically trigger decryption and cryptographic authentication
    startDecryption(metadata.files);
  }

  function renderFilesList(files) {
    recipientFileList.innerHTML = '';
    files.forEach((file, index) => {
      const row = document.createElement('div');
      row.className = 'file-row';
      row.id = `file-row-${index}`;
      row.setAttribute('role', 'listitem');

      const main = document.createElement('div');
      main.className = 'file-row-main';
      main.innerHTML = getFileSvgIcon();

      const nameSpan = document.createElement('span');
      nameSpan.className = 'file-row-name';
      nameSpan.textContent = file.name;
      nameSpan.title = file.name;
      main.appendChild(nameSpan);

      const meta = document.createElement('div');
      meta.className = 'file-row-meta';

      const sizeSpan = document.createElement('span');
      sizeSpan.className = 'file-row-size';
      sizeSpan.textContent = formatBytes(file.size);

      // Metadata is initially unauthenticated until AES-GCM succeeds
      const statusBadge = document.createElement('span');
      statusBadge.className = 'badge badge-pending';
      statusBadge.id = `status-${index}`;
      statusBadge.textContent = 'Pending verification';

      const actionBtn = document.createElement('button');
      actionBtn.className = 'btn btn-secondary btn-sm';
      actionBtn.id = `btn-dl-${index}`;
      actionBtn.disabled = true;
      actionBtn.textContent = 'Download';

      meta.appendChild(sizeSpan);
      meta.appendChild(statusBadge);
      meta.appendChild(actionBtn);

      row.appendChild(main);
      row.appendChild(meta);
      recipientFileList.appendChild(row);
    });
  }

  async function startDecryption(files) {
    decryptedFiles.length = 0;
    downloadAllBtn.disabled = true;
    setStatus('active', 'Authenticating...');

    let allSuccess = true;

    for (let i = 0; i < files.length; i++) {
      const fileMeta = files[i];
      const statusBadge = document.getElementById(`status-${i}`);
      const dlBtn = document.getElementById(`btn-dl-${i}`);

      if (statusBadge) {
        statusBadge.className = 'badge badge-authenticating';
        statusBadge.textContent = 'Authenticating...';
      }

      try {
        const downloadUrl = fileMeta.download_url || `/api/files/${shareId}/${fileMeta.file_id}`;
        const cipherResp = await fetch(downloadUrl);
        if (!cipherResp.ok) {
          throw new Error(`Failed to download ciphertext (${cipherResp.status})`);
        }
        const ciphertextBuffer = await cipherResp.arrayBuffer();

        // Decode key and nonce from metadata
        const rawKeyBytes = ObsidianCrypto.base64UrlToBuffer(fileMeta.key);
        const ivBytes = ObsidianCrypto.base64UrlToBuffer(fileMeta.iv);
        const cryptoKey = await ObsidianCrypto.importRawKey(rawKeyBytes);

        // Reconstruct exact Authenticated Additional Data (AAD)
        const aad = ObsidianCrypto.buildAdditionalData(
          shareId,
          fileMeta.file_id,
          fileMeta.name,
          fileMeta.type,
          fileMeta.size
        );

        // Decrypt and cryptographically verify authentication tag via Web Crypto AES-256-GCM
        const plaintextBuffer = await ObsidianCrypto.decryptFile(ciphertextBuffer, cryptoKey, ivBytes, aad);

        // Plaintext released ONLY upon authentication success
        const decryptedFileObj = {
          name: fileMeta.name,
          type: fileMeta.type,
          size: fileMeta.size,
          data: plaintextBuffer,
        };
        decryptedFiles[i] = decryptedFileObj;

        if (statusBadge) {
          statusBadge.className = 'badge badge-verified';
          statusBadge.textContent = 'Tag verified';
        }

        if (dlBtn) {
          dlBtn.disabled = false;
          dlBtn.onclick = () => downloadSingleFile(decryptedFileObj);
        }

      } catch (err) {
        console.error(`Decryption failed for "${fileMeta.name}":`, err);
        allSuccess = false;
        if (statusBadge) {
          statusBadge.className = 'badge badge-failed';
          statusBadge.textContent = 'Integrity verification failed';
        }
        if (dlBtn) {
          dlBtn.disabled = true;
        }
      }
    }

    if (decryptedFiles.some(f => f && f.data)) {
      downloadAllBtn.disabled = false;
    }

    if (allSuccess) {
      setStatus('success', 'All files verified');
    } else {
      setStatus('error', 'Verification failed');
      if (decryptBtn) {
        decryptBtn.style.display = 'inline-flex';
        decryptBtn.onclick = () => startDecryption(files);
      }
    }
  }

  function downloadSingleFile(fileObj) {
    const blob = new Blob([fileObj.data], { type: fileObj.type || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileObj.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }

  // Bulk ZIP Download via JSZip (Authenticated files only)
  downloadAllBtn.addEventListener('click', async () => {
    const authenticatedFiles = decryptedFiles.filter(f => f && f.data);
    if (authenticatedFiles.length === 0) {
      alert('No authenticated files are ready for download.');
      return;
    }

    if (typeof JSZip === 'undefined') {
      alert('JSZip library is not loaded.');
      return;
    }

    downloadAllBtn.disabled = true;
    const origText = downloadAllBtn.textContent;
    downloadAllBtn.textContent = 'Packaging ZIP...';

    try {
      const zip = new JSZip();
      const existingNames = new Set();

      authenticatedFiles.forEach(fileObj => {
        const uniqueName = deduplicateFilename(fileObj.name, existingNames);
        zip.file(uniqueName, fileObj.data);
      });

      const zipBlob = await zip.generateAsync({
        type: 'blob',
        compression: 'DEFLATE',
        compressionOptions: { level: 6 }
      });

      const url = URL.createObjectURL(zipBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `obsidian_transfer_${shareId.slice(0, 8)}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 10000);

    } catch (err) {
      console.error('ZIP generation error:', err);
      alert(`Failed to create ZIP package: ${err.message}`);
    } finally {
      downloadAllBtn.disabled = false;
      downloadAllBtn.textContent = origText;
    }
  });

  // Setup Info Dialogs (Security & Storage)
  function setupInfoModal(modalId, triggerIds, closeBtnIds) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    let returnTrigger = null;

    triggerIds.forEach(id => {
      const btn = document.getElementById(id);
      if (btn) {
        btn.addEventListener('click', () => {
          returnTrigger = btn;
          if (typeof modal.showModal === 'function') {
            modal.showModal();
          } else {
            modal.setAttribute('open', '');
          }
        });
      }
    });

    function closeModal() {
      if (typeof modal.close === 'function') {
        modal.close();
      } else {
        modal.removeAttribute('open');
      }
      if (returnTrigger && typeof returnTrigger.focus === 'function') {
        returnTrigger.focus();
      }
    }

    closeBtnIds.forEach(id => {
      const btn = document.getElementById(id);
      if (btn) {
        btn.addEventListener('click', closeModal);
      }
    });

    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });

    modal.addEventListener('cancel', () => {
      if (returnTrigger && typeof returnTrigger.focus === 'function') {
        setTimeout(() => returnTrigger.focus(), 0);
      }
    });
  }

  setupInfoModal('securityModal', ['headerSecurityBtn', 'footerSecurityBtn'], ['closeSecurityModalBtn', 'dismissSecurityModalBtn']);
  setupInfoModal('storageModal', ['headerStorageBtn', 'footerStorageBtn'], ['closeStorageModalBtn', 'dismissStorageModalBtn']);

  // Run on page load or immediately if DOM is already ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
