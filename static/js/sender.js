/**
 * Obsidian Secure V2 — Sender Controller (Technical Instrument Redesign)
 * Handles file staging, client-side AES-256-GCM encryption with AAD binding,
 * measured XHR byte upload progress, versioned fragment URL creation,
 * balanced 2-column transfer ready presentation, and persistent drag-and-drop.
 */
(function () {
  'use strict';

  // DOM Elements
  const emptyState = document.getElementById('emptyState');
  const dropZone = document.getElementById('dropZone');
  const compactDropZone = document.getElementById('compactDropZone');
  const fileInput = document.getElementById('fileInput');
  const selectFilesBtn = document.getElementById('selectFilesBtn');
  const addMoreBtn = document.getElementById('addMoreBtn');
  const fileListSection = document.getElementById('fileListSection');
  const fileList = document.getElementById('fileList');
  const fileSummary = document.getElementById('fileSummary');
  const encryptUploadBtn = document.getElementById('encryptUploadBtn');
  const clearAllBtn = document.getElementById('clearAllBtn');
  const progressSection = document.getElementById('progressSection');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');
  const progressPercent = document.getElementById('progressPercent');
  const progressDetail = document.getElementById('progressDetail');
  const successSection = document.getElementById('successSection');
  const shareUrlInput = document.getElementById('shareUrlInput');
  const copyLinkBtn = document.getElementById('copyLinkBtn');
  const qrSection = document.getElementById('qrSection');
  const qrContainer = document.getElementById('qrContainer');
  const downloadQrBtn = document.getElementById('downloadQrBtn');
  const enlargeQrBtn = document.getElementById('enlargeQrBtn');
  const qrModal = document.getElementById('qrModal');
  const modalQrContainer = document.getElementById('modalQrContainer');
  const closeQrModalBtn = document.getElementById('closeQrModalBtn');
  const modalDismissBtn = document.getElementById('modalDismissBtn');
  const modalDownloadQrBtn = document.getElementById('modalDownloadQrBtn');
  const shareNativeBtn = document.getElementById('shareNativeBtn');
  const shareMoreBtn = document.getElementById('shareMoreBtn');
  const errorBanner = document.getElementById('errorBanner');
  const errorMessage = document.getElementById('errorMessage');
  const statusDot = document.getElementById('statusDot');
  const statusLabel = document.getElementById('statusLabel');

  let selectedFiles = [];
  let lastFocusedTrigger = null;

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

  function showError(msg) {
    if (errorMessage && errorBanner) {
      errorMessage.textContent = msg;
      errorBanner.classList.remove('hidden');
    } else {
      alert(msg);
    }
    setStatus('error', 'Error');
  }

  function hideError() {
    if (errorBanner) {
      errorBanner.classList.add('hidden');
    }
  }

  function getFileSvgIcon() {
    return `<svg class="file-row-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>`;
  }

  function getRemoveSvgIcon() {
    return `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
  }

  function updateFileList() {
    fileList.innerHTML = '';
    if (selectedFiles.length === 0) {
      fileListSection.classList.add('hidden');
      if (emptyState) {
        emptyState.classList.remove('hidden');
      } else {
        dropZone.classList.remove('hidden');
      }
      setStatus('ready', 'Ready');
      return;
    }

    if (emptyState) {
      emptyState.classList.add('hidden');
    } else {
      dropZone.classList.add('hidden');
    }
    fileListSection.classList.remove('hidden');
    let totalBytes = 0;

    selectedFiles.forEach((file, index) => {
      totalBytes += file.size;
      const row = document.createElement('div');
      row.className = 'file-row';
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

      const removeBtn = document.createElement('button');
      removeBtn.className = 'btn-file-remove';
      removeBtn.type = 'button';
      removeBtn.setAttribute('aria-label', `Remove ${file.name}`);
      removeBtn.innerHTML = getRemoveSvgIcon();
      removeBtn.addEventListener('click', () => {
        selectedFiles.splice(index, 1);
        updateFileList();
      });

      meta.appendChild(sizeSpan);
      meta.appendChild(removeBtn);

      row.appendChild(main);
      row.appendChild(meta);
      fileList.appendChild(row);
    });

    fileSummary.textContent = `${selectedFiles.length} file(s) · ${formatBytes(totalBytes)}`;
    setStatus('ready', `${selectedFiles.length} file(s) staged`);
  }

  function addFiles(newFiles) {
    hideError();
    const allowedRemaining = ObsidianCrypto.MAX_FILE_COUNT - selectedFiles.length;
    if (newFiles.length > allowedRemaining) {
      showError(`Maximum limit is ${ObsidianCrypto.MAX_FILE_COUNT} files. You can add ${allowedRemaining} more.`);
      return;
    }

    let runningTotal = selectedFiles.reduce((sum, f) => sum + f.size, 0);

    for (let i = 0; i < newFiles.length; i++) {
      const f = newFiles[i];
      if (f.size === 0) {
        showError(`File "${f.name}" is empty (0 bytes) and cannot be encrypted.`);
        return;
      }
      if (f.size > ObsidianCrypto.MAX_FILE_SIZE) {
        showError(`File "${f.name}" exceeds the ${formatBytes(ObsidianCrypto.MAX_FILE_SIZE)} individual file limit.`);
        return;
      }
      runningTotal += f.size;
      if (runningTotal > (50 * 1024 * 1024)) {
        showError('Total collection size exceeds the 50 MB collection limit.');
        return;
      }
      selectedFiles.push(f);
    }
    updateFileList();
  }

  // File Picker Listeners
  selectFilesBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  if (addMoreBtn) {
    addMoreBtn.addEventListener('click', () => fileInput.click());
  }

  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  // Compact Persistent Drop Zone (Active when files are staged)
  if (compactDropZone) {
    compactDropZone.addEventListener('click', () => fileInput.click());
    compactDropZone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
      }
    });
    compactDropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      compactDropZone.classList.add('drag-over');
    });
    compactDropZone.addEventListener('dragleave', () => {
      compactDropZone.classList.remove('drag-over');
    });
    compactDropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      compactDropZone.classList.remove('drag-over');
      if (e.dataTransfer && e.dataTransfer.files) {
        addFiles(Array.from(e.dataTransfer.files));
      }
    });
  }

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      addFiles(Array.from(e.target.files));
      fileInput.value = '';
    }
  });

  // Large Drop Zone Drag and Drop Listeners
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    if (e.dataTransfer && e.dataTransfer.files) {
      addFiles(Array.from(e.dataTransfer.files));
    }
  });

  // Global Drop Target on Staged Manifest Area
  if (fileListSection) {
    fileListSection.addEventListener('dragover', (e) => {
      e.preventDefault();
      if (compactDropZone) compactDropZone.classList.add('drag-over');
    });
    fileListSection.addEventListener('dragleave', (e) => {
      if (e.relatedTarget && fileListSection.contains(e.relatedTarget)) return;
      if (compactDropZone) compactDropZone.classList.remove('drag-over');
    });
    fileListSection.addEventListener('drop', (e) => {
      e.preventDefault();
      if (compactDropZone) compactDropZone.classList.remove('drag-over');
      if (e.dataTransfer && e.dataTransfer.files) {
        addFiles(Array.from(e.dataTransfer.files));
      }
    });
  }

  clearAllBtn.addEventListener('click', () => {
    selectedFiles = [];
    updateFileList();
    hideError();
  });

  // Encrypt & Upload Execution
  encryptUploadBtn.addEventListener('click', async () => {
    if (selectedFiles.length === 0) {
      showError('Please choose at least one file to encrypt and transfer.');
      return;
    }
    hideError();

    encryptUploadBtn.disabled = true;
    clearAllBtn.disabled = true;
    if (addMoreBtn) addMoreBtn.disabled = true;

    // Show progress panel
    progressSection.classList.remove('hidden');
    progressBar.style.width = '0%';
    progressPercent.textContent = '0%';
    progressDetail.textContent = 'Generating 256-bit keys and preparing Web Crypto context...';
    setStatus('active', 'Encrypting...');

    try {
      const filesMetadata = [];
      const formData = new FormData();
      const totalFiles = selectedFiles.length;
      let totalBytes = 0;

      // 1. Generate 128-bit collection share ID upfront for AAD binding
      const shareId = ObsidianCrypto.randomOpaqueId(16);
      formData.append('share_id', shareId);

      for (let i = 0; i < totalFiles; i++) {
        const file = selectedFiles[i];
        totalBytes += file.size;

        progressText.textContent = `Encrypting file ${i + 1} of ${totalFiles}: ${file.name}`;
        progressPercent.textContent = `${Math.round(((i + 1) / totalFiles) * 100)}%`;
        progressBar.style.width = `${Math.round(((i + 1) / totalFiles) * 100)}%`;
        progressDetail.textContent = `Stage 1 of 2: Local AES-256-GCM encryption (${formatBytes(file.size)})`;

        // Generate opaque 128-bit file ID
        const fileId = ObsidianCrypto.randomOpaqueId(16);

        // Independent 256-bit key and fresh 96-bit nonce
        const key = await ObsidianCrypto.generateFileKey();
        const rawKeyBytes = await ObsidianCrypto.exportRawKey(key);
        const iv = ObsidianCrypto.generateNonce();

        // Canonical Authenticated Additional Data (AAD)
        const fileType = file.type || 'application/octet-stream';
        const aad = ObsidianCrypto.buildAdditionalData(shareId, fileId, file.name, fileType, file.size);

        // Encrypt via Web Crypto AES-256-GCM
        const plaintextBuffer = await file.arrayBuffer();
        const ciphertextBuffer = await ObsidianCrypto.encryptFile(plaintextBuffer, key, iv, aad);

        filesMetadata.push({
          file_id: fileId,
          name: file.name,
          type: fileType,
          size: file.size,
          key: ObsidianCrypto.bufferToBase64Url(rawKeyBytes),
          iv: ObsidianCrypto.bufferToBase64Url(iv),
        });

        const cipherBlob = new Blob([ciphertextBuffer], { type: 'application/octet-stream' });
        formData.append('files', cipherBlob, `${fileId}.enc`);
        formData.append('file_ids', fileId);
      }

      // 2. Upload Request Payload via XMLHttpRequest for Measured Progress
      progressBar.style.width = '0%';
      progressPercent.textContent = '0%';
      progressText.textContent = 'Uploading request payload...';
      progressDetail.textContent = 'Stage 2 of 2: Connecting to server...';
      setStatus('active', 'Uploading...');

      const uploadResult = await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload');

        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable && e.total > 0) {
            const percent = Math.min(100, Math.round((e.loaded / e.total) * 100));
            progressBar.style.width = `${percent}%`;
            progressPercent.textContent = `${percent}%`;
            progressDetail.textContent = `Stage 2 of 2: Transferred ${formatBytes(e.loaded)} of ${formatBytes(e.total)} (request payload)`;
          } else {
            progressBar.style.width = '100%';
            progressPercent.textContent = '';
            progressDetail.textContent = `Stage 2 of 2: Uploading (${formatBytes(e.loaded)} transferred)...`;
          }
        });

        xhr.addEventListener('load', () => {
          progressText.textContent = 'Finalizing transfer...';
          progressDetail.textContent = 'Server validating and writing encrypted collection...';
          if (xhr.status >= 200 && xhr.status < 300) {
            try {
              const res = JSON.parse(xhr.responseText);
              resolve(res);
            } catch (err) {
              reject(new Error('Invalid JSON response from server.'));
            }
          } else {
            let errMsg = `Upload failed with status ${xhr.status}`;
            try {
              const res = JSON.parse(xhr.responseText);
              if (res.error) errMsg = res.error;
            } catch (_) {}
            reject(new Error(errMsg));
          }
        });

        xhr.addEventListener('error', () => {
          reject(new Error('Network error during ciphertext upload.'));
        });

        xhr.send(formData);
      });

      if (!uploadResult.success) {
        throw new Error(uploadResult.error || 'Upload was not successful.');
      }

      progressBar.style.width = '100%';
      progressPercent.textContent = '100%';
      progressText.textContent = 'Transfer ready';
      progressDetail.textContent = `${totalFiles} file(s) encrypted and stored.`;
      setStatus('success', 'Transfer ready');

      // 3. Construct versioned client-side metadata and URL fragment
      const metadataObj = {
        v: 1,
        share_id: uploadResult.share_id,
        files: filesMetadata,
      };
      const fragment = ObsidianCrypto.encodeMetadata(metadataObj);
      const shareUrl = `${window.location.origin}/s/${uploadResult.share_id}#${fragment}`;

      shareUrlInput.value = shareUrl;

      // 4. QR Code Rendering with Overflow Detection & Modal Support
      qrContainer.innerHTML = '';
      if (modalQrContainer) modalQrContainer.innerHTML = '';
      const existingOverflow = document.getElementById('qrOverflowNotice');
      if (existingOverflow) existingOverflow.remove();

      if (typeof QRCode !== 'undefined') {
        if (shareUrl.length > 2950) {
          qrContainer.innerHTML = '<div style="color: var(--color-warning); font-size: 12px; text-align: center; padding: 14px;">QR unavailable (link exceeds 2,950 byte density limit).<br>Use direct link copying.</div>';
          downloadQrBtn.classList.add('hidden');
          if (enlargeQrBtn) enlargeQrBtn.classList.add('hidden');
          qrContainer.classList.remove('interactive');
          qrContainer.removeAttribute('role');
          qrContainer.removeAttribute('tabindex');
          qrContainer.removeAttribute('title');
          
          const overflowDiv = document.createElement('div');
          overflowDiv.id = 'qrOverflowNotice';
          overflowDiv.className = 'notice-box warning';
          overflowDiv.textContent = 'Share URL exceeds standard QR code density limit. Use the direct link above to share.';
          qrSection.parentNode.insertBefore(overflowDiv, qrSection.nextSibling);
        } else {
          try {
            // Normal Preview QR (180x180)
            new QRCode(qrContainer, {
              text: shareUrl,
              width: 180,
              height: 180,
              colorDark: '#0E1013',
              colorLight: '#FFFFFF',
              correctLevel: QRCode.CorrectLevel.L,
            });

            // Enlarged Modal QR (300x300, same URL & error correction)
            if (modalQrContainer) {
              new QRCode(modalQrContainer, {
                text: shareUrl,
                width: 300,
                height: 300,
                colorDark: '#0E1013',
                colorLight: '#FFFFFF',
                correctLevel: QRCode.CorrectLevel.L,
              });
              // Remove qrcode.min.js auto-generated title to prevent browser tooltip from overlapping enlarged QR
              modalQrContainer.removeAttribute('title');
              modalQrContainer.setAttribute('aria-label', 'Enlarged QR code');
            }

            // Remove native title to prevent overlapping URL tooltip while preserving accessibility via aria-label
            qrContainer.removeAttribute('title');
            qrContainer.setAttribute('aria-label', 'Enlarge QR code');

            downloadQrBtn.classList.remove('hidden');
            if (enlargeQrBtn) enlargeQrBtn.classList.remove('hidden');
            qrContainer.classList.add('interactive');
            qrContainer.setAttribute('role', 'button');
            qrContainer.setAttribute('tabindex', '0');
          } catch (qrErr) {
            console.warn('QR code generation failed:', qrErr);
            qrContainer.innerHTML = '<div style="color: var(--color-text-muted); font-size: 12px; text-align: center; padding: 14px;">QR generation failed for this URL length. Use direct link copying.</div>';
            downloadQrBtn.classList.add('hidden');
            if (enlargeQrBtn) enlargeQrBtn.classList.add('hidden');
            qrContainer.classList.remove('interactive');
          }
        }
      }

      // Check native device share capability
      if (navigator.share) {
        shareNativeBtn.classList.remove('hidden');
      } else {
        shareNativeBtn.classList.add('hidden');
      }

      // Transition views
      document.getElementById('uploadStage').classList.add('hidden');
      successSection.classList.remove('hidden');

    } catch (err) {
      console.error('Encryption or upload failed:', err);
      showError(err.message || 'An error occurred during encryption or upload.');
      progressSection.classList.add('hidden');
      encryptUploadBtn.disabled = false;
      clearAllBtn.disabled = false;
      if (addMoreBtn) addMoreBtn.disabled = false;
    }
  });

  // Modal Open / Close Logic with Focus Management
  function openQrModal(triggerEl) {
    if (!qrModal || !shareUrlInput.value || shareUrlInput.value.length > 2950) return;
    lastFocusedTrigger = triggerEl || document.activeElement;
    if (typeof qrModal.showModal === 'function') {
      qrModal.showModal();
    } else {
      qrModal.setAttribute('open', '');
    }
    if (closeQrModalBtn) {
      closeQrModalBtn.focus();
    }
  }

  function closeQrModal() {
    if (!qrModal) return;
    if (typeof qrModal.close === 'function') {
      qrModal.close();
    } else {
      qrModal.removeAttribute('open');
    }
    if (lastFocusedTrigger && typeof lastFocusedTrigger.focus === 'function') {
      lastFocusedTrigger.focus();
    }
  }

  // QR Modal Triggers
  if (enlargeQrBtn) {
    enlargeQrBtn.addEventListener('click', (e) => {
      e.preventDefault();
      openQrModal(enlargeQrBtn);
    });
  }

  qrContainer.addEventListener('click', () => {
    if (qrContainer.classList.contains('interactive')) {
      openQrModal(qrContainer);
    }
  });

  qrContainer.addEventListener('keydown', (e) => {
    if (qrContainer.classList.contains('interactive') && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      openQrModal(qrContainer);
    }
  });

  if (closeQrModalBtn) {
    closeQrModalBtn.addEventListener('click', closeQrModal);
  }

  if (modalDismissBtn) {
    modalDismissBtn.addEventListener('click', closeQrModal);
  }

  if (qrModal) {
    // Backdrop click dismissal: clicking on the dialog element outside its content box
    qrModal.addEventListener('click', (e) => {
      if (e.target === qrModal) {
        closeQrModal();
      }
    });

    // Native cancel event (Escape key pressed in <dialog>)
    qrModal.addEventListener('cancel', () => {
      if (lastFocusedTrigger && typeof lastFocusedTrigger.focus === 'function') {
        setTimeout(() => lastFocusedTrigger.focus(), 0);
      }
    });
  }

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

  // Copy share URL with visual confirmation
  copyLinkBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(shareUrlInput.value);
      const originalText = copyLinkBtn.innerHTML;
      copyLinkBtn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
      copyLinkBtn.style.backgroundColor = 'var(--color-success)';
      copyLinkBtn.style.color = '#0E1013';
      copyLinkBtn.style.borderColor = 'var(--color-success)';
      setTimeout(() => {
        copyLinkBtn.innerHTML = originalText;
        copyLinkBtn.style.backgroundColor = '';
        copyLinkBtn.style.color = '';
        copyLinkBtn.style.borderColor = '';
      }, 2000);
    } catch (err) {
      shareUrlInput.select();
      document.execCommand('copy');
      const originalText = copyLinkBtn.innerHTML;
      copyLinkBtn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
      setTimeout(() => { copyLinkBtn.innerHTML = originalText; }, 2000);
    }
  });

  // Native device share
  shareNativeBtn.addEventListener('click', async () => {
    if (navigator.share) {
      try {
        await navigator.share({
          title: 'Obsidian Secure File Transfer',
          text: 'Encrypted file transfer link:',
          url: shareUrlInput.value,
        });
      } catch (err) {
        if (err.name !== 'AbortError') {
          console.warn('Native share failed:', err);
        }
      }
    }
  });

  // Download QR Code PNG (uses high-resolution modal container if available, with standard quiet zone)
  function downloadQrImage() {
    const sourceContainer = (modalQrContainer && modalQrContainer.querySelector('canvas, img')) 
      ? modalQrContainer 
      : qrContainer;
    const canvas = sourceContainer.querySelector('canvas');
    const img = sourceContainer.querySelector('img');
    const sourceEl = (canvas && canvas.width > 0) ? canvas : ((img && img.src) ? img : null);

    if (sourceEl) {
      const quiet = 24;
      const srcW = sourceEl.naturalWidth || sourceEl.width || 300;
      const srcH = sourceEl.naturalHeight || sourceEl.height || 300;
      const exportCanvas = document.createElement('canvas');
      exportCanvas.width = srcW + (quiet * 2);
      exportCanvas.height = srcH + (quiet * 2);
      const ctx = exportCanvas.getContext('2d');
      ctx.fillStyle = '#FFFFFF';
      ctx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);
      ctx.drawImage(sourceEl, quiet, quiet, srcW, srcH);

      const dataUrl = exportCanvas.toDataURL('image/png');
      const a = document.createElement('a');
      a.href = dataUrl;
      a.download = 'obsidian_transfer_qr.png';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } else {
      showError('Could not generate QR image for download.');
    }
  }

  downloadQrBtn.addEventListener('click', downloadQrImage);
  if (modalDownloadQrBtn) {
    modalDownloadQrBtn.addEventListener('click', downloadQrImage);
  }

  // Start another transfer / Reset
  shareMoreBtn.addEventListener('click', () => {
    closeQrModal();
    selectedFiles = [];
    updateFileList();
    shareUrlInput.value = '';
    qrContainer.innerHTML = '';
    if (modalQrContainer) modalQrContainer.innerHTML = '';
    const existingOverflow = document.getElementById('qrOverflowNotice');
    if (existingOverflow) existingOverflow.remove();
    successSection.classList.add('hidden');
    progressSection.classList.add('hidden');
    document.getElementById('uploadStage').classList.remove('hidden');
    if (emptyState) emptyState.classList.remove('hidden');
    encryptUploadBtn.disabled = false;
    clearAllBtn.disabled = false;
    if (addMoreBtn) addMoreBtn.disabled = false;
    setStatus('ready', 'Ready');
    hideError();
  });

})();
