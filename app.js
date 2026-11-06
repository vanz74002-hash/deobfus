document.addEventListener('DOMContentLoaded', () => {
  const codeInput = document.getElementById('codeInput');
  const fileInput = document.getElementById('fileInput');
  const fileName = document.getElementById('fileName');
  const deobfBtn = document.getElementById('deobfBtn');
  const logContent = document.getElementById('logContent');
  const logStatus = document.getElementById('logStatus');
  const progressFill = document.getElementById('progressFill');
  const progressText = document.getElementById('progressText');
  const orbStage = document.getElementById('orbStage');
  const taskPanel = document.getElementById('taskPanel');
  const inputPanel = document.getElementById('inputPanel');

  let isProcessing = false;

  // File upload
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      fileName.textContent = file.name;
      const reader = new FileReader();
      reader.onload = (event) => { codeInput.value = event.target.result; };
      reader.readAsText(file);
    }
  });

  // Helper: timestamp
  const ts = () => {
    const d = new Date();
    return `[${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}]`;
  };

  // Helper: add log entry
  const addLog = (msg, type = 'info') => {
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
      <span class="log-time">${ts()}</span>
      <span class="log-arrow">&gt;</span>
      <span class="log-msg ${type}">${msg}</span>
    `;
    logContent.appendChild(entry);
    logContent.scrollTop = logContent.scrollHeight;
  };

  // Helper: clear log
  const clearLog = () => { logContent.innerHTML = ''; };

  // Helper: set status
  const setStatus = (state, text) => {
    const dot = logStatus.querySelector('.status-dot');
    const txt = logStatus.querySelector('.status-text');
    dot.className = `status-dot ${state}`;
    txt.textContent = text;
  };

  // Helper: progress
  const setProgress = (pct) => {
    progressFill.style.width = `${pct}%`;
    progressText.textContent = `${Math.round(pct)}%`;
  };

  // Helper: animate progress smoothly
  const animateProgress = (from, to, duration) => {
    const start = performance.now();
    const step = (now) => {
      const elapsed = now - start;
      const t = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      setProgress(from + (to - from) * eased);
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };

  // Helper: complete task with animation
  const completeTask = (id, delay = 0) => {
    return new Promise((resolve) => {
      setTimeout(() => {
        const task = document.getElementById(id);
        const connector = task.nextElementSibling;
        task.classList.add('completed');
        if (connector && connector.classList.contains('task-connector')) {
          connector.classList.add('active');
        }
        resolve();
      }, delay);
    });
  };

  // Helper: sleep
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  // Main deobfuscation flow
  deobfBtn.addEventListener('click', async () => {
    if (isProcessing) return;
    const code = codeInput.value.trim();
    if (!code) {
      alert('Payload kosong, Boss. Masukin kode dulu.');
      return;
    }

    isProcessing = true;
    deobfBtn.classList.add('loading');
    deobfBtn.disabled = true;

    // Reset UI
    clearLog();
    taskPanel.style.display = 'none';
    orbStage.style.display = 'flex';
    inputPanel.style.opacity = '0.5';
    inputPanel.style.pointerEvents = 'none';

    // Reset tasks
    ['task1', 'task2', 'task3'].forEach(id => {
      document.getElementById(id).classList.remove('completed');
    });
    document.querySelectorAll('.task-connector').forEach(c => c.classList.remove('active'));

    setStatus('running', 'Running...');
    setProgress(0);

    try {
      // === PHASE 1: SCAN ===
      addLog('Starting scan for obfuscation type...', 'info');
      await sleep(400);
      animateProgress(0, 15, 500);

      addLog('Analyzing code structure...', 'info');
      await sleep(500);
      animateProgress(15, 30, 500);

      addLog('Running 21-engine cascade detection...', 'info');
      await sleep(600);
      animateProgress(30, 45, 500);

      // Call API
      const response = await fetch('/api/deobfuscate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });

      const data = await response.json();

      if (!data.success) {
        addLog(`Detection failed: ${data.message || data.error}`, 'error');
        setStatus('idle', 'Failed');
        setProgress(0);
        resetUI();
        return;
      }

      // Task 1 complete
      addLog(`Obfuscation detected: ${data.detectedEngine} (confidence: ${(data.detection.confidence * 100).toFixed(1)}%)`, 'highlight');
      await sleep(400);
      animateProgress(45, 60, 400);
      await completeTask('task1', 300);

      // === PHASE 2: DEOBFUSCATION ===
      addLog('Starting deobfuscation...', 'info');
      await sleep(400);
      animateProgress(60, 75, 500);

      if (data.deobfuscation && data.deobfuscation.appliedLevels) {
        for (const lvl of data.deobfuscation.appliedLevels) {
          addLog(`Applied: ${lvl.level} (${lvl.changes} changes)`, 'info');
          await sleep(200);
        }
      }

      addLog('Deobfuscation completed successfully.', 'success');
      await sleep(400);
      animateProgress(75, 90, 500);
      await completeTask('task2', 300);

      // === PHASE 3: CREATE FILE ===
      addLog('Creating output file...', 'info');
      await sleep(300);

      const output = data.deobfuscation?.deobfuscatedCode || code;
      const blob = new Blob([output], { type: 'text/plain' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `deobfuscated_${data.detectedEngine.toLowerCase()}.txt`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      addLog(`File saved: deobfuscated_${data.detectedEngine.toLowerCase()}.txt`, 'success');
      await sleep(300);
      animateProgress(90, 100, 400);
      await completeTask('task3', 300);

      // Transition: hide orb, show task panel
      await sleep(500);
      orbStage.style.display = 'none';
      taskPanel.style.display = 'block';
      setStatus('success', 'Completed');

    } catch (err) {
      addLog(`Error: ${err.message}`, 'error');
      setStatus('idle', 'Error');
      setProgress(0);
    } finally {
      resetUI();
    }
  });

  const resetUI = () => {
    isProcessing = false;
    deobfBtn.classList.remove('loading');
    deobfBtn.disabled = false;
    inputPanel.style.opacity = '1';
    inputPanel.style.pointerEvents = 'auto';
  };

  // Fetch engine count
  fetch('/api/engines')
    .then(r => r.json())
    .then(d => {
      const el = document.getElementById('engineCount');
      if (el) el.textContent = `${d.total} ENGINES LOADED`;
    })
    .catch(() => {});
});
