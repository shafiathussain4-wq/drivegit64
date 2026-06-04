const state = {
  currentPath: '',
  view: 'drive',
  viewMode: 'grid',
  selected: null,
  clipboard: null,
  currentItems: [],
  searchQuery: '',
};

const el = id => document.getElementById(id);
const API = {
  list: p => fetch(`/api/files?path=${encodeURIComponent(p || '')}`, { credentials: 'same-origin' }).then(r => r.json()),
  tree: _ => fetch('/api/tree', { credentials: 'same-origin' }).then(r => r.json()),
  search: (q, max) => fetch(`/api/search?q=${encodeURIComponent(q)}${max ? '&max='+max : ''}`, { credentials: 'same-origin' }).then(r => r.json()),
  upload: (fd, path) => fetch(`/api/upload?path=${encodeURIComponent(path || '')}`, { method: 'POST', body: fd, credentials: 'same-origin' }),
  rename: (path, name) => fetch('/api/rename', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({path, name}), credentials: 'same-origin' }).then(r => r.json()),
  move: (items, dest) => fetch('/api/move', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({items, destination: dest}), credentials: 'same-origin' }).then(r => r.json()),
  mkdir: (path, name) => fetch('/api/folders', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({path, name}), credentials: 'same-origin' }).then(r => r.json()),
  delete: p => fetch(`/api/files?path=${encodeURIComponent(p)}`, { method: 'DELETE', credentials: 'same-origin' }).then(r => r.json()),
  trash: _ => fetch('/api/trash', { credentials: 'same-origin' }).then(r => r.json()),
  restore: p => fetch('/api/trash/restore', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({path: p}), credentials: 'same-origin' }).then(r => r.json()),
  emptyTrash: _ => fetch('/api/trash', { method: 'DELETE', credentials: 'same-origin' }).then(r => r.json()),
  share: p => fetch('/api/share', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({path: p}), credentials: 'same-origin' }).then(r => r.json()),
  shares: _ => fetch('/api/share', { credentials: 'same-origin' }).then(r => r.json()),
  stats: _ => fetch('/api/stats', { credentials: 'same-origin' }).then(r => r.json()),
};

// === AUTH ===
let currentUser = null;
let authMode = 'signin';

function checkAuth() {
  return fetch('/api/auth/me', { credentials: 'same-origin' })
    .then(r => r.json())
    .then(data => {
      if (data.authenticated === false || data.error) {
        showLogin();
        return false;
      }
      currentUser = data;
      showDrive();
      updateUserInfo(data);
      el('adminNav').style.display = data.admin ? '' : 'none';
      return true;
    })
    .catch(() => {
      showLogin();
      return false;
    });
}

function showLogin() {
  el('loginScreen').style.display = 'flex';
  el('driveApp').style.display = 'none';
}

function showDrive() {
  el('loginScreen').style.display = 'none';
  el('driveApp').style.display = 'flex';
}

function updateUserInfo(user) {
  el('userName').textContent = user.name;
  el('userEmail').textContent = user.email;
}

// Auth tabs
document.querySelectorAll('.auth-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    authMode = tab.dataset.tab;
    el('signinFields').style.display = authMode === 'signin' ? 'block' : 'none';
    el('signupFields').style.display = authMode === 'signup' ? 'block' : 'none';
    el('loginSubtitle').textContent = authMode === 'signin' ? 'Sign in to your account' : 'Create a new account';
    el('authError').textContent = '';
  });
});

// Auth helpers
function doSignin() {
  const email = el('signinEmail').value.trim();
  const password = el('signinPassword').value;
  el('authError').textContent = '';
  el('authError').style.color = '';
  if (!email || !password) { el('authError').textContent = 'Please fill in all fields'; return; }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  fetch('/api/auth/signin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'same-origin',
    signal: controller.signal,
  })
  .then(r => { clearTimeout(timer); return r.json(); })
  .then(data => {
    if (data.error) { el('authError').textContent = data.error; return; }
    if (data.success) { currentUser = data.user; showDrive(); updateUserInfo(data.user); loadFolder(''); loadStats(); }
  })
  .catch(err => {
    clearTimeout(timer);
    el('authError').textContent = err.name === 'AbortError' ? 'Request timed out' : 'Connection error';
  });
}
function doSignup() {
  const name = el('signupName').value.trim();
  const email = el('signupEmail').value.trim();
  const password = el('signupPassword').value;
  el('authError').textContent = '';
  if (!name || !email || !password) { el('authError').textContent = 'Please fill in all fields'; return; }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  fetch('/api/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, name, password }),
    credentials: 'same-origin',
    signal: controller.signal,
  })
  .then(r => { clearTimeout(timer); return r.json(); })
  .then(data => {
    if (data.error) { el('authError').textContent = data.error; return; }
    if (data.verificationSent) { el('authError').style.color = 'var(--success)'; el('authError').textContent = 'Verification email sent to ' + email + '. Check your inbox.'; return; }
    if (data.success) { currentUser = data.user; showDrive(); updateUserInfo(data.user); loadFolder(''); loadStats(); }
  })
  .catch(err => {
    clearTimeout(timer);
    el('authError').textContent = err.name === 'AbortError' ? 'Request timed out' : 'Connection error';
  });
}
el('authForm').addEventListener('submit', e => { e.preventDefault(); authMode === 'signin' ? doSignin() : doSignup(); });
el('authSubmitBtn').addEventListener('click', e => { e.preventDefault(); doSignin(); });

el('logoutBtn').addEventListener('click', () => {
  fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
    .then(() => { currentUser = null; showLogin(); })
    .catch(() => { currentUser = null; showLogin(); });
});

// === NAVIGATION ===
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    const view = item.dataset.view;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    if (view === 'drive') { state.currentPath = ''; navigate('drive'); }
    else if (view === 'trash') navigate('trash');
    else if (view === 'search') navigate('search');
    else if (view === 'shared') navigate('shared');
    else if (view === 'settings') navigate('settings');
    else if (view === 'admin') navigate('admin');
  });
});

function navigate(view, data) {
  state.view = view;
  const container = el('view-container');
  const settingsPanel = el('settingsPanel');
  const adminPanel = el('adminPanel');
  container.style.display = view === 'settings' || view === 'admin' ? 'none' : '';
  settingsPanel.style.display = view === 'settings' ? 'block' : 'none';
  adminPanel.style.display = view === 'admin' ? 'block' : 'none';
  container.innerHTML = '';
  if (view === 'drive') loadFolder(state.currentPath);
  else if (view === 'trash') loadTrash();
  else if (view === 'search') showSearch();
  else if (view === 'shared') loadShared();
  else if (view === 'settings') loadSettings();
  else if (view === 'admin') loadAdmin();
}

// === LOAD FOLDER ===
function loadFolder(dirPath) {
  state.currentPath = dirPath || '';
  state.view = 'drive';
  const container = el('view-container');
  container.innerHTML = '<div class="empty-state"><p>Loading...</p></div>';
  renderBreadcrumb(dirPath);
  API.list(dirPath).then(items => {
    state.currentItems = items;
    renderFiles(items);
    updateSidebarNav();
  }).catch(() => {
    container.innerHTML = '<div class="empty-state"><p>Error loading folder</p></div>';
  });
}

function renderBreadcrumb(path) {
  const bc = el('breadcrumb');
  const parts = path ? path.split('/') : [];
  let html = `<span class="breadcrumb-item${!path ? ' active' : ''}" onclick="loadFolder('')">My Drive</span>`;
  let cum = '';
  for (const p of parts) {
    cum = cum ? cum + '/' + p : p;
    const isLast = cum === path;
    html += `<span class="breadcrumb-sep">/</span>`;
    html += `<span class="breadcrumb-item${isLast ? ' active' : ''}" onclick="${isLast ? '' : `loadFolder('${cum}')`}">${escHtml(p)}</span>`;
    if (isLast) break;
  }
  bc.innerHTML = html;
}

function renderFiles(items) {
  const container = el('view-container');
  if (!items || !items.length) {
    container.innerHTML = `
      <div class="empty-state">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
        <p>This folder is empty</p>
        <span class="hint">Click "New" or drag files here to add them</span>
      </div>`;
    return;
  }
  if (state.viewMode === 'grid') renderGrid(items);
  else renderList(items);
}

// === GRID VIEW ===
function renderGrid(items) {
  const container = el('view-container');
  container.innerHTML = `<div class="files-grid" id="fileGrid"></div>`;
  const grid = el('fileGrid');
  for (const item of items) {
    const card = document.createElement('div');
    card.className = 'file-card';
    card.dataset.path = item.path;
    card.innerHTML = `
      <div class="file-icon-wrap ${getIconClass(item)}">${getIcon(item)}</div>
      <div class="file-card-name" title="${escHtml(item.name)}">${escHtml(item.name)}</div>
      <div class="file-card-meta">${item.sizeFormatted || ''}</div>`;
    card.addEventListener('click', e => onFileClick(e, item));
    card.addEventListener('dblclick', () => onFileDblClick(item));
    card.addEventListener('contextmenu', e => showContextMenu(e, item));
    grid.appendChild(card);
  }
}

// === LIST VIEW ===
function renderList(items) {
  const container = el('view-container');
  container.innerHTML = `<div class="files-list" id="fileList"></div>`;
  const list = el('fileList');
  for (const item of items) {
    const row = document.createElement('div');
    row.className = 'list-item';
    row.dataset.path = item.path;
    row.innerHTML = `
      <div class="file-icon-wrap ${getIconClass(item)}" style="width:32px;height:32px;font-size:1rem;display:flex;align-items:center;justify-content:center;border-radius:6px;flex-shrink:0">${getIcon(item)}</div>
      <span class="list-name">${escHtml(item.name)}</span>
      <span class="list-meta">${item.sizeFormatted || '—'}</span>
      <span class="list-modified">${item.modified ? fmtDate(item.modified) : '—'}</span>`;
    row.addEventListener('click', e => onFileClick(e, item));
    row.addEventListener('dblclick', () => onFileDblClick(item));
    row.addEventListener('contextmenu', e => showContextMenu(e, item));
    list.appendChild(row);
  }
}

// === FILE INTERACTIONS ===
function onFileClick(e, item) {
  document.querySelectorAll('.file-card.selected, .list-item.selected').forEach(el => el.classList.remove('selected'));
  const parent = e.currentTarget;
  parent.classList.add('selected');
  state.selected = item;
}

function onFileDblClick(item) {
  if (item.type === 'folder') {
    loadFolder(item.path);
  } else {
    previewFile(item);
  }
}

// === ICONS ===
function getIconClass(item) {
  if (item.type === 'folder') return 'file-icon-folder';
  const ext = (item.name || '').split('.').pop().toLowerCase();
  if (ext === 'pdf') return 'file-icon-pdf';
  if (['jpg','jpeg','png','gif','svg','webp','ico','bmp'].includes(ext)) return 'file-icon-image';
  if (['mp4','webm','avi','mkv','mov','wmv'].includes(ext)) return 'file-icon-video';
  if (['mp3','wav','ogg','flac','aac','m4a'].includes(ext)) return 'file-icon-audio';
  if (['zip','tar','gz','rar','7z','bz2'].includes(ext)) return 'file-icon-archive';
  if (['js','ts','py','java','c','cpp','cs','go','rs','rb','php','swift','html','css'].includes(ext)) return 'file-icon-code';
  if (['doc','docx','xls','xlsx','ppt','pptx','txt','md','rtf'].includes(ext)) return 'file-icon-doc';
  return 'file-icon-file';
}

function getIcon(item) {
  if (item.type === 'folder') {
    return `<svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor" opacity="0.8"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>`;
  }
  return `<svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor" opacity="0.6"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6z"/><path d="M14 2v6h6" fill="none" stroke="currentColor" stroke-width="2" opacity="0.4"/></svg>`;
}

// === VIEW TOGGLE ===
el('viewToggle').addEventListener('click', () => {
  state.viewMode = state.viewMode === 'grid' ? 'list' : 'grid';
  if (state.view === 'drive') renderFiles(state.currentItems);
});

// === SEARCH ===
let searchTimer;
el('searchInput').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    const q = el('searchInput').value.trim();
    if (q.length >= 2) {
      state.searchQuery = q;
      navigate('search');
      doSearch(q);
    } else if (!q && state.view === 'search') {
      navigate('drive');
    }
  }, 300);
});

function showSearch() {
  const q = el('searchInput').value.trim();
  const container = el('view-container');
  container.innerHTML = `
    <div class="search-header">
      <h2>Search Results</h2>
      <p>${q ? `Showing results for "${escHtml(q)}"` : 'Type to search...'}</p>
    </div>
    <div id="searchResults"></div>`;
  if (q) doSearch(q);
}

function doSearch(q) {
  const results = el('searchResults');
  if (!results) return;
  results.innerHTML = '<div class="empty-state"><p>Searching...</p></div>';
  API.search(q).then(items => {
    if (!items || !items.length) {
      results.innerHTML = '<div class="no-results">No files match your search</div>';
      return;
    }
    if (state.viewMode === 'grid') {
      results.innerHTML = '<div class="files-grid"></div>';
      const grid = results.querySelector('.files-grid');
      for (const item of items) {
        const card = document.createElement('div');
        card.className = 'file-card';
        card.innerHTML = `
          <div class="file-icon-wrap ${getIconClass(item)}">${getIcon(item)}</div>
          <div class="file-card-name" title="${escHtml(item.path)}">${escHtml(item.path)}</div>
          <div class="file-card-meta">${item.sizeFormatted || ''}</div>`;
        card.addEventListener('dblclick', () => {
          if (item.type === 'folder') loadFolder(item.path);
          else previewFile(item);
        });
        card.addEventListener('contextmenu', e => showContextMenu(e, item));
        grid.appendChild(card);
      }
    } else {
      results.innerHTML = '<div class="files-list"></div>';
      const list = results.querySelector('.files-list');
      for (const item of items) {
        const row = document.createElement('div');
        row.className = 'list-item';
        row.innerHTML = `
          <div class="file-icon-wrap ${getIconClass(item)}" style="width:32px;height:32px;font-size:1rem;display:flex;align-items:center;justify-content:center;border-radius:6px;flex-shrink:0">${getIcon(item)}</div>
          <span class="list-name">${escHtml(item.path)}</span>
          <span class="list-meta">${item.sizeFormatted || '—'}</span>`;
        row.addEventListener('dblclick', () => {
          if (item.type === 'folder') loadFolder(item.path);
          else previewFile(item);
        });
        row.addEventListener('contextmenu', e => showContextMenu(e, item));
        list.appendChild(row);
      }
    }
  });
}

// === UPLOAD ===
el('uploadBtn').addEventListener('click', () => el('fileInput').click());
el('fileInput').addEventListener('change', () => {
  if (el('fileInput').files.length) uploadFiles(el('fileInput').files);
  el('fileInput').value = '';
});
el('folderInput').addEventListener('change', () => {
  if (el('folderInput').files.length) uploadFiles(el('folderInput').files);
  el('folderInput').value = '';
});

// Drag & drop
document.addEventListener('dragover', e => e.preventDefault());
document.addEventListener('drop', e => e.preventDefault());

document.addEventListener('dragenter', e => {
  if (e.dataTransfer.types.includes('Files')) {
    if (!document.querySelector('.drag-overlay')) {
      const overlay = document.createElement('div');
      overlay.className = 'drag-overlay';
      document.body.appendChild(overlay);
    }
  }
});

document.addEventListener('dragleave', e => {
  if (!e.relatedTarget || e.relatedTarget.nodeName === 'HTML') {
    const overlay = document.querySelector('.drag-overlay');
    if (overlay) overlay.remove();
  }
});

document.addEventListener('drop', e => {
  document.querySelector('.drag-overlay')?.remove();
  if (e.dataTransfer.files.length) uploadFiles(e.dataTransfer.files);
});

function uploadFiles(files) {
  const fd = new FormData();
  for (const f of files) fd.append('file', f);
  const toast = document.createElement('div');
  toast.className = 'upload-toast';
  toast.textContent = `Uploading ${files.length} file(s)...`;
  document.body.appendChild(toast);
  API.upload(fd, state.currentPath).then(r => {
    toast.textContent = r.uploaded ? `${r.uploaded} file(s) uploaded` : 'Upload complete';
    setTimeout(() => toast.remove(), 2000);
    if (state.view === 'drive') loadFolder(state.currentPath);
    loadStats();
  }).catch(() => {
    toast.textContent = 'Upload failed';
    setTimeout(() => toast.remove(), 2000);
  });
}

// === PREVIEW ===
function previewFile(item) {
  const modal = el('previewModal');
  el('previewTitle').textContent = item.name;
  const body = el('previewBody');
  const ext = (item.name || '').split('.').pop().toLowerCase();
  const previewUrl = `/api/preview?path=${encodeURIComponent(item.path)}`;

  if (['jpg','jpeg','png','gif','svg','webp','ico','bmp'].includes(ext)) {
    body.innerHTML = `<img src="${previewUrl}" alt="${escHtml(item.name)}">`;
  } else if (['mp4','webm','avi','mkv','mov'].includes(ext)) {
    body.innerHTML = `<video controls autoplay><source src="${previewUrl}"></video>`;
  } else if (['mp3','wav','ogg','flac','aac','m4a'].includes(ext)) {
    body.innerHTML = `<audio controls autoplay><source src="${previewUrl}"></audio>`;
  } else if (ext === 'pdf') {
    body.innerHTML = `<iframe src="${previewUrl}"></iframe>`;
  } else if (['txt','md','js','ts','py','html','css','json','xml','csv','sh','bat','ps1','yml','yaml','ini','cfg','conf','log'].includes(ext)) {
    body.innerHTML = `<pre>Loading...</pre>`;
    fetch(previewUrl).then(r => r.text()).then(t => { body.innerHTML = `<pre>${escHtml(t)}</pre>`; }).catch(() => { body.innerHTML = '<pre>Error loading file</pre>'; });
  } else {
    body.innerHTML = `<div class="empty-state"><p>Preview not available for this file type</p><a class="btn-primary" href="/api/download?path=${encodeURIComponent(item.path)}" style="margin-top:16px;text-decoration:none">Download</a></div>`;
  }
  modal.style.display = 'flex';
}

el('previewClose').addEventListener('click', () => { el('previewModal').style.display = 'none'; el('previewBody').innerHTML = ''; });
el('previewModal').addEventListener('click', e => { if (e.target.classList.contains('modal-backdrop')) { el('previewModal').style.display = 'none'; el('previewBody').innerHTML = ''; } });

// === SHARE ===
function shareFile(item) {
  const modal = el('shareModal');
  el('shareLinkInput').value = 'Generating...';
  el('shareHint').style.display = 'none';
  modal.style.display = 'flex';
  API.share(item.path).then(r => {
    const url = `${window.location.origin}${r.url}`;
    el('shareLinkInput').value = url;
  }).catch(() => {
    el('shareLinkInput').value = 'Failed to generate link';
  });
}

el('shareClose').addEventListener('click', () => { el('shareModal').style.display = 'none'; });
el('shareModal').addEventListener('click', e => { if (e.target.classList.contains('modal-backdrop')) el('shareModal').style.display = 'none'; });
el('copyLinkBtn').addEventListener('click', () => {
  const input = el('shareLinkInput');
  input.select();
  navigator.clipboard.writeText(input.value);
  el('shareHint').textContent = 'Copied to clipboard!';
  el('shareHint').style.display = 'block';
  setTimeout(() => { el('shareHint').style.display = 'none'; }, 2000);
});

// === CONTEXT MENU ===
let contextTarget = null;
function showContextMenu(e, item) {
  e.preventDefault();
  contextTarget = item;
  const menu = el('contextMenu');
  // Disable preview for folders
  const previewItem = menu.querySelector('[data-action="preview"]');
  if (previewItem) previewItem.style.display = item.type === 'folder' ? 'none' : 'flex';
  menu.style.left = e.clientX + 'px';
  menu.style.top = e.clientY + 'px';
  menu.style.display = 'block';
  document.addEventListener('click', hideContextMenu, { once: true });
}

function hideContextMenu() {
  el('contextMenu').style.display = 'none';
}

el('contextMenu').querySelectorAll('.menu-item').forEach(item => {
  item.addEventListener('click', () => {
    const action = item.dataset.action;
    if (!contextTarget) return;
    if (action === 'preview') previewFile(contextTarget);
    else if (action === 'download') window.open(`/api/download?path=${encodeURIComponent(contextTarget.path)}`);
    else if (action === 'copylink') {
      if (contextTarget.type === 'folder') {
        API.share(contextTarget.path).then(r => {
          const url = `${window.location.origin}${r.url}`;
          navigator.clipboard.writeText(url);
          showToast('Share link copied to clipboard');
        }).catch(() => showToast('Failed to create share link'));
      } else {
        const url = `${window.location.origin}/api/download?path=${encodeURIComponent(contextTarget.path)}`;
        navigator.clipboard.writeText(url);
        showToast('Download link copied to clipboard');
      }
    }
    else if (action === 'share') shareFile(contextTarget);
    else if (action === 'rename') renameFile(contextTarget);
    else if (action === 'move') showMoveDialog(contextTarget);
    else if (action === 'delete') deleteFile(contextTarget);
    hideContextMenu();
  });
});

// === RENAME ===
function renameFile(item) {
  const cell = document.querySelector(`[data-path="${item.path}"]`);
  if (!cell) return;
  const nameEl = cell.querySelector('.file-card-name') || cell.querySelector('.list-name');
  if (!nameEl) return;
  const oldName = item.name;
  nameEl.innerHTML = `<input class="rename-input" type="text" value="${escHtml(oldName)}" autofocus>`;
  const input = nameEl.querySelector('input');
  input.select();
  const finish = () => {
    const newName = input.value.trim();
    if (newName && newName !== oldName) {
      API.rename(item.path, newName).then(r => {
        if (r.success) loadFolder(state.currentPath);
        else nameEl.textContent = oldName;
      }).catch(() => { nameEl.textContent = oldName; });
    } else {
      nameEl.textContent = oldName;
    }
  };
  input.addEventListener('blur', finish);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') { input.blur(); } if (e.key === 'Escape') { nameEl.textContent = oldName; } });
}

// === DELETE (to trash) ===
function deleteFile(item) {
  API.delete(item.path).then(r => {
    if (r.success) {
      showToast(`Moved "${item.name}" to trash`);
      loadFolder(state.currentPath);
      loadStats();
    }
  });
}

// === MOVE DIALOG ===
let moveItem = null;
function showMoveDialog(item) {
  moveItem = item;
  el('moveModal').style.display = 'flex';
  const tree = el('moveTree');
  tree.innerHTML = '<div class="empty-state"><p>Loading...</p></div>';
  API.tree().then(treeData => {
    tree.innerHTML = '';
    renderMoveTree(treeData, '');
  });
}

function renderMoveTree(nodes, prefix) {
  const tree = el('moveTree');
  for (const node of nodes) {
    const item = document.createElement('div');
    item.className = 'move-tree-item';
    item.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="#f9d71c"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg> ${escHtml(node.name)}`;
    const fullPath = prefix ? prefix + '/' + node.name : node.name;
    item.dataset.path = fullPath;
    item.addEventListener('click', () => {
      el('moveTree').querySelectorAll('.move-tree-item').forEach(n => n.classList.remove('selected'));
      item.classList.add('selected');
      el('moveConfirm').dataset.target = fullPath;
    });
    tree.appendChild(item);
    if (node.children && node.children.length) {
      const childContainer = document.createElement('div');
      childContainer.className = 'move-tree-children';
      childContainer.style.display = 'none';
      item.appendChild(childContainer);
      item.addEventListener('click', () => {
        const isExpanded = childContainer.style.display === 'block';
        childContainer.style.display = isExpanded ? 'none' : 'block';
        if (!childContainer.hasChildNodes() && node.children.length) {
          renderMoveTree(node.children, fullPath);
        }
      });
    }
  }
}

el('moveCancel').addEventListener('click', () => { el('moveModal').style.display = 'none'; });
el('moveModal').addEventListener('click', e => { if (e.target.classList.contains('modal-backdrop')) el('moveModal').style.display = 'none'; });
el('moveConfirm').addEventListener('click', () => {
  const target = el('moveConfirm').dataset.target;
  if (!target || !moveItem) return;
  API.move([{path: moveItem.path}], target).then(r => {
    if (r.moved) { showToast(`Moved to "${target}"`); loadFolder(state.currentPath); }
    el('moveModal').style.display = 'none';
  });
});

// === TRASH ===
function loadTrash() {
  const container = el('view-container');
  container.innerHTML = `
    <div class="trash-actions">
      <button class="btn-danger" id="emptyTrashBtn"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
      Empty trash</button>
    </div>
    <div id="trashList"></div>`;
  el('emptyTrashBtn').addEventListener('click', () => {
    if (confirm('Permanently delete all items in trash?')) {
      API.emptyTrash().then(() => loadTrash());
    }
  });
  API.trash().then(items => {
    const list = el('trashList');
    if (!items || !items.length) {
      list.innerHTML = '<div class="empty-state"><p>Trash is empty</p></div>';
      return;
    }
    for (const item of items) {
      const row = document.createElement('div');
      row.className = 'list-item';
      row.innerHTML = `
        <div class="file-icon-wrap ${getIconClass(item)}" style="width:32px;height:32px;font-size:1rem;display:flex;align-items:center;justify-content:center;border-radius:6px;flex-shrink:0">${getIcon(item)}</div>
        <span class="list-name">${escHtml(item.originalPath || item.name)}</span>
        <span class="list-meta">${item.sizeFormatted || '—'}</span>
        <span class="list-meta" style="width:80px;text-align:right">
          <button class="btn-secondary" style="padding:4px 12px;font-size:0.8rem">Restore</button>
        </span>`;
      row.querySelector('button').addEventListener('click', () => {
        API.restore(item.path).then(r => {
          showToast(r.success ? 'Restored' : 'Restore failed');
          loadTrash();
          loadStats();
        });
      });
      list.appendChild(row);
    }
  });
}

// === SHARED ===
function loadShared() {
  const container = el('view-container');
  container.innerHTML = '<div class="empty-state"><p>Loading shared links...</p></div>';
  API.shares().then(links => {
    if (!links || !links.length) {
      container.innerHTML = '<div class="empty-state"><p>No shared links</p><span class="hint">Right-click a file and select Share to create a link</span></div>';
      return;
    }
    let html = '';
    for (const link of links) {
      const url = `${window.location.origin}${link.url}`;
      html += `<div class="shared-item">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        <span style="flex:1">${escHtml(link.path)}</span>
        <a href="${url}" target="_blank" style="color:var(--primary);font-size:0.85rem;text-decoration:none">Open</a>
        <button class="btn-secondary" style="padding:4px 12px;font-size:0.8rem" onclick="navigator.clipboard.writeText('${url}');showToast('Copied!')">Copy</button>
      </div>`;
    }
    container.innerHTML = `<div class="shared-section">${html}</div>`;
  });
}

// === NEW BUTTON ===
el('newBtn').addEventListener('click', e => {
  e.stopPropagation();
  const menu = el('newMenu');
  menu.style.left = e.clientX + 'px';
  menu.style.top = e.clientY + 'px';
  menu.style.display = 'block';
  setTimeout(() => {
    document.addEventListener('click', () => { el('newMenu').style.display = 'none'; }, { once: true });
  }, 0);
});

el('newMenu').querySelectorAll('.menu-item').forEach(item => {
  item.addEventListener('click', () => {
    const action = item.dataset.action;
    if (action === 'folder') createFolder();
    else if (action === 'upload') el('fileInput').click();
    else if (action === 'uploadFolder') el('folderInput').click();
    el('newMenu').style.display = 'none';
  });
});

function createFolder() {
  const name = prompt('Folder name:');
  if (!name || !name.trim()) return;
  API.mkdir(state.currentPath, name.trim()).then(r => {
    if (r.success) { loadFolder(state.currentPath); showToast(`Created "${name}"`); }
    else showToast(r.error || 'Failed to create folder');
  });
}

// === STATS ===
function loadStats() {
  API.stats().then(s => {
    const pct = s.totalSize > 0 ? Math.min(100, Math.round(s.totalSize / (1024*1024*1024) * 100)) : 0;
    el('storageFill').style.width = Math.min(pct, 100) + '%';
    el('storageText').textContent = `${s.totalSizeFormatted} used · ${s.totalFiles} files · ${s.totalFolders} folders`;
  }).catch(() => {
    el('storageText').textContent = 'Storage info unavailable';
  });
}

// === SIDEBAR NAV UPDATE ===
function updateSidebarNav() {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const driveNav = document.querySelector('.nav-item[data-view="drive"]');
  if (driveNav) driveNav.classList.add('active');
}

// === UTILITIES ===
function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}
function formatSize(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

function fmtDate(d) {
  try {
    const date = new Date(d);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
  } catch (e) { return '—'; }
}

function showToast(msg) {
  const t = document.createElement('div');
  t.className = 'upload-toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2500);
}

// === SETTINGS ===
function loadSettings() {
  el('settingsName').value = currentUser.name || '';
  el('settingsCurrentPw').value = '';
  el('settingsNewPw').value = '';
  el('profileStatus').textContent = '';
  el('passwordStatus').textContent = '';
}

el('saveProfileBtn').addEventListener('click', () => {
  const name = el('settingsName').value.trim();
  if (!name) { el('profileStatus').textContent = 'Name cannot be empty'; el('profileStatus').style.color = 'var(--danger)'; return; }
  fetch('/api/auth/update-profile', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
    credentials: 'same-origin',
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) { el('profileStatus').textContent = data.error; el('profileStatus').style.color = 'var(--danger)'; return; }
    currentUser.name = name;
    el('userName').textContent = name;
    el('profileStatus').textContent = 'Profile updated successfully';
    el('profileStatus').style.color = 'var(--success)';
  })
  .catch(() => {
    el('profileStatus').textContent = 'Error updating profile';
    el('profileStatus').style.color = 'var(--danger)';
  });
});

el('changePwBtn').addEventListener('click', () => {
  const currentPassword = el('settingsCurrentPw').value;
  const newPassword = el('settingsNewPw').value;
  if (!currentPassword || !newPassword) { el('passwordStatus').textContent = 'Fill in both fields'; el('passwordStatus').style.color = 'var(--danger)'; return; }
  if (newPassword.length < 4) { el('passwordStatus').textContent = 'New password must be at least 4 characters'; el('passwordStatus').style.color = 'var(--danger)'; return; }
  fetch('/api/auth/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword, newPassword }),
    credentials: 'same-origin',
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) { el('passwordStatus').textContent = data.error; el('passwordStatus').style.color = 'var(--danger)'; return; }
    el('passwordStatus').textContent = 'Password changed successfully';
    el('passwordStatus').style.color = 'var(--success)';
    el('settingsCurrentPw').value = '';
    el('settingsNewPw').value = '';
  })
  .catch(() => {
    el('passwordStatus').textContent = 'Error changing password';
    el('passwordStatus').style.color = 'var(--danger)';
  });
});

// === ADMIN ===
function loadAdmin() {
  const tbody = el('adminUsersBody');
  const stats = el('adminStats');
  tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">Loading...</td></tr>';
  stats.innerHTML = '';
  fetch('/api/admin/users', { credentials: 'same-origin' })
    .then(r => r.json())
    .then(users => {
      if (users.error) { tbody.innerHTML = `<tr><td colspan="7" class="error-cell">${users.error}</td></tr>`; return; }
      let totalStorage = 0, totalFiles = 0, totalUsers = users.length;
      tbody.innerHTML = users.map(u => {
        totalStorage += u.storageSize || 0;
        totalFiles += u.fileCount || 0;
        const date = u.created_at ? new Date(u.created_at).toLocaleDateString() : '-';
        return `<tr>
          <td>${escHtml(u.email)}</td>
          <td>${escHtml(u.name)}</td>
          <td>${u.verified ? '<span class="badge badge-success">Yes</span>' : '<span class="badge badge-danger">No</span>'}</td>
          <td>${u.admin ? '<span class="badge badge-admin">Admin</span>' : '<span class="badge">User</span>'}</td>
          <td>${u.fileCount}</td>
          <td>${u.storageSizeFormatted || '0 B'}</td>
          <td>${date}</td>
        </tr>`;
      }).join('');
      stats.innerHTML = `
        <div class="stat-card"><span class="stat-value">${totalUsers}</span><span class="stat-label">Users</span></div>
        <div class="stat-card"><span class="stat-value">${totalFiles}</span><span class="stat-label">Files</span></div>
        <div class="stat-card"><span class="stat-value">${formatSize(totalStorage)}</span><span class="stat-label">Total Storage</span></div>
      `;
    })
    .catch(() => {
      tbody.innerHTML = '<tr><td colspan="7" class="error-cell">Error loading users</td></tr>';
    });
}

// === KEYBOARD SHORTCUTS ===
document.addEventListener('keydown', e => {
  if (e.key === 'Delete' || e.key === 'Backspace') {
    if (state.selected && state.view === 'drive') { deleteFile(state.selected); }
  }
  if (e.key === 'Escape') {
    el('previewModal').style.display = 'none';
    el('shareModal').style.display = 'none';
    el('moveModal').style.display = 'none';
    el('contextMenu').style.display = 'none';
    el('newMenu').style.display = 'none';
  }
  if (e.ctrlKey && e.key === 'v') {
    // no-op: avoid browser paste issues
  }
});

// === INIT ===
checkAuth().then(authed => {
  if (authed) {
    loadFolder('');
    loadStats();
  }
});
