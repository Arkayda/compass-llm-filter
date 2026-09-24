const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// Управление темами (Dark / Light)
function initTheme() {
  const saved = localStorage.getItem('compass-theme');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = saved || (prefersDark ? 'dark' : 'light');
  applyTheme(theme);
}
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('compass-theme', theme);
  const isDark = theme === 'dark';
  $('theme-text').textContent = isDark ? 'Светлая тема' : 'Тёмная тема';
  $('theme-icon').innerHTML = isDark
    ? '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>'
    : '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
}
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

const TABS = ['overview', 'settings', 'rules', 'sandbox', 'audit'];

function showTab(name) {
  document.querySelectorAll('nav button').forEach(b => {
    const selected = b.dataset.tab === name;
    b.classList.toggle('active', selected);
    b.setAttribute('aria-selected', selected ? 'true' : 'false');
  });
  TABS.forEach(t => $('tab-' + t).hidden = t !== name);
  if (name === 'audit') loadAudit();
}

// делегирование всех обработчиков: консоль живёт под строгим CSP
// (script-src 'self') — inline-атрибуты onclick запрещены
document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  switch (el.dataset.action) {
    case 'show-tab': showTab(el.dataset.tab); break;
    case 'toggle-theme': toggleTheme(); break;
    case 'save-settings': saveSettings(); break;
    case 'add-rule': addRule(); break;
    case 'load-audit': loadAudit(); break;
    case 'run-sandbox': runSandbox(); break;
    case 'sb-view': setSbView(el.dataset.view); break;
    case 'toggle-rule': toggleRule(el.dataset.id, el.dataset.enabled !== '1'); break;
    case 'delete-rule': deleteRule(el.dataset.id); break;
  }
});

// Аккуратное форматирование поля detail из тела ошибки API:
// строки — как есть; объекты и списки (FastAPI 400/409/422) — как «loc: msg»
function formatDetail(detail) {
  if (detail === undefined || detail === null || detail === '') return '';
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail.map(item => {
      if (item && typeof item === 'object' && item.msg) {
        const loc = Array.isArray(item.loc) ? item.loc.join('.') : item.loc;
        return loc ? loc + ': ' + item.msg : String(item.msg);
      }
      return formatDetail(item);
    }).join('; ');
  }
  if (typeof detail === 'object') {
    if (detail.msg !== undefined) return String(detail.msg);
    if (detail.message !== undefined) return String(detail.message);
    try { return JSON.stringify(detail); } catch (e) { return ''; }
  }
  return String(detail);
}

// Единая обёртка над fetch: сначала читаем текст, затем пробуем распарсить JSON.
// Так не падаем на пустом теле (401), plain-text ошибках (500) и сетевых сбоях;
// при !resp.ok бросаем Error с кодом статуса и человекочитаемым описанием.
async function api(path, opts) {
  let resp;
  try {
    resp = await fetch(path, opts && {headers: {'Content-Type': 'application/json'}, ...opts});
  } catch (e) {
    throw new Error('Сеть недоступна (' + ((e && e.message) || e) + ')');
  }
  const text = await resp.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch (e) { data = null; } }
  if (!resp.ok) {
    const raw = (data && data.detail !== undefined) ? data.detail : text.trim();
    const err = new Error('HTTP ' + resp.status + (resp.statusText ? ' ' + resp.statusText : '') +
      ': ' + (formatDetail(raw) || 'нет деталей'));
    err.status = resp.status;
    throw err;
  }
  return data;
}

// Строка статуса для сообщений об ошибках («Настройки», «Правила», «Песочница»):
// message == null — скрыть; isError — красная «пилюля», иначе обычная подсказка
function setStatus(id, message, isError) {
  const el = $(id);
  if (!el) return;
  if (!message) { el.textContent = ''; el.style.display = 'none'; return; }
  el.textContent = message;
  el.className = isError ? 'pill bad' : 'hint';
  el.style.display = '';
}

function errText(e) { return (e && e.message) ? e.message : String(e); }

const MODE_TITLES = {
  enforce: ['enforce — маскирование', 'ok'],
  detect: ['detect — shadow', 'warn'],
};
const FAIL_TITLES = {
  closed: ['fail-closed — блокировать при сбое', 'ok'],
  open: ['fail-open — пропускать при сбое', 'warn'],
};
const ANON_TITLES = {
  fake: 'подстановки: реалистичные',
  placeholders: 'подстановки: плейсхолдеры',
};

// ——— Защита несохранённых настроек от затирания опросом (loadOverview каждые 5 с) ———
// Селект, который администратор уже изменил (но ещё не нажал «Применить»)
// или который сейчас в фокусе, опросом не перезаписывается.
const settingsDirty = new Set();
function setIfPristine(id, value) {
  const el = $(id);
  if (!el || settingsDirty.has(id) || document.activeElement === el) return;
  el.value = value;
}

async function loadOverview() {
  try {
    const health = await api('/healthz');
    $('upstream-info').textContent = health.upstream;
    setIfPristine('set-mode', health.mode);
    setIfPristine('set-fail', health.fail_mode);
    setIfPristine('set-anon', health.anonymization_mode);
    const [mode, modeCls] = MODE_TITLES[health.mode] || [health.mode, 'muted'];
    const [fail, failCls] = FAIL_TITLES[health.fail_mode] || [health.fail_mode, 'muted'];
    $('ov-badges').innerHTML =
      `<span class="pill ${modeCls}">${mode}</span>` +
      `<span class="pill ${failCls}">${fail}</span>` +
      `<span class="pill muted">${ANON_TITLES[health.anonymization_mode] || health.anonymization_mode}</span>`;
    $('ov-upstream').textContent = 'апстрим: ' + health.upstream;

    // Динамический расчет Security Score
    const checks = [
      { id: 'sc-auth', ok: !!health.auth_configured, okText: 'Аутентификация активна', failText: 'Аутентификация не настроена' },
      { id: 'sc-pepper', ok: !!health.has_pepper, okText: 'Соль ГПСЧ активна', failText: 'Без серверной соли' },
      { id: 'sc-mode', ok: health.mode === 'enforce', okText: 'Режим: enforce', failText: 'Режим: detect (shadow)' },
      { id: 'sc-fail', ok: health.fail_mode === 'closed', okText: 'Политика: fail-closed', failText: 'Политика: fail-open' },
      { id: 'sc-shield', ok: true, okText: 'ReDoS & Prompt Shield', failText: '' },
      { id: 'sc-headers', ok: true, okText: 'CSP, CSRF & Rate Limit', failText: '' }
    ];
    const passed = checks.filter(c => c.ok).length;
    const scorePct = Math.round((passed / checks.length) * 100);

    $('sc-pct').textContent = scorePct + '%';
    if (scorePct === 100) {
      $('sc-badge').className = 'score-badge ok';
      $('sc-badge-icon').innerHTML = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>';
      $('sc-title').textContent = 'Максимальная защита (100%)';
      $('sc-desc').textContent = 'Все рубежи безопасности, криптографическая соль (pepper) и CSP/CSRF активны.';
    } else {
      $('sc-badge').className = 'score-badge warn';
      $('sc-badge-icon').innerHTML = '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>';
      $('sc-title').textContent = `Частичная защита (${scorePct}%)`;
      const recs = [];
      if (!health.has_pepper) recs.push('задайте COMPASS_SECRET_PEPPER для защиты от подбора');
      if (!health.auth_configured) recs.push('задайте COMPASS_AUTH_USER / PASSWORD');
      if (health.mode !== 'enforce') recs.push('переключите режим в enforce');
      if (health.fail_mode !== 'closed') recs.push('установите fail_mode: closed');
      $('sc-desc').textContent = 'Рекомендация: ' + (recs.join(', ') || 'проверьте настройки безопасности') + '.';
    }

    checks.forEach(c => {
      const el = $(c.id);
      if (el) {
        el.className = 'check-item ' + (c.ok ? 'ok' : 'warn');
        el.innerHTML = `<span class="check-dot"></span> ${c.ok ? c.okText : c.failText}`;
      }
    });

    const metrics = await (await fetch('/metrics')).text();
    const stats = {}, errors = {};
    metrics.split('\n').forEach(line => {
      let m = line.match(/^compass_masked_total\{type="(\w+)"\} (\d+)$/);
      if (m && +m[2] > 0) stats[m[1]] = +m[2];
      m = line.match(/^(compass_blocked_total|compass_failopen_total|compass_mask_errors_total|compass_upstream_errors_total|compass_prompt_injections_total) (\d+)$/);
      if (m && +m[2] > 0) errors[m[1].replace(/^compass_|_total$/g, '')] = +m[2];
    });
    const titles = {phones:'Телефоны', cards:'Карты', emails:'E-mail', links:'Ссылки',
      domains:'Домены', ips:'IP-адреса', names:'Имена', mentions:'@упоминания',
      snils:'СНИЛС', inns:'ИНН', inns12:'ИНН-12', ogrns:'ОГРН', ogrnips:'ОГРНИП',
      passports:'Паспорта', ibans:'IBAN', secrets:'Секреты', custom:'Свои правила'};
    const grid = Object.entries(stats).map(([k, v]) =>
      `<div class="stat"><div class="v">${v}</div><div class="k">${titles[k] || k}</div></div>`).join('');
    $('overview-stats').innerHTML = grid || '<div class="empty">нет данных — прогоните трафик</div>';
    const errTitles = {blocked:'Заблокировано', failopen:'Пропущено (fail-open)',
      'mask_errors':'Ошибки маскирования', 'upstream_errors':'Ошибки апстрима',
      'prompt_injections':'Инъекции промпта'};
    const errGrid = Object.entries(errors).map(([k, v]) =>
      `<div class="stat"><div class="v">${v}</div><div class="k">${errTitles[k] || k}</div></div>`).join('');
    $('ov-errors').innerHTML = errGrid || '<div class="empty">всё чисто</div>';
  } catch (e) { console.error(e); }
}

async function saveSettings() {
  try {
    await api('/v1/settings', {method: 'PUT', body: JSON.stringify({
      mode: $('set-mode').value, fail_mode: $('set-fail').value,
      anonymization_mode: $('set-anon').value})});
    settingsDirty.clear(); // успешно сохранено — снова доверяем значениям сервера
    setStatus('set-status', null);
    loadOverview();
  } catch (e) {
    console.error(e);
    setStatus('set-status', 'Не удалось сохранить настройки: ' + errText(e), true);
  }
}

async function loadDetectors() {
  try {
    const data = await api('/v1/detectors');
    const body = $('detectors-body');
    body.innerHTML = data.detectors.map(d => `<tr>
      <td>${esc(d.title)}</td>
      <td class="mono">${esc(d.example)}</td>
      <td>${esc(d.note)}</td>
    </tr>`).join('');
  } catch (e) { console.error(e); }
}

async function loadRules() {
  try {
    const data = await api('/v1/rules');
    const body = $('rules-body');
    if (!data.rules.length) { body.innerHTML = '<tr><td colspan="5" class="empty">правил пока нет</td></tr>'; setStatus('rules-status', null); return; }
    body.innerHTML = data.rules.map(r => `<tr>
      <td>${esc(r.name)}</td><td class="mono">${esc(r.pattern)}</td>
      <td>${r.replacement === 'fake' ? 'fake' : esc(r.placeholder)}</td>
      <td><span class="pill ${r.enabled ? 'ok' : 'warn'}">${r.enabled ? 'вкл' : 'выкл'}</span></td>
      <td>
        <button class="btn ghost small" data-action="toggle-rule" data-id="${esc(r.id)}" data-enabled="${r.enabled ? '1' : '0'}">${r.enabled ? 'выключить' : 'включить'}</button>
        <button class="btn ghost small" data-action="delete-rule" data-id="${esc(r.id)}">удалить</button>
      </td></tr>`).join('');
    setStatus('rules-status', null);
  } catch (e) {
    console.error(e);
    // не оставляем ложное «правил пока нет» при сбое загрузки
    $('rules-body').innerHTML = '<tr><td colspan="5" class="empty">Не удалось загрузить правила</td></tr>';
    setStatus('rules-status', 'Не удалось загрузить правила: ' + errText(e), true);
  }
}

async function addRule() {
  setStatus('rules-status', null);
  try {
    const res = await api('/v1/rules', {method: 'POST', body: JSON.stringify({
      name: $('rule-name').value, pattern: $('rule-pattern').value,
      replacement: $('rule-replacement').value, placeholder: $('rule-placeholder').value})});
    if (res && res.detail) {
      // на случай, если бэкенд отвечает 200 с описанием ошибки валидации
      setStatus('rules-status', 'Ошибка добавления правила: ' + formatDetail(res.detail), true);
      return;
    }
    // успех — очищаем поля формы
    $('rule-name').value = ''; $('rule-pattern').value = ''; $('rule-placeholder').value = '';
    loadRules();
  } catch (e) {
    console.error(e);
    setStatus('rules-status', 'Ошибка добавления правила: ' + errText(e), true);
  }
}

async function toggleRule(id, enabled) {
  try {
    await api('/v1/rules/' + id, {method: 'PATCH', body: JSON.stringify({enabled})}); loadRules();
  } catch (e) {
    console.error(e);
    setStatus('rules-status', 'Не удалось изменить правило: ' + errText(e), true);
  }
}
async function deleteRule(id) {
  try {
    await api('/v1/rules/' + id, {method: 'DELETE'}); loadRules();
  } catch (e) {
    console.error(e);
    setStatus('rules-status', 'Не удалось удалить правило: ' + errText(e), true);
  }
}

// Sandbox view switching: активная кнопка — класс .active,
// видимость контейнеров — через style.display (currentSbView не нужен)
function setSbView(mode) {
  document.querySelectorAll('.sb-tab-btn').forEach(btn => {
    const selected = btn.dataset.view === mode;
    btn.classList.toggle('active', selected);
    btn.setAttribute('aria-selected', selected ? 'true' : 'false');
  });
  $('sb-view-diff').style.display = mode === 'diff' ? 'grid' : 'none';
  $('sb-view-restored').style.display = mode === 'restored' ? 'block' : 'none';
  $('sb-view-raw').style.display = mode === 'raw' ? 'block' : 'none';
}

function highlightText(text, replacements, isFake) {
  if (!replacements || !replacements.length || !text) return esc(text || '');

  // Собираем все вхождения
  const matches = [];
  replacements.forEach((item, idx) => {
    const val = isFake ? item.fake : item.original;
    if (!val || val.length === 0) return;
    let pos = 0;
    while ((pos = text.indexOf(val, pos)) !== -1) {
      matches.push({
        start: pos,
        end: pos + val.length,
        len: val.length,
        item: item,
        idx: idx
      });
      pos += val.length;
    }
  });

  if (!matches.length) return esc(text);

  // Сортируем: по началу asc, по длине desc
  matches.sort((a, b) => a.start - b.start || b.len - a.len);

  // Исключаем пересечения
  const nonOverlapping = [];
  let lastEnd = 0;
  for (const m of matches) {
    if (m.start >= lastEnd) {
      nonOverlapping.push(m);
      lastEnd = m.end;
    }
  }

  let result = '';
  let cursor = 0;
  for (const m of nonOverlapping) {
    if (m.start > cursor) {
      result += esc(text.slice(cursor, m.start));
    }
    const catClass = 'hl-' + (m.item.category || 'names');
    const matchedText = text.slice(m.start, m.end);
    const tooltip = isFake
      ? `Замена [${m.item.category || 'pii'}]: ${m.item.original}`
      : `Будет заменено на: ${m.item.fake}`;
    result += `<mark class="hl ${catClass}" data-idx="${m.idx}" title="${esc(tooltip)}">${esc(matchedText)}</mark>`;
    cursor = m.end;
  }
  if (cursor < text.length) {
    result += esc(text.slice(cursor));
  }
  return result;
}

function bindHoverSync() {
  document.querySelectorAll('mark.hl').forEach(el => {
    el.onmouseenter = () => {
      const idx = el.dataset.idx;
      document.querySelectorAll(`mark.hl[data-idx="${idx}"]`).forEach(m => m.classList.add('active'));
    };
    el.onmouseleave = () => {
      const idx = el.dataset.idx;
      document.querySelectorAll(`mark.hl[data-idx="${idx}"]`).forEach(m => m.classList.remove('active'));
    };
  });
}

async function runSandbox() {
  let entities = [];
  try { entities = JSON.parse($('sb-entities').value || '[]'); } catch (e) {}
  const text = $('sb-text').value;
  setStatus('sb-status', null);
  try {
    const data = await api('/v1/sandbox', {method: 'POST', body: JSON.stringify({text, entities})});

    // Injection Banner
    if (data.injections && data.injections.length > 0) {
      $('sb-injection-alert').style.display = 'flex';
      $('sb-injection-text').textContent = 'Обнаружены сигнатуры: ' + data.injections.join(', ');
    } else {
      $('sb-injection-alert').style.display = 'none';
    }

    // Legend
    $('sb-legend').style.display = (data.replacements && data.replacements.length > 0) ? 'flex' : 'none';

    // Highlighted Side-by-Side
    $('sb-diff-orig').innerHTML = highlightText(text, data.replacements, false);
    $('sb-diff-masked').innerHTML = highlightText(data.masked || '', data.replacements, true);
    bindHoverSync();

    // Raw and restored views
    $('sb-raw-masked').textContent = data.masked || '—';
    $('sb-restored').textContent = data.restored || '—';

    $('sb-stats').innerHTML = 'Всего замен: ' + (data.replacements ? data.replacements.length : 0) +
      ' · Утечки: ' + (data.leaks === 0
        ? '<span class="pill ok">0 — чисто</span>'
        : `<span class="pill bad">${data.leaks} — маскирование не удалось</span>`);
  } catch (e) {
    console.error(e);
    setStatus('sb-status', 'Маскирование не выполнено: ' + errText(e), true);
  }
}

async function loadAudit() {
  try {
    const data = await api('/v1/audit/records');
    const body = $('audit-body');
    if (!data.records.length) { body.innerHTML = '<tr><td colspan="7" class="empty">записей нет</td></tr>'; return; }
    body.innerHTML = data.records.slice().reverse().map(r => `<tr>
      <td class="mono">${new Date(r.ts * 1000).toLocaleTimeString('ru-RU')}</td>
      <td class="mono">${esc(r.path)}</td>
      <td>${esc(r.mode || '—')}</td>
      <td class="mono">${r.detected ? esc(Object.entries(r.detected).map(([k, v]) => k + ':' + v).join(' ')) : '—'}</td>
      <td class="mono">${r.entities ?? '—'}</td>
      <td>${r.injections && r.injections.length
        ? `<span class="tags">${r.injections.map(t => `<span class="pill bad">${esc(t)}</span>`).join('')}</span>`
        : '<span class="pill muted">—</span>'}</td>
      <td>${r.blocked
        ? `<span class="pill bad">заблокирован</span>${r.reason ? '<div class="hint" style="margin:4px 0 0">' + esc(r.reason) + '</div>' : ''}`
        : '<span class="pill ok">ок</span>'}</td>
    </tr>`).join('');
  } catch (e) {
    console.error(e);
    $('audit-body').innerHTML = '<tr><td colspan="7" class="empty">Не удалось загрузить журнал аудита</td></tr>';
  }
}

initTheme();
// помечаем селекты настроек «грязными» при ручном изменении,
// чтобы периодический опрос не затирал несохранённый выбор
['set-mode', 'set-fail', 'set-anon'].forEach(id => {
  const el = $(id);
  if (el) el.addEventListener('change', () => settingsDirty.add(id));
});
loadOverview(); loadRules(); loadDetectors();
setInterval(loadOverview, 5000);
