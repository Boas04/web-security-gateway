'use strict';
document.querySelectorAll('nav a').forEach(a => { if (a.pathname === location.pathname) a.setAttribute('aria-current', 'page'); });
async function api(path, data) {
  const response = await fetch(path, data ? {method:'POST', headers:{'Content-Type':'application/json','X-Lab-Request':'1'}, body:JSON.stringify(data)} : {});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Permintaan gagal. Silakan coba lagi.');
  return result;
}
function notice(target, text, error=false) {
  target.replaceChildren();
  target.className = 'notice' + (error ? ' error' : '');
  const p = document.createElement('p'); p.textContent = text; target.append(p);
}
function field(target, label, value, code=false) {
  const p = document.createElement('p'); p.textContent = label;
  const content = document.createElement(code ? 'code' : 'strong'); content.textContent = value;
  p.append(document.createElement('br'), content); target.append(p);
}
function formHandler(id, outputId, path, success) {
  const form = document.getElementById(id); if (!form) return;
  const output = document.getElementById(outputId);
  form.addEventListener('submit', async event => {
    event.preventDefault(); const button = form.querySelector('button'); button.disabled = true;
    notice(output, 'Memproses permintaan…');
    try { await success(await api(path, Object.fromEntries(new FormData(form))), output, form); }
    catch (error) { notice(output, error.message, true); }
    finally { button.disabled = false; }
  });
}
formHandler('complaint-form','form-message','/api/complaints',(result, output, form) => {
  notice(output, 'Laporan diterima. Simpan kedua kode ini sekarang; kunci akses hanya ditampilkan sekali.');
  field(output, 'Nomor laporan', result.reference, true); field(output, 'Kunci akses', result.access_token, true);
  form.reset();
});
formHandler('status-form','status-message','/api/complaints/status',(result, output) => {
  notice(output, 'Laporan ditemukan.');
  for (const [key,label] of Object.entries({reference:'Nomor',title:'Judul',category:'Kategori',location:'Lokasi fiktif',status:'Status',created_at:'Dibuat (UTC)'})) field(output, label, result[key]);
});
document.getElementById('document-search')?.addEventListener('submit', async event => {
  event.preventDefault(); const output = document.getElementById('document-message');
  try {
    const result = await api('/api/documents?q=' + encodeURIComponent(new FormData(event.target).get('q')));
    const list = document.getElementById('document-list'); list.replaceChildren();
    result.items.forEach(doc => {
      const card = document.createElement('article'); card.className = 'doc-card';
      const title = document.createElement('h3'); title.textContent = doc.title;
      const description = document.createElement('p'); description.textContent = doc.description;
      const link = document.createElement('a'); link.className='text-link'; link.textContent = 'Unduh dokumen ↓'; link.href='/api/documents/' + encodeURIComponent(doc.id) + '/download';
      card.append(title, description, link); list.append(card);
    });
    notice(output, `${result.items.length} dokumen ditemukan.`);
  } catch(error) { notice(output, error.message, true); }
});
