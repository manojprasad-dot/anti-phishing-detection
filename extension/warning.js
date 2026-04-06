// PhishGuard — warning.js
// Reads URL params and populates the warning page

const params = new URLSearchParams(window.location.search);
const url = params.get('url') || 'Unknown';
const confidence = parseFloat(params.get('confidence') || '0');
const reasons = params.get('reasons') || '';

document.getElementById('blocked-url').textContent = url;
document.getElementById('confidence').textContent = Math.round(confidence * 100) + '%';
document.getElementById('conf-bar').style.width = Math.round(confidence * 100) + '%';

if (reasons) {
  const list = reasons.split('|').filter(r => r);
  if (list.length > 0) {
    document.getElementById('reasons-section').style.display = 'block';
    document.getElementById('reasons-list').innerHTML = list.map(r => `<li>${r}</li>`).join('');
  }
}

document.getElementById('go-back').addEventListener('click', () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = 'https://www.google.com';
  }
});

document.getElementById('proceed').addEventListener('click', () => {
  window.location.href = url;
});
