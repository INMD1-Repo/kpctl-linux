export const TOKEN_KEY = 'kpctl-admin-token';
export const kernelPath = (kernel) => '/api/kernels/' + encodeURIComponent(kernel);
export const hostPath = (host) => '/api/hosts/' + encodeURIComponent(host.id);

export function storage(action) {
  try { return action(window.sessionStorage); } catch { return null; }
}

export async function request(token, method, path, body, signal) {
  const response = await fetch(path, {
    method, signal, credentials: 'omit',
    headers: { Authorization: 'Bearer ' + token, ...(body !== undefined && { 'Content-Type': 'application/json' }) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let data = text;
  if ((response.headers.get('Content-Type') || '').startsWith('application/json') && text) {
    try { data = JSON.parse(text); } catch { /* Preserve a malformed server response as text. */ }
  }
  if (!response.ok) {
    const error = new Error(data?.error || text || `요청 실패 (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return data;
}

export function normalizeStatus(data) {
  return { ...data, tracks: data.tracks || [], jobs: data.jobs || [], hosts: data.hosts || [], rings: data.rings || [], unpatchable: data.unpatchable || [] };
}
