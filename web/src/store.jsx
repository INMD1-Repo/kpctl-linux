import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { normalizeStatus, request, storage, TOKEN_KEY } from './api.js';

const Context = createContext(null);
export const useApp = () => useContext(Context);

export function AppProvider({ children }) {
  const [token, setToken] = useState(() => storage(s => s.getItem(TOKEN_KEY)) || '');
  const tokenRef = useRef(token);
  const [status, setStatus] = useState(null);
  const [error, setError] = useState('');
  const [loginError, setLoginError] = useState('');
  const [pendingLogin, setPendingLogin] = useState(false);
  const [notice, setNotice] = useState(null);
  const [revision, setRevision] = useState(0);
  const refreshSequence = useRef(0);
  const refreshing = useRef(false);
  const refreshAbort = useRef(null);

  const logout = useCallback((message = '') => {
    tokenRef.current = '';
    refreshSequence.current++;
    refreshAbort.current?.abort();
    refreshing.current = false;
    setToken(''); setStatus(null); setNotice(null); setError(''); setLoginError(message);
    storage(s => s.removeItem(TOKEN_KEY));
  }, []);

  const api = useCallback(async (method, path, body, signal) => {
    const identity = tokenRef.current;
    try { return await request(identity, method, path, body, signal); }
    catch (err) {
      if (err.status === 401 && tokenRef.current === identity) logout('인증이 만료됐습니다. 다시 로그인하세요.');
      throw err;
    }
  }, [logout]);

  const refresh = useCallback(async () => {
    if (!tokenRef.current || refreshing.current) return;
    const identity = tokenRef.current;
    const sequence = ++refreshSequence.current;
    const controller = new AbortController();
    refreshAbort.current = controller;
    refreshing.current = true;
    try {
      const data = await request(identity, 'GET', '/api/status', undefined, controller.signal);
      if (sequence !== refreshSequence.current || identity !== tokenRef.current) return;
      setStatus(normalizeStatus(data)); setError(''); setRevision(value => value + 1);
    } catch (err) {
      if (sequence !== refreshSequence.current || err.name === 'AbortError') return;
      if (err.status === 401) logout('토큰이 맞지 않거나 인증이 만료됐습니다.');
      else setError(err.message);
    } finally {
      if (sequence === refreshSequence.current) refreshing.current = false;
    }
  }, [logout]);

  const login = useCallback(async candidate => {
    candidate = candidate.trim();
    if (!candidate) return;
    setPendingLogin(true); setLoginError('');
    try {
      const data = await request(candidate, 'GET', '/api/status');
      refreshAbort.current?.abort(); refreshSequence.current++; refreshing.current = false;
      tokenRef.current = candidate; setToken(candidate); setStatus(normalizeStatus(data)); setError('');
      storage(s => s.setItem(TOKEN_KEY, candidate));
    } catch (err) {
      logout(err.status === 401 ? '토큰이 맞지 않습니다.' : err.message);
    } finally { setPendingLogin(false); }
  }, [logout]);

  useEffect(() => {
    if (token) void refresh();
    return () => { refreshSequence.current++; refreshAbort.current?.abort(); refreshing.current = false; };
  }, [token, refresh]);

  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(null), notice.bad ? 12000 : 4000);
    return () => clearTimeout(timer);
  }, [notice]);

  const notify = useCallback((message, bad = false) => setNotice({ message, bad }), []);
  return <Context.Provider value={{ token, status, error, loginError, pendingLogin, login, logout, api, refresh, notify, notice, revision }}>{children}</Context.Provider>;
}

// Abort obsolete reads when the selected host/kernel, page or session changes.
export function useResource(path, revision = 0) {
  const { api, token } = useApp();
  const [result, setResult] = useState({ path: null, data: null, error: '', loading: true });
  const sequence = useRef(0);
  const pending = useRef(false);
  const current = useRef(null);
  // A polling tick must not cancel a slow read of the same resource. A new
  // selection/session and unmount still abort it and invalidate its response.
  useEffect(() => {
    return () => { sequence.current++; current.current?.abort(); pending.current = false; };
  }, [path, token, api]);
  useEffect(() => {
    if (!path) { setResult({ path, data: null, error: '', loading: false }); return; }
    if (pending.current) return;
    const controller = new AbortController();
    const id = ++sequence.current;
    current.current = controller; pending.current = true;
    setResult(old => old.path === path && old.data !== null ? { ...old, error: '' } : { path, data: null, error: '', loading: true });
    api('GET', path, undefined, controller.signal).then(
      data => { if (id === sequence.current) setResult({ path, data, error: '', loading: false }); },
      error => { if (id === sequence.current && error.name !== 'AbortError') setResult({ path, data: null, error: error.message, loading: false }); },
    ).finally(() => { if (id === sequence.current) pending.current = false; });
  }, [path, revision, token, api]);
  return result.path === path ? result : { data: null, error: '', loading: Boolean(path) };
}

// Dialogs pause dashboard polling, so live logs have their own read timer.
export function usePolling(milliseconds = 5000, enabled = true) {
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision(value => value + 1), []);
  useEffect(() => {
    if (!enabled) return;
    const tick = () => { if (document.visibilityState !== 'hidden') reload(); };
    const timer = setInterval(tick, milliseconds);
    document.addEventListener('visibilitychange', tick);
    return () => { clearInterval(timer); document.removeEventListener('visibilitychange', tick); };
  }, [milliseconds, enabled, reload]);
  return { revision, reload };
}
