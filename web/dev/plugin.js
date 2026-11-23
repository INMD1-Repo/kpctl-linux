import { createDemoStore } from './store.js';

export function demoApi() {
  const store = createDemoStore();
  return { name: 'kpctl-demo-api', apply: 'serve', configureServer(server) {
    server.middlewares.use(async (req, res, next) => {
      if (!req.url?.startsWith('/api/')) return next();
      res.setHeader('Cache-Control', 'no-store');
      try {
        const chunks = []; let length = 0;
        for await (const chunk of req) {
          length += chunk.length;
          if (length > 65536) { res.writeHead(413, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: '가상 요청 본문이 너무 큽니다.' })); return; }
          chunks.push(chunk);
        }
        const text = Buffer.concat(chunks).toString('utf8');
        const result = store.handle(req.method, req.url, text ? JSON.parse(text) : {}, req.headers.authorization?.replace(/^Bearer /, ''));
        res.writeHead(result.status, { 'Content-Type': result.type + '; charset=utf-8' });
        res.end(result.type === 'application/json' ? JSON.stringify(result.body) : result.body);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: '가상 요청의 JSON 또는 경로 형식이 잘못됐습니다.' }));
      }
    });
  } };
}
