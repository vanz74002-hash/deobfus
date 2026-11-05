import indexHtml from './index.html';
import styleCss from './style.css';
import appJs from './app.js';

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // Serve Static Assets
        if (url.pathname === '/' || url.pathname === '/index.html') {
            return new Response(indexHtml, {
                headers: { 'Content-Type': 'text/html;charset=UTF-8' },
            });
        }
        if (url.pathname === '/style.css') {
            return new Response(styleCss, {
                headers: { 'Content-Type': 'text/css;charset=UTF-8' },
            });
        }
        if (url.pathname === '/app.js') {
            return new Response(appJs, {
                headers: { 'Content-Type': 'application/javascript;charset=UTF-8' },
            });
        }

        // Mock Deobfuscation API
        if (url.pathname === '/api/deobfuscate' && request.method === 'POST') {
            const { code } = await request.json();
            
            // MOCK LOGIC: Just add a header to prove it went through the worker
            const deobfuscatedCode = `-- DEOBFUSCATED BY KAIRO ENGINE v4.1\n-- STATUS: SUCCESS (MOCK)\n\n${code}`;
            
            return new Response(JSON.stringify({ 
                success: true, 
                result: deobfuscatedCode 
            }), {
                headers: { 'Content-Type': 'application/json' },
            });
        }

        return new Response('Not Found', { status: 404 });
    },
};
