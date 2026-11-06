import indexHtml from './index.html';
import styleCss from './style.css';
import appJs from './app.js';

import { processPrometheus } from './prometheus.js';
import { processLuraph } from './luraph.js';
import { processMoonSec } from './moonsec.js';
import { processIronBrew } from './ironbrew.js';
import { processAztupBrew } from './aztupbrew.js';
import { processHercules } from './hercules.js';
import { processBoronide } from './boronide.js';
import { processPSU } from './psu.js';
import { processWeAreDevs } from './wearedevs.js';
import { processLuaObfuscator } from './luaobfuscator.js';
import { processDarkSec } from './darksec.js';
import { processSLua } from './slua.js';
import { process25ms } from './25ms.js';
import { process77fuscator } from './77fuscator.js';
import { processMoonVeil } from './moonveil.js';
import { processObscuraLua } from './obscuralua.js';
import { processSynapseXen } from './synapse_xen.js';
import { processWYnFuscate } from './wynfuscate.js';
import { processRealVux } from './realvux.js';
import { processLuast } from './luast.js';
import { processLuawl } from './luawl.js';

const ENGINES = [
  { name: 'Prometheus', processor: processPrometheus, flag: 'isPrometheus' },
  { name: 'Luraph', processor: processLuraph, flag: 'isLuraph' },
  { name: 'MoonSec', processor: processMoonSec, flag: 'isMoonSec' },
  { name: 'IronBrew', processor: processIronBrew, flag: 'isIronBrew' },
  { name: 'AztupBrew', processor: processAztupBrew, flag: 'isAztupBrew' },
  { name: 'Hercules', processor: processHercules, flag: 'isHercules' },
  { name: 'Boronide', processor: processBoronide, flag: 'isBoronide' },
  { name: 'PSU', processor: processPSU, flag: 'isPSU' },
  { name: 'WeAreDevs', processor: processWeAreDevs, flag: 'isWeAreDevs' },
  { name: 'LuaObfuscator', processor: processLuaObfuscator, flag: 'isLuaObfuscator' },
  { name: 'DarkSec', processor: processDarkSec, flag: 'isDarkSec' },
  { name: 'SLua', processor: processSLua, flag: 'isSLua' },
  { name: '25ms', processor: process25ms, flag: 'is25ms' },
  { name: '77fuscator', processor: process77fuscator, flag: 'is77fuscator' },
  { name: 'MoonVeil', processor: processMoonVeil, flag: 'isMoonVeil' },
  { name: 'ObscuraLua', processor: processObscuraLua, flag: 'isObscuraLua' },
  { name: 'SynapseXen', processor: processSynapseXen, flag: 'isSynapseXen' },
  { name: 'WYnFuscate', processor: processWYnFuscate, flag: 'isWYnFuscate' },
  { name: 'RealVux', processor: processRealVux, flag: 'isRealVux' },
  { name: 'Luast', processor: processLuast, flag: 'isLuast' },
  { name: 'Luawl', processor: processLuawl, flag: 'isLuawl' },
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Serve Static Assets (akan dibaca sebagai string text berkat [[rules]])
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return new Response(indexHtml, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    if (url.pathname === '/style.css') {
      return new Response(styleCss, { headers: { 'Content-Type': 'text/css;charset=UTF-8' } });
    }
    if (url.pathname === '/app.js') {
      return new Response(appJs, { headers: { 'Content-Type': 'application/javascript;charset=UTF-8' } });
    }

    // API: List Engines
    if (url.pathname === '/api/engines' && request.method === 'GET') {
      return new Response(JSON.stringify({
        total: ENGINES.length,
        engines: ENGINES.map(e => e.name),
      }), { headers: { 'Content-Type': 'application/json' } });
    }

    // API: Health Check
    if (url.pathname === '/api/health') {
      return new Response(JSON.stringify({ status: 'online', engines: ENGINES.length }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // API: Main Deobfuscation Endpoint
    if (url.pathname === '/api/deobfuscate' && request.method === 'POST') {
      try {
        const { code } = await request.json();

        if (!code || typeof code !== 'string' || code.trim().length === 0) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Empty or invalid input',
          }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        let bestResult = null;
        let bestConfidence = 0;
        let detectedEngine = null;

        // Cascade detection
        for (const engine of ENGINES) {
          const r = engine.processor(code);
          if (r.success && r.detection && r.detection[engine.flag] && r.detection.confidence > bestConfidence) {
            bestResult = r;
            bestConfidence = r.detection.confidence;
            detectedEngine = engine.name;
            break;
          }
          // Simpan fallback confidence tertinggi
          if (r.detection && r.detection.confidence > bestConfidence) {
            bestResult = r;
            bestConfidence = r.detection.confidence;
            if (!detectedEngine) detectedEngine = engine.name;
          }
        }

        if (!bestResult || !bestResult.success) {
          return new Response(JSON.stringify({
            success: false,
            detectedEngine: null,
            message: 'No obfuscator detected with high confidence',
            detection: bestResult?.detection || null,
          }), { headers: { 'Content-Type': 'application/json' } });
        }

        return new Response(JSON.stringify({
          success: true,
          detectedEngine,
          detection: bestResult.detection,
          deobfuscation: bestResult.deobfuscation,
          message: bestResult.message,
        }), { headers: { 'Content-Type': 'application/json' } });

      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response('Not Found', { status: 404 });
  },
};
