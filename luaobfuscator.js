/**
 * KAIRO ENGINE // lua-obfuscator Detector & Deobfuscator
 * Target: Luau scripts obfuscated by lua-obfuscator (npm/github)
 * Signature: short underscore vars (_1, _2), base64+XOR, IIFE, loadstring, VM-based (v3+)
 */

// ============================================================
// SECTION 1: DETECTION ENGINE
// ============================================================

export class LuaObfuscatorDetector {
    constructor() {
        this.layers = [
            { name: 'SignatureScan', weight: 0.25, run: this.signatureScan.bind(this) },
            { name: 'VariableNamingPattern', weight: 0.20, run: this.variableNamingPattern.bind(this) },
            { name: 'IIFEPattern', weight: 0.15, run: this.iifePattern.bind(this) },
            { name: 'StringEncryptionPattern', weight: 0.15, run: this.stringEncryptionPattern.bind(this) },
            { name: 'LoadstringPattern', weight: 0.10, run: this.loadstringPattern.bind(this) },
            { name: 'VMStructureDetection', weight: 0.10, run: this.vmStructureDetection.bind(this) },
            { name: 'HeuristicAnalysis', weight: 0.05, run: this.heuristicAnalysis.bind(this) },
        ];
    }

    detect(code) {
        if (!code || typeof code !== 'string') {
            return { isLuaObfuscator: false, confidence: 0, version: 'unknown', layers: [], error: 'Empty input' };
        }

        const results = [];
        let totalConfidence = 0;

        for (const layer of this.layers) {
            try {
                const layerResult = layer.run(code);
                results.push({
                    layer: layer.name,
                    confidence: layerResult.confidence,
                    evidence: layerResult.evidence || [],
                    versionHint: layerResult.versionHint || null,
                });
                totalConfidence += layerResult.confidence * layer.weight;
            } catch (err) {
                results.push({ layer: layer.name, confidence: 0, error: err.message });
            }
        }

        const isLuaObfuscator = totalConfidence >= 0.50;
        const version = this.inferVersion(results, code);

        return {
            isLuaObfuscator,
            confidence: Math.min(totalConfidence, 1.0),
            version,
            layers: results,
        };
    }

    // --- Layer 1: Signature / Watermark ---
    signatureScan(code) {
        const evidence = [];
        let confidence = 0;

        const signatures = [
            { pattern: /lua[_-]?obfuscator/i, label: 'lua-obfuscator keyword' },
            { pattern: /--\s*Obfuscated\s+(with|by)\s+lua/i, label: 'Obfuscation watermark' },
            { pattern: /--\s*This\s+(file|script)\s+was\s+obfuscated/i, label: 'Generated watermark' },
            { pattern: /LUA_OBFUSCATOR/i, label: 'Uppercase tag' },
            { pattern: /luaobfuscator\.com/i, label: 'Domain reference' },
            { pattern: /--\s*lua-obfuscator\s+v[0-9]/i, label: 'Version tag in comment' },
            { pattern: /Obfuscated by lua-obfuscator/i, label: 'Full watermark' },
        ];

        for (const sig of signatures) {
            if (sig.pattern.test(code)) {
                evidence.push(sig.label);
                confidence += 0.20;
            }
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 2: Variable Naming Pattern (KHAS LUA-OBFUSCATOR) ---
    variableNamingPattern(code) {
        const evidence = [];
        let confidence = 0;

        // Signature: short underscore variables: _, _1, _2, _3, _12, _123
        const shortUnderscore = /local\s+(_[0-9]*)\b/g;
        const shortMatches = [...code.matchAll(shortUnderscore)];

        if (shortMatches.length >= 10) {
            evidence.push(`Short underscore variables (_1, _2, ...): ${shortMatches.length}`);
            confidence += 0.40;
        } else if (shortMatches.length >= 5) {
            evidence.push(`Short underscore variables: ${shortMatches.length}`);
            confidence += 0.20;
        }

        // Single underscore `_` as variable (sangat khas lua-obfuscator)
        const singleUnderscore = /local\s+_([0-9]+)?\s*=/g;
        const singleMatches = [...code.matchAll(singleUnderscore)];
        if (singleMatches.length >= 5) {
            evidence.push(`Single underscore assignments: ${singleMatches.length}`);
            confidence += 0.25;
        }

        // Ratio: underscore vars / total vars
        const allVars = code.match(/local\s+([a-zA-Z_][a-zA-Z0-9_]*)/g) || [];
        const underscoreVars = allVars.filter(v => {
            const name = v.replace('local ', '');
            return /^_[0-9]*$/.test(name);
        });
        const ratio = allVars.length > 0 ? underscoreVars.length / allVars.length : 0;

        if (ratio > 0.5) {
            evidence.push(`Underscore variable ratio: ${(ratio * 100).toFixed(1)}%`);
            confidence += 0.30;
        } else if (ratio > 0.25) {
            evidence.push(`Underscore variable ratio: ${(ratio * 100).toFixed(1)}%`);
            confidence += 0.15;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 3: IIFE Pattern (KHAS LUA-OBFUSCATOR) ---
    iifePattern(code) {
        const evidence = [];
        let confidence = 0;

        // IIFE: (function(...) ... end)(...)
        const iifePattern = /\(\s*function\s*\([^)]*\)[\s\S]*?end\s*\)\s*\([^)]*\)/g;
        const iifeMatches = code.match(iifePattern);
        if (iifeMatches && iifeMatches.length >= 3) {
            evidence.push(`IIFE wrappers: ${iifeMatches.length}`);
            confidence += 0.35;
        } else if (iifeMatches && iifeMatches.length >= 1) {
            evidence.push(`IIFE wrappers: ${iifeMatches.length}`);
            confidence += 0.15;
        }

        // Nested IIFE: (function() return function() ... end end)()
        const nestedIIFE = /\(\s*function\s*\(\s*\)\s*return\s+\(\s*function/g;
        const nestedMatches = code.match(nestedIIFE);
        if (nestedMatches && nestedMatches.length >= 2) {
            evidence.push(`Nested IIFE: ${nestedMatches.length}`);
            confidence += 0.25;
        }

        // IIFE with string table: (function(...) local _ = {...} ... end)({...})
        const tableIIFE = /\(\s*function\s*\([^)]*\)[\s\S]*?local\s+_[0-9]*\s*=\s*\{[\s\S]*?\}[\s\S]*?end\s*\)\s*\(\s*\{/g;
        if (tableIIFE.test(code)) {
            evidence.push('IIFE with inline string table');
            confidence += 0.20;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 4: String Encryption Pattern ---
    stringEncryptionPattern(code) {
        const evidence = [];
        let confidence = 0;

        // Base64 + XOR combination (khas lua-obfuscator)
        const base64Pattern = /["'][A-Za-z0-9+\/=]{20,}["']/g;
        const base64Matches = code.match(base64Pattern);
        if (base64Matches && base64Matches.length >= 3) {
            evidence.push(`Base64 strings: ${base64Matches.length}`);
            confidence += 0.20;
        }

        // XOR pattern
        const xorPattern = /bit32\.bxor\s*\(\s*\d+\s*,\s*\d+\s*\)/g;
        const xorMatches = code.match(xorPattern);
        if (xorMatches && xorMatches.length >= 5) {
            evidence.push(`XOR operations: ${xorMatches.length}`);
            confidence += 0.20;
        }

        // string.char + byte manipulation (string.byte, string.sub combo)
        const byteComboPattern = /string\.byte\s*\([^)]+\)[\s\S]*?string\.char/g;
        if (byteComboPattern.test(code)) {
            evidence.push('string.byte + string.char combo');
            confidence += 0.20;
        }

        // string.reverse usage (khas lua-obfuscator v1-v2)
        const reversePattern = /string\.reverse\s*\([^)]+\)/g;
        const reverseMatches = code.match(reversePattern);
        if (reverseMatches && reverseMatches.length >= 2) {
            evidence.push(`string.reverse usage: ${reverseMatches.length}`);
            confidence += 0.15;
        }

        // Decrypt function
        const decryptFuncPattern = /function\s+_[0-9]*\s*\([^)]*\)[\s\S]{80,}return\s+string\.char/g;
        if (decryptFuncPattern.test(code)) {
            evidence.push('Decrypt function with underscore name');
            confidence += 0.20;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 5: Loadstring Pattern ---
    loadstringPattern(code) {
        const evidence = [];
        let confidence = 0;

        // loadstring final execution
        const loadstringPattern = /loadstring\s*\(\s*_[0-9]*\s*\)\s*\(\s*\)/g;
        const loadMatches = code.match(loadstringPattern);
        if (loadMatches && loadMatches.length >= 1) {
            evidence.push(`loadstring(_N)() final exec: ${loadMatches.length}`);
            confidence += 0.35;
        }

        // loadstring + table.concat
        const loadConcatPattern = /loadstring\s*\(\s*table\.concat\s*\(\s*_[0-9]*\s*\)/g;
        if (loadConcatPattern.test(code)) {
            evidence.push('loadstring + table.concat');
            confidence += 0.25;
        }

        // loadstring + decrypt function call
        const loadDecryptPattern = /loadstring\s*\(\s*_[0-9]*\s*\(\s*_[0-9]*\s*\)\s*\)/g;
        if (loadDecryptPattern.test(code)) {
            evidence.push('loadstring(decrypt(...)) pattern');
            confidence += 0.30;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 6: VM Structure Detection (v3+) ---
    vmStructureDetection(code) {
        const evidence = [];
        let confidence = 0;

        // VM dispatch table
        const dispatchPattern = /local\s+_[0-9]+\s*=\s*\{[\s\S]*?\[\d+\]\s*=\s*function/g;
        const dispatchMatches = code.match(dispatchPattern);
        if (dispatchMatches && dispatchMatches.length >= 5) {
            evidence.push(`VM dispatch table: ${dispatchMatches.length} opcodes`);
            confidence += 0.35;
        }

        // Bytecode array
        const bytecodePattern = /local\s+_[0-9]+\s*=\s*\{\s*[\d\s,]{80,}\s*\}/;
        if (bytecodePattern.test(code)) {
            evidence.push('Bytecode array detected');
            confidence += 0.20;
        }

        // VM loop
        const vmLoopPattern = /while\s+true\s+do[\s\S]{300,}if\s+_[0-9]+\s*==\s*\d+/;
        if (vmLoopPattern.test(code)) {
            evidence.push('VM dispatch loop detected');
            confidence += 0.20;
        }

        // Stack operations
        const stackPattern = /table\.insert\([^,]+,\s*[^)]+\)|table\.remove\([^)]+\)/g;
        const stackMatches = code.match(stackPattern);
        if (stackMatches && stackMatches.length >= 8) {
            evidence.push(`Stack operations: ${stackMatches.length}`);
            confidence += 0.15;
        }

        return { confidence: Math.min(confidence, 1.0), evidence, versionHint: confidence > 0.4 ? 'v3-vm' : null };
    }

    // --- Layer 7: Heuristic Analysis ---
    heuristicAnalysis(code) {
        const evidence = [];
        let confidence = 0;

        // High entropy strings
        const stringLiterals = code.match(/"([^"\\]|\\.)*"/g) || [];
        let highEntropyStrings = 0;
        for (const s of stringLiterals) {
            if (this.calculateEntropy(s) > 4.5 && s.length > 20) {
                highEntropyStrings++;
            }
        }
        if (highEntropyStrings > 5) {
            evidence.push(`High-entropy strings: ${highEntropyStrings}`);
            confidence += 0.25;
        }

        // Minified structure
        const lines = code.split('\n').filter(l => l.trim().length > 0);
        const avgLineLength = code.length / Math.max(lines.length, 1);
        if (avgLineLength > 5000 && lines.length < 10) {
            evidence.push(`Minified: ${lines.length} lines, avg ${avgLineLength.toFixed(0)} chars/line`);
            confidence += 0.20;
        }

        // Function density
        const functionCount = (code.match(/\bfunction\b/g) || []).length;
        const localCount = (code.match(/\blocal\b/g) || []).length;
        if (localCount > 0 && functionCount / localCount > 0.3) {
            evidence.push(`High function/local ratio: ${(functionCount / localCount).toFixed(2)}`);
            confidence += 0.15;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    calculateEntropy(str) {
        if (!str || str.length === 0) return 0;
        const freq = {};
        for (const c of str) freq[c] = (freq[c] || 0) + 1;
        let entropy = 0;
        const len = str.length;
        for (const c in freq) {
            const p = freq[c] / len;
            if (p > 0) entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    inferVersion(results, code) {
        const vm = results.find(r => r.layer === 'VMStructureDetection');
        const loadstring = results.find(r => r.layer === 'LoadstringPattern');
        const iife = results.find(r => r.layer === 'IIFEPattern');

        if (vm && vm.confidence > 0.5) {
            return 'v3-vm';
        }
        if (loadstring && loadstring.confidence > 0.3 && iife && iife.confidence > 0.2) {
            return 'v2-loadstring-iife';
        }
        if (loadstring && loadstring.confidence > 0.3) {
            return 'v2-loadstring';
        }
        if (iife && iife.confidence > 0.2) {
            return 'v1-iife';
        }
        if (results.some(r => r.confidence > 0 && r.layer === 'SignatureScan')) {
            return 'v1-legacy';
        }
        return 'unknown';
    }
}


// ============================================================
// SECTION 2: DEOBFUSCATION ENGINE
// ============================================================

export class LuaObfuscatorDeobfuscator {
    constructor() {
        this.levels = [
            { name: 'BasicCleanup', run: this.level1BasicCleanup.bind(this) },
            { name: 'StringDecryption', run: this.level2StringDecryption.bind(this) },
            { name: 'Base64Decryption', run: this.level3Base64Decryption.bind(this) },
            { name: 'ConstantDecryption', run: this.level4ConstantDecryption.bind(this) },
            { name: 'VariableRenaming', run: this.level5VariableRenaming.bind(this) },
            { name: 'LoadstringResolution', run: this.level6LoadstringResolution.bind(this) },
            { name: 'IIFEUnwrapping', run: this.level7IIFEUnwrapping.bind(this) },
            { name: 'ControlFlowUnflattening', run: this.level8CFFUnflattening.bind(this) },
            { name: 'VMMetadataExtraction', run: this.level9VMMetadataExtraction.bind(this) },
        ];
    }

    deobfuscate(code, detectionResult = null) {
        if (!code) return { success: false, deobfuscatedCode: '', appliedLevels: [], notes: 'Empty input' };

        let current = code;
        const appliedLevels = [];
        const notes = [];

        const orderedLevels = this.orderLevelsByHint(detectionResult);

        for (const level of orderedLevels) {
            try {
                const before = current;
                const result = level.run(current);

                if (result.changed && result.code !== before) {
                    current = result.code;
                    appliedLevels.push({
                        level: level.name,
                        changes: result.changes || 0,
                        notes: result.notes || null,
                    });

                    if (this.isClean(current)) {
                        notes.push(`Early exit after ${level.name}`);
                        break;
                    }
                }
            } catch (err) {
                notes.push(`${level.name} failed: ${err.message}`);
            }
        }

        return {
            success: appliedLevels.length > 0,
            deobfuscatedCode: current,
            appliedLevels,
            notes: notes.join(' | '),
            finalEntropy: this.calculateEntropy(current),
        };
    }

    orderLevelsByHint(detection) {
        if (!detection || !detection.version) return this.levels;

        const v = detection.version;
        if (v === 'v3-vm') {
            return [
                this.levels[1], // String
                this.levels[2], // Base64
                this.levels[8], // VM
                this.levels[0], // Cleanup
                this.levels[3], // Constant
                this.levels[4], // Rename
                this.levels[5], // Loadstring
                this.levels[6], // IIFE
                this.levels[7], // CFF
            ];
        }
        if (v === 'v2-loadstring-iife' || v === 'v2-loadstring') {
            return [
                this.levels[1], // String
                this.levels[2], // Base64
                this.levels[5], // Loadstring
                this.levels[6], // IIFE
                this.levels[0], // Cleanup
                this.levels[3], // Constant
                this.levels[4], // Rename
                this.levels[7], // CFF
                this.levels[8], // VM
            ];
        }
        if (v === 'v1-iife' || v === 'v1-legacy') {
            return [
                this.levels[1], // String
                this.levels[2], // Base64
                this.levels[6], // IIFE
                this.levels[0], // Cleanup
                this.levels[3], // Constant
                this.levels[4], // Rename
                this.levels[5], // Loadstring
                this.levels[7], // CFF
                this.levels[8], // VM
            ];
        }
        return this.levels;
    }

    // --- LEVEL 1: Basic Cleanup ---
    level1BasicCleanup(code) {
        let result = code;
        let changes = 0;

        // Hapus watermark lua-obfuscator
        const before = result;
        result = result.replace(/--\s*Obfuscated\s+(with|by)\s+lua[_-]?obfuscator.*/gi, '');
        result = result.replace(/--\s*This\s+(file|script)\s+was\s+obfuscated.*/gi, '');
        result = result.replace(/--\s*lua-obfuscator.*/gi, '');
        if (result !== before) changes++;

        // Hapus komentar kosong beruntun
        result = result.replace(/(--[^\n]*\n){3,}/g, '--\n');

        // Opaque predicate sederhana
        const opaquePattern = /if\s+\(([^)]{10,})\)\s*then\s*([\s\S]*?)\s*end/g;
        result = result.replace(opaquePattern, (match, cond, body) => {
            if (/^\s*\(?[a-zA-Z_0-9]+\s*==\s*\1\)?\s*$/.test(cond) || /^\s*\(?\s*0\s*==\s*0\s*\)?\s*$/.test(cond)) {
                changes++;
                return body.trim();
            }
            return match;
        });

        return { code: result, changed: result !== code, changes };
    }

    // --- LEVEL 2: String Decryption ---
    level2StringDecryption(code) {
        let result = code;
        let changes = 0;

        // Pattern 1: string.char(a, b, c) langsung
        result = result.replace(/string\.char\(([\d\s,]+)\)/g, (match, args) => {
            try {
                const bytes = args.split(',').map(s => parseInt(s.trim(), 10));
                if (bytes.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
                    changes++;
                    return JSON.stringify(String.fromCharCode(...bytes));
                }
            } catch (e) { /* ignore */ }
            return match;
        });

        // Pattern 2: XOR dengan key recovery
        const keyPatterns = [
            /local\s+(_[0-9]*)\s*=\s*(\d+)\s*(?:--\s*key)?/i,
        ];

        let recoveredKey = null;
        let keyName = null;
        for (const kp of keyPatterns) {
            const km = code.match(kp);
            if (km) {
                const candidate = parseInt(km[2], 10);
                if (candidate >= 0 && candidate <= 255) {
                    recoveredKey = candidate;
                    keyName = km[1];
                    break;
                }
            }
        }

        if (recoveredKey !== null) {
            const xorCharPattern = /string\.char\(\s*((?:bit32\.bxor\(\s*\d+\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)\s*,?\s*)+)\)/g;
            result = result.replace(xorCharPattern, (match, inner) => {
                try {
                    const byteMatches = [...inner.matchAll(/bit32\.bxor\(\s*(\d+)\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)/g)];
                    const bytes = byteMatches.map(m => {
                        const byte = parseInt(m[1], 10);
                        const varKey = m[2];
                        if (varKey === keyName) return byte ^ recoveredKey;
                        return byte;
                    });
                    if (bytes.length > 0 && bytes.every(n => n >= 0 && n <= 255)) {
                        changes++;
                        return JSON.stringify(String.fromCharCode(...bytes));
                    }
                } catch (e) { /* ignore */ }
                return match;
            });
        }

        // Pattern 3: String table lookup
        const tablePattern = /local\s+(_[0-9]+)\s*=\s*\{([^}]+)\}/;
        const tableMatch = result.match(tablePattern);
        if (tableMatch) {
            const tableName = tableMatch[1];
            const entries = tableMatch[2].split(',').map(s => {
                const trimmed = s.trim();
                if (/^["'].*["']$/.test(trimmed)) {
                    try { return JSON.parse(trimmed); } catch (e) { return null; }
                }
                const n = parseInt(trimmed, 10);
                return isNaN(n) ? null : n;
            });

            const lookupPattern = new RegExp(`${tableName}\\[(\\d+)\\]`, 'g');
            result = result.replace(lookupPattern, (match, idx) => {
                const i = parseInt(idx, 10);
                if (entries[i] !== null && entries[i] !== undefined) {
                    changes++;
                    return typeof entries[i] === 'string' ? JSON.stringify(entries[i]) : entries[i];
                }
                return match;
            });
        }

        // Pattern 4: string.reverse + string.char
        result = result.replace(/string\.reverse\s*\(\s*string\.char\(([\d\s,]+)\)\s*\)/g, (match, args) => {
            try {
                const bytes = args.split(',').map(s => parseInt(s.trim(), 10));
                if (bytes.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
                    changes++;
                    const str = String.fromCharCode(...bytes);
                    return JSON.stringify(str.split('').reverse().join(''));
                }
            } catch (e) { /* ignore */ }
            return match;
        });

        return { code: result, changed: result !== code, changes, notes: changes > 0 ? `Decrypted ${changes} strings` : null };
    }

    // --- LEVEL 3: Base64 Decryption ---
    level3Base64Decryption(code) {
        let result = code;
        let changes = 0;

        // Detect base64 decode function (lua-obfuscator sering inline base64 decoder)
        // Pattern: function _N(s) ... return ... end lalu dipanggil ke string base64
        const b64FuncPattern = /function\s+(_[0-9]+)\s*\([^)]*\)[\s\S]*?return\s+string\.char[\s\S]*?end/;
        const b64FuncMatch = code.match(b64FuncPattern);

        if (b64FuncMatch) {
            const funcName = b64FuncMatch[1];
            // Cek apakah function ini dipanggil dengan base64 string
            const callPattern = new RegExp(`${funcName}\\s*\\(\\s*["']([A-Za-z0-9+\\/=]{20,})["']\\s*\\)`, 'g');
            result = result.replace(callPattern, (match, b64str) => {
                try {
                    // Decode base64 (simplified — asumsikan function ini base64 decoder)
                    const decoded = atob(b64str);
                    changes++;
                    return JSON.stringify(decoded);
                } catch (e) { /* ignore */ }
                return match;
            });
        }

        // Pattern: inline base64 decode table
        const b64TablePattern = /local\s+(_[0-9]+)\s*=\s*["'][A-Za-z0-9+\/=]{20,}["']/g;
        const b64TableMatches = [...code.matchAll(b64TablePattern)];
        if (b64TableMatches.length >= 2) {
            for (const m of b64TableMatches) {
                try {
                    const b64 = m[0].match(/["']([^"']+)["']/)[1];
                    const decoded = atob(b64);
                    // Cek apakah decoded looks like readable text
                    if (/^[\x20-\x7E]+$/.test(decoded) && decoded.length > 5) {
                        result = result.replace(m[0], `local ${m[0].split('=')[0].trim()} = ${JSON.stringify(decoded)}`);
                        changes++;
                    }
                } catch (e) { /* ignore */ }
            }
        }

        return { code: result, changed: result !== code, changes, notes: changes > 0 ? `Decoded ${changes} base64 strings` : null };
    }

    // --- LEVEL 4: Constant Decryption ---
    level4ConstantDecryption(code) {
        let result = code;
        let changes = 0;

        // Fold arithmetic
        result = result.replace(/\(\s*(\d+)\s*([+\-*/])\s*(\d+)\s*\)/g, (match, a, op, b) => {
            const na = parseInt(a, 10);
            const nb = parseInt(b, 10);
            let r;
            switch (op) {
                case '+': r = na + nb; break;
                case '-': r = na - nb; break;
                case '*': r = na * nb; break;
                case '/': r = nb !== 0 ? na / nb : null; break;
            }
            if (r !== null && r !== undefined && Number.isFinite(r)) {
                changes++;
                return String(r);
            }
            return match;
        });

        // Fold bit32 operations
        result = result.replace(/bit32\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, a, b) => {
            changes++;
            return String(parseInt(a, 10) ^ parseInt(b, 10));
        });
        result = result.replace(/bit32\.band\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, a, b) => {
            changes++;
            return String(parseInt(a, 10) & parseInt(b, 10));
        });
        result = result.replace(/bit32\.bor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, a, b) => {
            changes++;
            return String(parseInt(a, 10) | parseInt(b, 10));
        });
        result = result.replace(/bit32\.lshift\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, a, b) => {
            changes++;
            return String(parseInt(a, 10) << parseInt(b, 10));
        });
        result = result.replace(/bit32\.rshift\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, a, b) => {
            changes++;
            return String(parseInt(a, 10) >>> parseInt(b, 10));
        });

        // Fold string operations: string.len("...") → N
        result = result.replace(/string\.len\s*\(\s*"([^"]*)"\s*\)/g, (match, s) => {
            changes++;
            return String(s.length);
        });

        // Fold string.sub yang bisa di-resolve
        result = result.replace(/string\.sub\s*\(\s*"([^"]*)"\s*,\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, s, start, end) => {
            changes++;
            return JSON.stringify(s.substring(parseInt(start, 10) - 1, parseInt(end, 10)));
        });

        return { code: result, changed: result !== code, changes, notes: changes > 0 ? `Folded ${changes} constants` : null };
    }

    // --- LEVEL 5: Variable Renaming ---
    level5VariableRenaming(code) {
        let result = code;
        let changes = 0;

        // Collect underscore variables: _, _1, _2, _12, _123
        const underscoreVars = new Set();
        const varPattern = /\b(_[0-9]*)\b/g;
        let m;
        while ((m = varPattern.exec(code)) !== null) {
            if (m[1].length >= 1 && !this.isLuaKeyword(m[1])) {
                underscoreVars.add(m[1]);
            }
        }

        // Also collect _0x...
        const hexPattern = /\b(_0x[0-9a-fA-F]+)\b/g;
        while ((m = hexPattern.exec(code)) !== null) {
            underscoreVars.add(m[1]);
        }

        if (underscoreVars.size === 0) return { code: result, changed: false, changes: 0 };

        const renameMap = {};
        let counter = 1;
        // Sort by length (shorter first) biar _ → v1, _1 → v2, _12 → v3
        const sorted = [...underscoreVars].sort((a, b) => a.length - b.length);
        for (const v of sorted) {
            renameMap[v] = `v${counter++}`;
        }

        for (const [oldName, newName] of Object.entries(renameMap)) {
            const re = new RegExp(`\\b${oldName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g');
            result = result.replace(re, newName);
            changes++;
        }

        return { code: result, changed: result !== code, changes, notes: `Renamed ${changes} variables` };
    }

    isLuaKeyword(name) {
        const keywords = new Set([
            'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
            'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat',
            'return', 'then', 'true', 'until', 'while', 'continue',
        ]);
        return keywords.has(name);
    }

    // --- LEVEL 6: Loadstring Resolution ---
    level6LoadstringResolution(code) {
        let result = code;
        let changes = 0;

        // Pattern: loadstring(_N)()
        const loadstringPattern = /loadstring\s*\(\s*(_[0-9]+)\s*\)\s*\(\s*\)/g;
        result = result.replace(loadstringPattern, (match, varName) => {
            const defPattern = new RegExp(`local\\s+${varName}\\s*=\\s*([^\\n]+)`);
            const defMatch = result.match(defPattern);
            if (defMatch) {
                const value = defMatch[1].trim();
                if (/^["'].*["']$/.test(value)) {
                    changes++;
                    return value;
                }
                if (/^[a-zA-Z_][a-zA-Z0-9_]*\s*\(/.test(value)) {
                    changes++;
                    return `--[[ loadstring resolved: ${varName} = ${value} ]]`;
                }
            }
            return match;
        });

        // Pattern: loadstring(table.concat(_N))()
        const loadConcatPattern = /loadstring\s*\(\s*table\.concat\s*\(\s*(_[0-9]+)\s*\)\s*\)\s*\(\s*\)/g;
        result = result.replace(loadConcatPattern, (match, tableName) => {
            const tablePattern = new RegExp(`local\\s+${tableName}\\s*=\\s*\\{([^}]+)\\}`);
            const tableMatch = result.match(tablePattern);
            if (tableMatch) {
                const entries = tableMatch[1].split(',').map(s => {
                    const trimmed = s.trim();
                    if (/^["'].*["']$/.test(trimmed)) {
                        try { return JSON.parse(trimmed); } catch (e) { return null; }
                    }
                    return null;
                }).filter(x => x !== null);

                if (entries.length > 0) {
                    const concatenated = entries.join('');
                    changes++;
                    return JSON.stringify(concatenated);
                }
            }
            return match;
        });

        return { code: result, changed: result !== code, changes, notes: changes > 0 ? `Resolved ${changes} loadstring calls` : null };
    }

    // --- LEVEL 7: IIFE Unwrapping ---
    level7IIFEUnwrapping(code) {
        let result = code;
        let changes = 0;

        // Pattern: (function() return X end)() → X
        const iifeReturnPattern = /\(\s*function\s*\(\s*\)\s*return\s+([\s\S]+?)\s*end\s*\)\s*\(\s*\)/g;
        result = result.replace(iifeReturnPattern, (match, inner) => {
            // Cek apakah inner bukan function definition lain
            if (!/^\s*function\s*\(/.test(inner)) {
                changes++;
                return inner.trim();
            }
            return match;
        });

        // Pattern: (function(...) ... end)(args) → inline body dengan args substitution
        const iifePattern = /\(\s*function\s*\(([^)]*)\)([\s\S]*?)end\s*\)\s*\(([^)]*)\)/g;
        result = result.replace(iifePattern, (match, params, body, args) => {
            const paramList = params.split(',').map(s => s.trim()).filter(Boolean);
            const argList = args.split(',').map(s => s.trim()).filter(Boolean);

            if (paramList.length === argList.length && paramList.length > 0) {
                let inlined = body;
                for (let i = 0; i < paramList.length; i++) {
                    const re = new RegExp(`\\b${paramList[i]}\\b`, 'g');
                    inlined = inlined.replace(re, argList[i]);
                }
                changes++;
                return inlined.trim();
            }
            return match;
        });

        // Iterasi sampai stabil (nested IIFE)
        let prevResult = '';
        let iterations = 0;
        while (prevResult !== result && iterations < 5) {
            prevResult = result;
            result = result.replace(/\(\s*function\s*\(\s*\)\s*return\s+([\s\S]+?)\s*end\s*\)\s*\(\s*\)/g, (match, inner) => {
                if (!/^\s*function\s*\(/.test(inner)) {
                    changes++;
                    return inner.trim();
                }
                return match;
            });
            iterations++;
        }

        return { code: result, changed: result !== code, changes, notes: changes > 0 ? `Unwrapped ${changes} IIFE` : null };
    }

    // --- LEVEL 8: Control Flow Unflattening ---
    level8CFFUnflattening(code) {
        let result = code;
        let changes = 0;

        const cffPattern = /local\s+(v\d+|_[0-9]+)\s*=\s*(0x[0-9a-fA-F]+|\d+)([\s\S]*?while\s+true\s+do[\s\S]*?end)/;
        const cffMatch = result.match(cffPattern);

        if (cffMatch) {
            const stateVar = cffMatch[1];
            const loopBody = cffMatch[3];

            const branchRegex = new RegExp(`(?:if|elseif)\\s+${stateVar}\\s*==\\s*(0x[0-9a-fA-F]+|\\d+)\\s*then([\\s\\S]*?)(?=(?:elseif|else|end))`, 'g');
            const branches = [];
            let bm;
            while ((bm = branchRegex.exec(loopBody)) !== null) {
                branches.push({ state: bm[1], body: bm[2].trim() });
            }

            if (branches.length >= 2) {
                branches.sort((a, b) => parseInt(a.state, 16) - parseInt(b.state, 16));
                let reconstructed = branches.map(b => {
                    return b.body
                        .replace(new RegExp(`${stateVar}\\s*=\\s*(0x[0-9a-fA-F]+|\\d+)\\s*`), '')
                        .replace(/break\s*/g, '')
                        .trim();
                }).filter(b => b.length > 0).join('\n');

                result = result.replace(cffMatch[0], reconstructed);
                changes++;
            }
        }

        return { code: result, changed: result !== code, changes, notes: changes > 0 ? 'Unflattened control flow' : null };
    }

    // --- LEVEL 9: VM Metadata Extraction ---
    level9VMMetadataExtraction(code) {
        let result = code;
        let changes = 0;
        const notes = [];

        const dispatchPattern = /local\s+(_[0-9]+)\s*=\s*\{([\s\S]*?)\}/;
        const dispatchMatch = result.match(dispatchPattern);

        if (dispatchMatch) {
            const tableName = dispatchMatch[1];
            const tableBody = dispatchMatch[2];
            const funcEntries = (tableBody.match(/function/g) || []).length;

            if (funcEntries >= 5) {
                notes.push(`VM dispatch table: ${tableName} (${funcEntries} opcodes)`);

                const bytecodePattern = /local\s+(_[0-9]+)\s*=\s*\{\s*([\d\s,]+)\s*\}/;
                const bytecodeMatch = result.match(bytecodePattern);

                if (bytecodeMatch) {
                    const bytecodeName = bytecodeMatch[1];
                    const bytecode = bytecodeMatch[2].split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
                    notes.push(`Bytecode: ${bytecodeName} (${bytecode.length} ops)`);

                    const vmLoopPattern = /while\s+true\s+do[\s\S]*?break[\s\S]*?end/;
                    if (vmLoopPattern.test(result)) {
                        result = result.replace(vmLoopPattern,
                            `-- [[ VM LOOP EXTRACTED BY KAIRO ]]\n-- Bytecode: [${bytecode.slice(0, 30).join(', ')}${bytecode.length > 30 ? ', ...' : ''}]\n-- Opcodes: ${funcEntries}\n-- Full VM emulation required`);
                        changes++;
                    }
                }
            }
        }

        return { code: result, changed: result !== code, changes, notes: notes.length > 0 ? notes.join(' | ') : null };
    }

    calculateEntropy(str) {
        if (!str || str.length === 0) return 0;
        const freq = {};
        for (const c of str) freq[c] = (freq[c] || 0) + 1;
        let entropy = 0;
        const len = str.length;
        for (const c in freq) {
            const p = freq[c] / len;
            if (p > 0) entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    isClean(code) {
        const hasUnderscoreVars = /\b_[0-9]+\b/.test(code);
        const hasHexVars = /_0x[0-9a-fA-F]{4,}/.test(code);
        const entropy = this.calculateEntropy(code);
        const hasDispatcher = /while\s+true\s+do[\s\S]{200,}if.*==.*then/.test(code);
        return !hasUnderscoreVars && !hasHexVars && entropy < 4.0 && !hasDispatcher;
    }
}


// ============================================================
// SECTION 3: ORCHESTRATOR
// ============================================================

export function processLuaObfuscator(code) {
    const detector = new LuaObfuscatorDetector();
    const detection = detector.detect(code);

    if (!detection.isLuaObfuscator) {
        return {
            success: false,
            detection,
            deobfuscation: null,
            message: 'Input tidak terdeteksi sebagai lua-obfuscator',
        };
    }

    const deobfuscator = new LuaObfuscatorDeobfuscator();
    const deobfuscation = deobfuscator.deobfuscate(code, detection);

    return {
        success: deobfuscation.success,
        detection,
        deobfuscation,
        message: deobfuscation.success
            ? `Deobfuscation selesai. Version: ${detection.version}. Applied: ${deobfuscation.appliedLevels.map(l => l.level).join(', ')}`
            : 'Detect sebagai lua-obfuscator tapi deobfuscation tidak menghasilkan perubahan signifikan',
    };
}
