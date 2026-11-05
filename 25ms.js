/**
 * KAIRO ENGINE // 25ms Obfuscator Detector & Deobfuscator
 * Target: Luau scripts obfuscated by 25ms
 * Signature: _25ms_ / ms_ prefix, custom string encoding, loadstring execution, VM-lite
 */

// ============================================================
// SECTION 1: DETECTION ENGINE
// ============================================================

export class Ms25Detector {
    constructor() {
        this.layers = [
            { name: 'SignatureScan', weight: 0.30, run: this.signatureScan.bind(this) },
            { name: 'VariableNamingPattern', weight: 0.25, run: this.variableNamingPattern.bind(this) },
            { name: 'StringEncryptionPattern', weight: 0.15, run: this.stringEncryptionPattern.bind(this) },
            { name: 'LoadstringPattern', weight: 0.15, run: this.loadstringPattern.bind(this) },
            { name: 'HeuristicAnalysis', weight: 0.15, run: this.heuristicAnalysis.bind(this) },
        ];
    }

    detect(code) {
        if (!code || typeof code !== 'string') {
            return { is25ms: false, confidence: 0, version: 'unknown', layers: [], error: 'Empty input' };
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

        const is25ms = totalConfidence >= 0.50;
        const version = this.inferVersion(results, code);

        return {
            is25ms,
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
            { pattern: /25ms/i, label: '25ms keyword' },
            { pattern: /25[_-]?ms/i, label: '25-ms variant' },
            { pattern: /--\s*\[\[\s*25ms/i, label: '25ms header comment' },
            { pattern: /Protected by 25ms/i, label: 'Protection watermark' },
            { pattern: /25ms\s+Obfuscator/i, label: '25ms obfuscator comment' },
            { pattern: /obfuscated with 25ms/i, label: 'Generation tag' },
        ];

        for (const sig of signatures) {
            if (sig.pattern.test(code)) {
                evidence.push(sig.label);
                confidence += 0.20;
            }
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 2: Variable Naming Pattern ---
    variableNamingPattern(code) {
        const evidence = [];
        let confidence = 0;

        // 25ms signature: variable dengan prefix `_25ms_`, `ms_`, atau `v25`
        const msPrefix = /local\s+(_25ms_[a-zA-Z0-9_]+|ms_[a-zA-Z0-9_]+|v25[a-zA-Z0-9_]*)/g;
        const msMatches = [...code.matchAll(msPrefix)];

        if (msMatches.length >= 5) {
            evidence.push(`25ms-prefixed variables: ${msMatches.length}`);
            confidence += 0.40;
        } else if (msMatches.length >= 2) {
            evidence.push(`25ms-prefixed variables: ${msMatches.length}`);
            confidence += 0.20;
        }

        // Mix pattern: _0x... + ms_...
        const mixPattern = /local\s+(_0x[0-9a-fA-F]+|_25ms_[a-zA-Z0-9_]+|ms_[a-zA-Z0-9_]+)/g;
        const mixMatches = [...code.matchAll(mixPattern)];
        if (mixMatches.length >= 8) {
            evidence.push(`Mixed obfuscation variables: ${mixMatches.length}`);
            confidence += 0.25;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 3: String Encryption Pattern ---
    stringEncryptionPattern(code) {
        const evidence = [];
        let confidence = 0;

        // XOR pattern
        const xorPattern = /bit32\.bxor\s*\(\s*\d+\s*,\s*\d+\s*\)/g;
        const xorMatches = code.match(xorPattern);
        if (xorMatches && xorMatches.length >= 5) {
            evidence.push(`XOR operations: ${xorMatches.length}`);
            confidence += 0.25;
        }

        // string.char + bit32 kombinasi
        const charBxorPattern = /string\.char\s*\([^)]*bit32\.bxor[^)]*\)/g;
        const charBxorMatches = code.match(charBxorPattern);
        if (charBxorMatches && charBxorMatches.length >= 3) {
            evidence.push(`string.char + bit32.bxor: ${charBxorMatches.length}`);
            confidence += 0.20;
        }

        // Base64-like strings (25ms sering pakai ini buat payload)
        const b64Pattern = /["'][A-Za-z0-9+\/=]{30,}["']/g;
        const b64Matches = code.match(b64Pattern);
        if (b64Matches && b64Matches.length >= 3) {
            evidence.push(`Base64-like strings: ${b64Matches.length}`);
            confidence += 0.15;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 4: Loadstring Pattern ---
    loadstringPattern(code) {
        const evidence = [];
        let confidence = 0;

        // loadstring final execution
        const loadstringPattern = /loadstring\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)\s*\(\s*\)/g;
        const loadMatches = code.match(loadstringPattern);
        if (loadMatches && loadMatches.length >= 1) {
            evidence.push(`loadstring() final exec: ${loadMatches.length}`);
            confidence += 0.35;
        }

        // loadstring + table.concat
        const loadConcatPattern = /loadstring\s*\(\s*table\.concat/g;
        if (loadConcatPattern.test(code)) {
            evidence.push('loadstring + table.concat pattern');
            confidence += 0.25;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 5: Heuristic Analysis ---
    heuristicAnalysis(code) {
        const evidence = [];
        let confidence = 0;

        // Minified structure (25ms fokus ke size/speed)
        const lines = code.split('\n').filter(l => l.trim().length > 0);
        const avgLineLength = code.length / Math.max(lines.length, 1);
        if (avgLineLength > 3000 && lines.length < 15) {
            evidence.push(`Minified: ${lines.length} lines, avg ${avgLineLength.toFixed(0)} chars/line`);
            confidence += 0.30;
        }

        // High function density
        const functionCount = (code.match(/\bfunction\b/g) || []).length;
        const localCount = (code.match(/\blocal\b/g) || []).length;
        if (localCount > 0 && functionCount / localCount > 0.3) {
            evidence.push(`High function/local ratio: ${(functionCount / localCount).toFixed(2)}`);
            confidence += 0.15;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    inferVersion(results, code) {
        const loadstring = results.find(r => r.layer === 'LoadstringPattern');
        if (loadstring && loadstring.confidence > 0.3) {
            return 'v2-loadstring';
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

export class Ms25Deobfuscator {
    constructor() {
        this.levels = [
            { name: 'BasicCleanup', run: this.level1BasicCleanup.bind(this) },
            { name: 'StringDecryption', run: this.level2StringDecryption.bind(this) },
            { name: 'ConstantDecryption', run: this.level3ConstantDecryption.bind(this) },
            { name: 'VariableRenaming', run: this.level4VariableRenaming.bind(this) },
            { name: 'LoadstringResolution', run: this.level5LoadstringResolution.bind(this) },
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
        if (v === 'v2-loadstring') {
            return [
                this.levels[1], // String
                this.levels[4], // Loadstring
                this.levels[0], // Cleanup
                this.levels[2], // Constant
                this.levels[3], // Rename
            ];
        }
        return this.levels;
    }

    // --- LEVEL 1: Basic Cleanup ---
    level1BasicCleanup(code) {
        let result = code;
        let changes = 0;

        // Hapus watermark 25ms
        const before = result;
        result = result.replace(/--\s*\[\[\s*25ms[\s\S]*?\]\]/gi, '');
        result = result.replace(/--\s*Protected by 25ms.*/gi, '');
        result = result.replace(/--\s*25ms\s+Obfuscator.*/gi, '');
        if (result !== before) changes++;

        // Hapus komentar kosong beruntun
        result = result.replace(/(--[^\n]*\n){3,}/g, '--\n');

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
            /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(\d+)\s*(?:--\s*key)?/i,
            /local\s+(_25ms_[a-zA-Z0-9_]+|ms_[a-zA-Z0-9_]+)\s*=\s*(\d+)/,
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
        const tablePattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\{([^}]+)\}/;
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

        return { code: result, changed: result !== code, changes, notes: changes > 0 ? `Decrypted ${changes} strings` : null };
    }

    // --- LEVEL 3: Constant Decryption ---
    level3ConstantDecryption(code) {
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

        return { code: result, changed: result !== code, changes, notes: changes > 0 ? `Folded ${changes} constants` : null };
    }

    // --- LEVEL 4: Variable Renaming ---
    level4VariableRenaming(code) {
        let result = code;
        let changes = 0;

        // Collect 25ms-style variables
        const msVars = new Set();
        const varPatterns = [
            /\b(_25ms_[a-zA-Z0-9_]+|ms_[a-zA-Z0-9_]+|v25[a-zA-Z0-9_]*)\b/g,
            /\b(_0x[0-9a-fA-F]+)\b/g,
        ];

        for (const pattern of varPatterns) {
            let m;
            while ((m = pattern.exec(code)) !== null) {
                if (m[1].length >= 3 && !this.isLuaKeyword(m[1])) {
                    msVars.add(m[1]);
                }
            }
        }

        if (msVars.size === 0) return { code: result, changed: false, changes: 0 };

        const renameMap = {};
        let counter = 1;
        for (const v of msVars) {
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

    // --- LEVEL 5: Loadstring Resolution ---
    level5LoadstringResolution(code) {
        let result = code;
        let changes = 0;

        // Pattern: loadstring(VAR)()
        const loadstringPattern = /loadstring\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*\(\s*\)/g;
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

        // Pattern: loadstring(table.concat(TABLE))()
        const loadConcatPattern = /loadstring\s*\(\s*table\.concat\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*\)\s*\(\s*\)/g;
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
        const hasMsVars = /_25ms_|ms_|v25/.test(code);
        const hasHexVars = /_0x[0-9a-fA-F]{4,}/.test(code);
        const entropy = this.calculateEntropy(code);
        return !hasMsVars && !hasHexVars && entropy < 4.0;
    }
}


// ============================================================
// SECTION 3: ORCHESTRATOR
// ============================================================

export function process25ms(code) {
    const detector = new Ms25Detector();
    const detection = detector.detect(code);

    if (!detection.is25ms) {
        return {
            success: false,
            detection,
            deobfuscation: null,
            message: 'Input tidak terdeteksi sebagai 25ms obfuscator',
        };
    }

    const deobfuscator = new Ms25Deobfuscator();
    const deobfuscation = deobfuscator.deobfuscate(code, detection);

    return {
        success: deobfuscation.success,
        detection,
        deobfuscation,
        message: deobfuscation.success
            ? `Deobfuscation selesai. Version: ${detection.version}. Applied: ${deobfuscation.appliedLevels.map(l => l.level).join(', ')}`
            : 'Detect sebagai 25ms tapi deobfuscation tidak menghasilkan perubahan signifikan',
    };
}
