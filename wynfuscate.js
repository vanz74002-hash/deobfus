/**
 * KAIRO ENGINE // wYnFuscate Obfuscator Detector & Deobfuscator
 * Target: Luau scripts obfuscated by wYnFuscate
 * Signature: wyn_ / wf_ / wYn_ prefix, mixed-case watermark, XOR + shift cipher, CFF, loadstring, VM-lite (v2+)
 */

// ============================================================
// SECTION 1: DETECTION ENGINE
// ============================================================

export class WYnFuscateDetector {
    constructor() {
        this.layers = [
            { name: 'SignatureScan', weight: 0.30, run: this.signatureScan.bind(this) },
            { name: 'VariableNamingPattern', weight: 0.20, run: this.variableNamingPattern.bind(this) },
            { name: 'StringEncryptionPattern', weight: 0.15, run: this.stringEncryptionPattern.bind(this) },
            { name: 'ControlFlowPattern', weight: 0.15, run: this.controlFlowPattern.bind(this) },
            { name: 'LoadstringPattern', weight: 0.10, run: this.loadstringPattern.bind(this) },
            { name: 'HeuristicAnalysis', weight: 0.10, run: this.heuristicAnalysis.bind(this) },
        ];
    }

    detect(code) {
        if (!code || typeof code !== 'string') {
            return { isWYnFuscate: false, confidence: 0, version: 'unknown', layers: [], error: 'Empty input' };
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

        const isWYnFuscate = totalConfidence >= 0.50;
        const version = this.inferVersion(results, code);

        return {
            isWYnFuscate,
            confidence: Math.min(totalConfidence, 1.0),
            version,
            layers: results,
        };
    }

    // --- Layer 1: Signature / Watermark (KHAS WYnFUSCATE — MIXED CASE) ---
    signatureScan(code) {
        const evidence = [];
        let confidence = 0;

        const signatures = [
            { pattern: /wYnFuscate/, label: 'wYnFuscate mixed-case keyword' },
            { pattern: /wynfuscate/i, label: 'wynfuscator keyword' },
            { pattern: /wYn[_-]?fuscate/i, label: 'wYn-fuscate variant' },
            { pattern: /--\s*\[\[\s*wYn/i, label: 'wYn header comment' },
            { pattern: /WYN_V[0-9]/i, label: 'Version tag' },
            { pattern: /Protected by wYn/i, label: 'Protection watermark' },
            { pattern: /Obfuscated with wYnFuscate/i, label: 'Generation tag' },
            { pattern: /wYnFuscate\s+Obfuscator/i, label: 'Obfuscator comment' },
            { pattern: /--\s*wYn\s+Protection/i, label: 'wYn protection tag' },
            { pattern: /\bwYn\b/, label: 'wYn mixed-case standalone' },
        ];

        for (const sig of signatures) {
            if (sig.pattern.test(code)) {
                evidence.push(sig.label);
                confidence += 0.18;
            }
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 2: Variable Naming Pattern (KHAS WYnFUSCATE) ---
    variableNamingPattern(code) {
        const evidence = [];
        let confidence = 0;

        // wYnFuscate signature: variable dengan prefix `wyn_`, `wf_`, `wYn_`, `wynf_`
        const wynPrefix = /local\s+((?:wyn|wf|wYn|wynf|WYN|WF)[a-zA-Z0-9_]*)/g;
        const wynMatches = [...code.matchAll(wynPrefix)];

        if (wynMatches.length >= 5) {
            evidence.push(`wYn-prefixed variables: ${wynMatches.length}`);
            confidence += 0.40;
        } else if (wynMatches.length >= 2) {
            evidence.push(`wYn-prefixed variables: ${wynMatches.length}`);
            confidence += 0.20;
        }

        // Mix pattern: _0x... + wyn_...
        const mixPattern = /local\s+(_0x[0-9a-fA-F]+|(?:wyn|wf|wYn|wynf|WYN|WF)[a-zA-Z0-9_]*)/g;
        const mixMatches = [...code.matchAll(mixPattern)];
        if (mixMatches.length >= 8) {
            evidence.push(`Mixed obfuscation variables: ${mixMatches.length}`);
            confidence += 0.25;
        }

        // Ratio: wyn vars / total vars
        const allVars = code.match(/local\s+([a-zA-Z_][a-zA-Z0-9_]*)/g) || [];
        const wynStyleVars = allVars.filter(v => {
            const name = v.replace('local ', '');
            return /^(?:wyn|wf|wYn|wynf|WYN|WF)/i.test(name) || /^_0x[0-9a-fA-F]+$/.test(name);
        });
        const ratio = allVars.length > 0 ? wynStyleVars.length / allVars.length : 0;

        if (ratio > 0.5) {
            evidence.push(`wYn-style variable ratio: ${(ratio * 100).toFixed(1)}%`);
            confidence += 0.30;
        } else if (ratio > 0.25) {
            evidence.push(`wYn-style variable ratio: ${(ratio * 100).toFixed(1)}%`);
            confidence += 0.15;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 3: String Encryption Pattern ---
    stringEncryptionPattern(code) {
        const evidence = [];
        let confidence = 0;

        // XOR + shift combo (khas wYnFuscate)
        // Pattern: string.char(bit32.bxor(N, K) + offset)
        const xorShiftPattern = /string\.char\s*\(\s*bit32\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)\s*([+\-])\s*(\d+)\s*\)/g;
        const xorShiftMatches = code.match(xorShiftPattern);
        if (xorShiftMatches && xorShiftMatches.length >= 3) {
            evidence.push(`XOR + shift cipher: ${xorShiftMatches.length}`);
            confidence += 0.30;
        }

        // XOR pattern dasar
        const xorPattern = /bit32\.bxor\s*\(\s*\d+\s*,\s*\d+\s*\)/g;
        const xorMatches = code.match(xorPattern);
        if (xorMatches && xorMatches.length >= 5) {
            evidence.push(`XOR operations: ${xorMatches.length}`);
            confidence += 0.20;
        }

        // string.char + bit32 kombinasi
        const charBxorPattern = /string\.char\s*\([^)]*bit32\.bxor[^)]*\)/g;
        const charBxorMatches = code.match(charBxorPattern);
        if (charBxorMatches && charBxorMatches.length >= 3) {
            evidence.push(`string.char + bit32.bxor: ${charBxorMatches.length}`);
            confidence += 0.20;
        }

        // Decrypt function dengan loop
        const decryptFuncPattern = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)[\s\S]{80,}for\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\d+\s*,\s*#[\s\S]*?return\s+string\.char/g;
        if (decryptFuncPattern.test(code)) {
            evidence.push('String decryption function with loop');
            confidence += 0.20;
        }

        // String table
        const stringTablePattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\{\s*"[^"]{10,}"[\s\S]*?\}/;
        if (stringTablePattern.test(code)) {
            evidence.push('Encrypted string table');
            confidence += 0.15;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 4: Control Flow Pattern ---
    controlFlowPattern(code) {
        const evidence = [];
        let confidence = 0;

        // CFF: state variable + while true + if/elseif chain
        const cffPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+|\d+)[\s\S]*?while\s+true\s+do[\s\S]*?(?:if|elseif)\s+\1\s*==/;
        if (cffPattern.test(code)) {
            evidence.push('Control flow flattening (state-based) detected');
            confidence += 0.35;
        }

        // Multiple state assignments dalam loop
        const stateAssignPattern = /while\s+true\s+do[\s\S]*?[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*(0x[0-9a-fA-F]+|\d+)[\s\S]*?[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*(0x[0-9a-fA-F]+|\d+)/g;
        const stateMatches = code.match(stateAssignPattern);
        if (stateMatches && stateMatches.length >= 3) {
            evidence.push(`State transitions: ${stateMatches.length}`);
            confidence += 0.20;
        }

        // VM-lite dispatch (wYnFuscate v2+)
        const vmLitePattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\{[\s\S]*?\[\d+\]\s*=\s*function/g;
        const vmLiteMatches = code.match(vmLitePattern);
        if (vmLiteMatches && vmLiteMatches.length >= 3 && vmLiteMatches.length < 10) {
            evidence.push(`VM-lite dispatch: ${vmLiteMatches.length} opcodes`);
            confidence += 0.20;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 5: Loadstring Pattern ---
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

        // loadstring + decrypt
        const loadDecryptPattern = /loadstring\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)\s*\)/g;
        if (loadDecryptPattern.test(code)) {
            evidence.push('loadstring(decrypt(...)) pattern');
            confidence += 0.30;
        }

        return { confidence: Math.min(confidence, 1.0), evidence };
    }

    // --- Layer 6: Heuristic Analysis ---
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
        const cff = results.find(r => r.layer === 'ControlFlowPattern');
        const loadstring = results.find(r => r.layer === 'LoadstringPattern');

        // Cek VM-lite (v2+)
        if (cff && cff.evidence.some(e => /VM-lite/i.test(e))) {
            return 'v2-vm-lite';
        }
        if (cff && cff.confidence > 0.3 && loadstring && loadstring.confidence > 0.3) {
            return 'v2-cff-loadstring';
        }
        if (cff && cff.confidence > 0.3) {
            return 'v2-cff';
        }
        if (loadstring && loadstring.confidence > 0.3) {
            return 'v1-loadstring';
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

export class WYnFuscateDeobfuscator {
    constructor() {
        this.levels = [
            { name: 'BasicCleanup', run: this.level1BasicCleanup.bind(this) },
            { name: 'StringDecryption', run: this.level2StringDecryption.bind(this) },
            { name: 'ConstantDecryption', run: this.level3ConstantDecryption.bind(this) },
            { name: 'VariableRenaming', run: this.level4VariableRenaming.bind(this) },
            { name: 'ControlFlowUnflattening', run: this.level5CFFUnflattening.bind(this) },
            { name: 'LoadstringResolution', run: this.level6LoadstringResolution.bind(this) },
            { name: 'VMLiteMetadata', run: this.level7VMLiteMetadata.bind(this) },
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
        if (v === 'v2-vm-lite' || v === 'v2-cff-loadstring') {
            return [
                this.levels[1], // String
                this.levels[4], // CFF
                this.levels[5], // Loadstring
                this.levels[6], // VM-lite
                this.levels[0], // Cleanup
                this.levels[2], // Constant
                this.levels[3], // Rename
            ];
        }
        if (v === 'v2-cff') {
            return [
                this.levels[1], // String
                this.levels[4], // CFF
                this.levels[0], // Cleanup
                this.levels[2], // Constant
                this.levels[3], // Rename
                this.levels[5], // Loadstring
                this.levels[6], // VM-lite
            ];
        }
        if (v === 'v1-loadstring' || v === 'v1-legacy') {
            return [
                this.levels[1], // String
                this.levels[5], // Loadstring
                this.levels[0], // Cleanup
                this.levels[2], // Constant
                this.levels[3], // Rename
                this.levels[4], // CFF
                this.levels[6], // VM-lite
            ];
        }
        return this.levels;
    }

    // --- LEVEL 1: Basic Cleanup ---
    level1BasicCleanup(code) {
        let result = code;
        let changes = 0;

        // Hapus watermark wYnFuscate
        const before = result;
        result = result.replace(/--\s*\[\[\s*wYn[\s\S]*?\]\]/gi, '');
        result = result.replace(/--\s*Protected by wYn.*/gi, '');
        result = result.replace(/--\s*wYnFuscate\s+Obfuscator.*/gi, '');
        result = result.replace(/--\s*Obfuscated with wYnFuscate.*/gi, '');
        result = result.replace(/--\s*wYn\s+Protection.*/gi, '');
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

    // --- LEVEL 2: String Decryption (KHAS WYnFUSCATE — XOR + SHIFT) ---
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

        // Pattern 2: XOR + shift combo — string.char(bit32.bxor(N, K) + offset)
        result = result.replace(/string\.char\s*\(\s*bit32\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)\s*([+\-])\s*(\d+)\s*\)/g, (match, a, k, op, offset) => {
            const xorResult = parseInt(a, 10) ^ parseInt(k, 10);
            const final = op === '+' ? xorResult + parseInt(offset, 10) : xorResult - parseInt(offset, 10);
            if (final >= 0 && final <= 255) {
                changes++;
                return JSON.stringify(String.fromCharCode(final));
            }
            return match;
        });

        // Pattern 3: Multi-layer XOR
        result = result.replace(/string\.char\(\s*bit32\.bxor\s*\(\s*bit32\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)\s*,\s*(\d+)\s*\)\s*\)/g, (match, a, k1, k2) => {
            const first = parseInt(a, 10) ^ parseInt(k1, 10);
            const final = first ^ parseInt(k2, 10);
            if (final >= 0 && final <= 255) {
                changes++;
                return JSON.stringify(String.fromCharCode(final));
            }
            return match;
        });

        // Pattern 4: XOR dengan key recovery
        const keyPatterns = [
            /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(\d+)\s*(?:--\s*key)?/i,
            /local\s+((?:wyn|wf|wYn|wynf|WYN|WF)[a-zA-Z0-9_]*)\s*=\s*(\d+)/,
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

        // Pattern 5: String table lookup
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
        result = result.replace(/bit32\.lshift\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, a, b) => {
            changes++;
            return String(parseInt(a, 10) << parseInt(b, 10));
        });
        result = result.replace(/bit32\.rshift\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, a, b) => {
            changes++;
            return String(parseInt(a, 10) >>> parseInt(b, 10));
        });

        // Fold nested
        let prevResult = '';
        let iterations = 0;
        while (prevResult !== result && iterations < 5) {
            prevResult = result;
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
            iterations++;
        }

        return { code: result, changed: result !== code, changes, notes: changes > 0 ? `Folded ${changes} constants` : null };
    }

    // --- LEVEL 4: Variable Renaming ---
    level4VariableRenaming(code) {
        let result = code;
        let changes = 0;

        // Collect wYnFuscate-style variables
        const wynVars = new Set();
        const varPatterns = [
            /\b((?:wyn|wf|wYn|wynf|WYN|WF)[a-zA-Z0-9_]*)\b/g,
            /\b(_0x[0-9a-fA-F]+)\b/g,
        ];

        for (const pattern of varPatterns) {
            let m;
            while ((m = pattern.exec(code)) !== null) {
                if (m[1].length >= 3 && !this.isLuaKeyword(m[1])) {
                    wynVars.add(m[1]);
                }
            }
        }

        if (wynVars.size === 0) return { code: result, changed: false, changes: 0 };

        const renameMap = {};
        let counter = 1;
        for (const v of wynVars) {
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

    // --- LEVEL 5: Control Flow Unflattening ---
    level5CFFUnflattening(code) {
        let result = code;
        let changes = 0;

        const cffPattern = /local\s+(v\d+|[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+|\d+)([\s\S]*?while\s+true\s+do[\s\S]*?end)/;
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

    // --- LEVEL 6: Loadstring Resolution ---
    level6LoadstringResolution(code) {
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

    // --- LEVEL 7: VM-Lite Metadata Extraction ---
    level7VMLiteMetadata(code) {
        let result = code;
        let changes = 0;
        const notes = [];

        // VM-lite dispatch table (lebih kecil dari VM penuh)
        const dispatchPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\{([\s\S]*?)\}/;
        const dispatchMatch = result.match(dispatchPattern);

        if (dispatchMatch) {
            const tableName = dispatchMatch[1];
            const tableBody = dispatchMatch[2];
            const funcEntries = (tableBody.match(/function/g) || []).length;

            // VM-lite biasanya 3-15 opcodes (VM penuh >15)
            if (funcEntries >= 3 && funcEntries < 20) {
                notes.push(`VM-lite dispatch: ${tableName} (${funcEntries} opcodes)`);

                const bytecodePattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\{\s*([\d\s,]+)\s*\}/;
                const bytecodeMatch = result.match(bytecodePattern);

                if (bytecodeMatch) {
                    const bytecodeName = bytecodeMatch[1];
                    const bytecode = bytecodeMatch[2].split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
                    notes.push(`Bytecode: ${bytecodeName} (${bytecode.length} ops)`);

                    const vmLoopPattern = /while\s+true\s+do[\s\S]*?break[\s\S]*?end/;
                    if (vmLoopPattern.test(result)) {
                        result = result.replace(vmLoopPattern,
                            `-- [[ VM-LITE LOOP EXTRACTED BY KAIRO ]]\n-- Bytecode: [${bytecode.slice(0, 30).join(', ')}${bytecode.length > 30 ? ', ...' : ''}]\n-- Opcodes: ${funcEntries}\n-- VM-lite emulation required for full deobfuscation`);
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
        const hasWynVars = /(?:wyn|wf|wYn|wynf|WYN|WF)[a-zA-Z0-9_]*/i.test(code);
        const hasHexVars = /_0x[0-9a-fA-F]{4,}/.test(code);
        const entropy = this.calculateEntropy(code);
        const hasDispatcher = /while\s+true\s+do[\s\S]{200,}if.*==.*then/.test(code);
        return !hasWynVars && !hasHexVars && entropy < 4.0 && !hasDispatcher;
    }
}


// ============================================================
// SECTION 3: ORCHESTRATOR
// ============================================================

export function processWYnFuscate(code) {
    const detector = new WYnFuscateDetector();
    const detection = detector.detect(code);

    if (!detection.isWYnFuscate) {
        return {
            success: false,
            detection,
            deobfuscation: null,
            message: 'Input tidak terdeteksi sebagai wYnFuscate obfuscator',
        };
    }

    const deobfuscator = new WYnFuscateDeobfuscator();
    const deobfuscation = deobfuscator.deobfuscate(code, detection);

    return {
        success: deobfuscation.success,
        detection,
        deobfuscation,
        message: deobfuscation.success
            ? `Deobfuscation selesai. Version: ${detection.version}. Applied: ${deobfuscation.appliedLevels.map(l => l.level).join(', ')}`
            : 'Detect sebagai wYnFuscate tapi deobfuscation tidak menghasilkan perubahan signifikan',
    };
}
