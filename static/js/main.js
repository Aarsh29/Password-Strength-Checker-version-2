/**
 * SHIELD PASSWORD SECURITY AUDITOR - REAL-TIME FRONTEND ENGINE [v3.1.0]
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Element Declarations
    const passwordInput = document.getElementById('passwordInput');
    const toggleVisibility = document.getElementById('toggleVisibility');
    const generateBtn = document.getElementById('generateBtn');
    const copyBtn = document.getElementById('copyBtn');
    const saveBtn = document.getElementById('saveBtn');
    
    const strengthLabel = document.getElementById('strengthLabel');
    const scorePercentage = document.getElementById('scorePercentage');
    const strengthProgress = document.getElementById('strengthProgress');
    const hashDisplayValue = document.getElementById('hashDisplayValue');
    
    const overallRatingBadge = document.getElementById('overallRatingBadge');
    const entropyValue = document.getElementById('entropyValue');
    const entropyDesc = document.getElementById('entropyDesc');
    
    const breachStatus = document.getElementById('breachStatus');
    const reuseStatus = document.getElementById('reuseStatus');
    
    // Pattern Weakness Container
    const patternWeaknessBlock = document.getElementById('patternWeaknessBlock');
    const patternWeaknessList = document.getElementById('patternWeaknessList');
    
    // Checklist Items
    const chkLength = document.getElementById('chkLength');
    const chkLower = document.getElementById('chkLower');
    const chkUpper = document.getElementById('chkUpper');
    const chkDigit = document.getElementById('chkDigit');
    const chkSpecial = document.getElementById('chkSpecial');
    const chkSeq = document.getElementById('chkSeq');
    const chkRep = document.getElementById('chkRep');
    
    // 4-Tier Crack Estimations
    const crackOnlineThrottled = document.getElementById('crackOnlineThrottled');
    const crackOnlineUnthrottled = document.getElementById('crackOnlineUnthrottled');
    const crackOfflineCPU = document.getElementById('crackOfflineCPU');
    const crackOfflineGPU = document.getElementById('crackOfflineGPU');
    
    // Suggestions
    const suggestionsList = document.getElementById('suggestionsList');
    const alternativeBox = document.getElementById('alternativeBox');
    const alternativeValue = document.getElementById('alternativeValue');
    const useAlternativeBtn = document.getElementById('useAlternativeBtn');
    
    // Toast Notification
    const toast = document.getElementById('toast');
    const toastMsg = document.getElementById('toastMsg');
    
    let debounceTimer = null;
    
    // Cached states for network-dependent checks
    let isPreviouslyUsedServerResponse = false;
    let isBreachedServerResponse = false;
    let cachedHibpCount = 0;

    // Cache dictionary for client-side Have I Been Pwned range API calls
    const HIBP_CLIENT_CACHE = {};

    // Standard list of common passwords for local leetspeak and dictionary normalization
    const LOCAL_COMMON_PASSWORDS = [
        "123456", "password", "123456789", "qwerty", "12345678", "12345", "1234567",
        "1234567890", "1234", "password123", "admin", "letmein", "iloveyou", "football",
        "welcome", "123123", "computer", "111111", "monkey", "secret", "login", "hunter2",
        "qwertyuiop", "dragon", "superman", "mustang", "shadow", "master", "rookie",
        "killer", "password1", "michael", "jessica", "daniel", "andrew", "matthew",
        "chelsea", "drowssap", "pass123", "admin123", "root", "testing", "hello",
        "soccer", "baseball", "basketball", "starwars", "superstar", "ninja", "wizard",
        "hacker", "anonymous", "matrix", "cyber", "security", "hackme"
    ];

    const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"];

    // --- EVENT LISTENERS ---

    // 1. Real-Time Password Typing
    passwordInput.addEventListener('input', () => {
        const password = passwordInput.value;
        
        if (password) {
            // Run full audit immediately client-side for absolute real-time feedback
            runInstantLocalAudit(password);
            
            // Set asynchronous network checks to "scanning..." state
            breachStatus.textContent = 'SCANNING...';
            breachStatus.className = 'status-warning flash-text';
            reuseStatus.textContent = 'SCANNING...';
            reuseStatus.className = 'status-warning flash-text';
            
            // Debounce the direct client-side HIBP and backend reuse check
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                runAsyncNetworkAudit(password);
            }, 500); // 500ms debounce to limit requests
        } else {
            resetAuditReport();
        }
    });

    // 2. Toggle Password Masking Visibility
    toggleVisibility.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        
        const icon = toggleVisibility.querySelector('i');
        icon.className = isPassword ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
    });

    // 3. Generate Strong Password
    generateBtn.addEventListener('click', async () => {
        try {
            generateBtn.disabled = true;
            const res = await fetch('/generate?length=16');
            if (!res.ok) throw new Error('Generation failed');
            
            const data = await res.json();
            passwordInput.value = data.password;
            
            // Run instant local audit
            runInstantLocalAudit(data.password);
            
            // Trigger asynchronous database checks
            runAsyncNetworkAudit(data.password);
            
            showToast('Secure password generated!');
        } catch (err) {
            console.error(err);
            showToast('Failed to generate password.', true);
        } finally {
            generateBtn.disabled = false;
        }
    });

    // 4. Copy Password
    copyBtn.addEventListener('click', () => {
        const password = passwordInput.value;
        if (!password) return;
        
        navigator.clipboard.writeText(password)
            .then(() => showToast('Password copied to clipboard!'))
            .catch(err => {
                console.error(err);
                showToast('Failed to copy to clipboard.', true);
            });
    });

    // 5. Save History (Commit Hash)
    saveBtn.addEventListener('click', async () => {
        const password = passwordInput.value;
        if (!password) return;
        
        try {
            saveBtn.disabled = true;
            const res = await fetch('/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            
            if (!res.ok) throw new Error('Database registry failed');
            const data = await res.json();
            
            if (data.success) {
                showToast(data.message);
                isPreviouslyUsedServerResponse = true;
                // Re-audit locally to immediately deduct points for reuse
                runInstantLocalAudit(password);
                reuseStatus.textContent = 'REUSED';
                reuseStatus.className = 'status-breached';
            } else {
                showToast(data.message, true);
            }
        } catch (err) {
            console.error(err);
            showToast('Failed to commit hash.', true);
        } finally {
            saveBtn.disabled = false;
        }
    });

    // 6. Apply suggested strong alternative
    useAlternativeBtn.addEventListener('click', () => {
        const altPassword = alternativeValue.textContent;
        if (!altPassword) return;
        
        passwordInput.value = altPassword;
        runInstantLocalAudit(altPassword);
        runAsyncNetworkAudit(altPassword);
        showToast('Applied recommended strong alternative!');
    });

    // --- INSTANT CLIENT-SIDE AUDITING ENGINE ---

    /**
     * Evaluates all scoring rules, patterns, complexity checklists, and crack-times
     * client-side with 0ms latency.
     */
    function runInstantLocalAudit(password) {
        if (!password) {
            resetAuditReport();
            return;
        }
        
        // Enable basic buttons
        copyBtn.disabled = false;
        saveBtn.disabled = false;
        
        const len = password.length;
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasDigit = /[0-9]/.test(password);
        const hasSpecial = /[^A-Za-z0-9]/.test(password);
        
        // Compute dynamic patterns locally
        const seqPatterns = localCheckSequential(password);
        const repPatterns = localCheckRepeated(password);
        const hasLeet = localCheckLeet(password);
        const hasYear = /(19|20)\d{2}/.test(password);
        const detectedWords = LOCAL_COMMON_PASSWORDS.filter(w => w.length >= 4 && password.toLowerCase().includes(w));
        
        // Update local checklists
        toggleChecklistItem(chkLength, len >= 12);
        toggleChecklistItem(chkLower, hasLower);
        toggleChecklistItem(chkUpper, hasUpper);
        toggleChecklistItem(chkDigit, hasDigit);
        toggleChecklistItem(chkSpecial, hasSpecial);
        toggleChecklistItem(chkSeq, seqPatterns.length === 0);
        toggleChecklistItem(chkRep, repPatterns.length === 0);
        
        // Compute adjusted human entropy locally
        const { entropy, deductions } = localCalculateEntropy(password, seqPatterns, repPatterns, hasLeet, hasYear, detectedWords);
        
        entropyValue.innerHTML = `${entropy} <span class="bits">bits</span>`;
        if (deductions.length > 0) {
            entropyDesc.textContent = `Adjusted for human habits. Penalties: ${deductions.join(', ')}`;
        } else {
            entropyDesc.textContent = "Cryptographically secure mathematical search space.";
        }
        
        // Estimate crack times locally
        const crackTimes = localEstimateCrackTime(entropy);
        crackOnlineThrottled.textContent = crackTimes.online_throttled;
        crackOnlineUnthrottled.textContent = crackTimes.online_unthrottled;
        crackOfflineCPU.textContent = crackTimes.offline_cpu;
        crackOfflineGPU.textContent = crackTimes.offline_gpu;
        
        setCrackTimeStyling(crackOnlineThrottled, crackTimes.online_throttled);
        setCrackTimeStyling(crackOnlineUnthrottled, crackTimes.online_unthrottled);
        setCrackTimeStyling(crackOfflineCPU, crackTimes.offline_cpu);
        setCrackTimeStyling(crackOfflineGPU, crackTimes.offline_gpu);
        
        // Display local pattern weaknesses instantly
        const patternWeaknesses = [];
        if (detectedWords.length > 0) patternWeaknesses.push(`Contains common word/name: '${detectedWords[0]}'`);
        if (seqPatterns.length > 0) patternWeaknesses.push(`Contains sequence/keyboard walk: '${seqPatterns[0]}'`);
        if (repPatterns.length > 0) patternWeaknesses.push(`Contains repeated characters: '${repPatterns[0]}'`);
        if (hasYear) {
            const match = password.match(/(19|20)\d{2}/);
            patternWeaknesses.push(`Contains year pattern: '${match[0]}'`);
        }
        if (hasLeet) patternWeaknesses.push("Uses common character substitutions (l33tspeak)");
        
        if (patternWeaknesses.length > 0) {
            patternWeaknessBlock.style.display = 'block';
            patternWeaknessList.innerHTML = '';
            patternWeaknesses.forEach(w => {
                const span = document.createElement('span');
                span.className = 'pattern-badge';
                span.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${w}`;
                patternWeaknessList.appendChild(span);
            });
        } else {
            patternWeaknessBlock.style.display = 'none';
        }
        
        // Compute weighted scoring instantly
        let score = 0;
        
        // Length score
        if (len > 12) score += 25;
        else if (len >= 8) score += 15;
        else score += 5;
        
        // Complexity scores
        if (hasUpper) score += 15;
        if (hasLower) score += 15;
        if (hasDigit) score += 15;
        if (hasSpecial) score += 20;
        
        // Entropy score
        const entropyContrib = Math.min(20, (entropy / 60) * 20);
        score += entropyContrib;
        
        // Local Penalties
        const isCommonWord = LOCAL_COMMON_PASSWORDS.includes(password.toLowerCase()) || isBreachedServerResponse;
        if (isCommonWord) score -= 40;
        if (seqPatterns.length > 0) score -= 20;
        if (repPatterns.length > 0) score -= 20;
        
        // Subtraction for server-side history reuse
        if (isPreviouslyUsedServerResponse) score -= 30;
        
        score = Math.max(0, Math.min(100, Math.round(score)));
        
        // Update visual progress bars and badges
        scorePercentage.textContent = `${score}%`;
        strengthProgress.style.width = `${score}%`;
        
        strengthProgress.className = 'progress-bar';
        strengthLabel.className = 'strength-lbl';
        overallRatingBadge.className = 'rating-badge';
        
        let rating = "Weak";
        if (len < 8 || isCommonWord) rating = "Weak";
        else if (score < 45) rating = "Weak";
        else if (score < 70) rating = "Medium";
        else if (score < 85) rating = "Strong";
        else rating = "Very Strong";
        
        const ratingClassMap = {
            'Weak': { text: 'text-weak', bar: 'bar-weak', badge: 'badge-weak' },
            'Medium': { text: 'text-medium', bar: 'bar-medium', badge: 'badge-medium' },
            'Strong': { text: 'text-strong', bar: 'bar-strong', badge: 'badge-strong' },
            'Very Strong': { text: 'text-very-strong', bar: 'bar-very-strong', badge: 'badge-very-strong' }
        };
        
        const styling = ratingClassMap[rating] || ratingClassMap['Weak'];
        strengthLabel.textContent = rating.toUpperCase();
        strengthLabel.classList.add(styling.text);
        strengthProgress.classList.add(styling.bar);
        
        overallRatingBadge.textContent = rating.toUpperCase();
        overallRatingBadge.classList.add(styling.badge);
        
        // Live client-side visual hash digest generator
        hashDisplayValue.textContent = localSha256(password);
        
        // Recommendations list
        suggestionsList.innerHTML = '';
        const suggestions = [];
        if (len < 12) suggestions.push("Increase length to at least 12 characters (16+ is ideal).");
        if (!hasUpper) suggestions.push("Add uppercase letters (A-Z).");
        if (!hasLower) suggestions.push("Add lowercase letters (a-z).");
        if (!hasDigit) suggestions.push("Add numbers (0-9).");
        if (!hasSpecial) suggestions.push("Add special characters or punctuation.");
        if (seqPatterns.length > 0) suggestions.push("Avoid sequential letters, numbers, or keyboard rows.");
        if (repPatterns.length > 0) suggestions.push("Avoid repeating characters sequentially.");
        if (isCommonWord && !isBreachedServerResponse) suggestions.push("CRITICAL: This is a highly common dictionary password. Choose another password.");
        if (isBreachedServerResponse) suggestions.push(`CRITICAL: Found in Have I Been Pwned breach database (${cachedHibpCount} times). Choose another password!`);
        if (isPreviouslyUsedServerResponse) suggestions.push("WARNING: This password hash was committed to your history. Avoid reusing it.");
        if (hasLeet) suggestions.push("Avoid obvious l33tspeak substitutions (e.g. '@' for 'a', '0' for 'o').");
        
        if (suggestions.length === 0) {
            suggestions.push("Excellent password! It meets all dynamic security audit guidelines.");
        }
        
        suggestions.forEach(s => {
            const p = document.createElement('p');
            p.textContent = s;
            if (s.includes('CRITICAL') || s.includes('WARNING')) {
                p.style.color = 'var(--neon-red)';
            }
            suggestionsList.appendChild(p);
        });
        
        // Generate alternative
        if (rating !== 'Very Strong') {
            alternativeValue.textContent = localGenerateAlternative(password);
            alternativeBox.style.display = 'block';
        } else {
            alternativeBox.style.display = 'none';
        }
    }

    /**
     * Performs Have I Been Pwned range check directly from the client's browser (CORS enabled)
     * and SQLite database reuse checks asynchronously.
     */
    async function runAsyncNetworkAudit(password) {
        try {
            // 1. Direct client-side HIBP range API check (highly accurate and fast)
            const hibpPromise = checkHibpClientSide(password);
            
            // 2. Local SQLite database check via Flask endpoint
            const dbPromise = fetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            }).then(res => {
                if (!res.ok) throw new Error();
                return res.json();
            });
            
            const [hibpCount, dbData] = await Promise.all([hibpPromise, dbPromise]);
            
            // Check if password has changed since we started the async check (prevents race conditions)
            if (passwordInput.value !== password) {
                return; 
            }
            
            // Update HIBP status
            if (hibpCount > 0) {
                breachStatus.textContent = `BREACHED (${hibpCount}x)`;
                breachStatus.className = 'status-breached';
                isBreachedServerResponse = true;
                cachedHibpCount = hibpCount;
            } else {
                breachStatus.textContent = 'CLEAN';
                breachStatus.className = 'status-clean';
                isBreachedServerResponse = false;
                cachedHibpCount = 0;
            }
            
            // Update History Reuse status
            isPreviouslyUsedServerResponse = dbData.is_previously_used;
            if (dbData.is_previously_used) {
                reuseStatus.textContent = 'REUSED';
                reuseStatus.className = 'status-breached';
            } else {
                reuseStatus.textContent = 'NOT USED';
                reuseStatus.className = 'status-clean';
            }
            
            // Re-run local audit once to reflect the breach status in scoring & recommendations
            runInstantLocalAudit(password);
            
        } catch (err) {
            console.error("Network audit error:", err);
            if (passwordInput.value === password) {
                breachStatus.textContent = 'ERROR (API)';
                breachStatus.className = 'status-warning';
                reuseStatus.textContent = 'ERROR (DB)';
                reuseStatus.className = 'status-warning';
            }
        }
    }

    /**
     * Direct Client-Side Have I Been Pwned Range Check using k-Anonymity.
     * Hashes password with SHA-1 locally, queries HIBP with the first 5 characters,
     * and filters the returned suffix lines inside the browser.
     */
    async function checkHibpClientSide(password) {
        if (password.length < 6) return 0;
        
        // Compute SHA-1 hash locally
        const msgUint8 = new TextEncoder().encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', msgUint8);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const sha1 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        
        const prefix = sha1.slice(0, 5);
        const suffix = sha1.slice(5);
        
        // Check memory cache
        if (HIBP_CLIENT_CACHE[prefix]) {
            return HIBP_CLIENT_CACHE[prefix][suffix] || 0;
        }
        
        // Query range API
        const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        if (!res.ok) throw new Error('HIBP server error');
        const text = await res.text();
        
        const lines = text.split('\n');
        const suffixes = {};
        for (const line of lines) {
            const parts = line.split(':');
            if (parts.length === 2) {
                suffixes[parts[0].trim().toUpperCase()] = parseInt(parts[1].trim(), 10);
            }
        }
        
        // Cache and return
        HIBP_CLIENT_CACHE[prefix] = suffixes;
        return suffixes[suffix] || 0;
    }

    // --- CLIENT-SIDE CRYPTOGRAPHIC & MATHEMATICAL HELPERS ---

    function localCalculateEntropy(password, seqs, reps, leet, year, words) {
        let pool = 0;
        if (/[a-z]/.test(password)) pool += 26;
        if (/[A-Z]/.test(password)) pool += 26;
        if (/[0-9]/.test(password)) pool += 10;
        if (/[^a-zA-Z0-9]/.test(password)) pool += 32;
        
        if (pool === 0) pool = 1;
        let entropy = password.length * Math.log2(pool);
        const deductions = [];
        
        if (words.length > 0) {
            entropy -= 15;
            deductions.push("dictionary word (-15 bits)");
        }
        if (reps.length > 0 || /(.{2,6})\1+/.test(password)) {
            entropy -= 10;
            deductions.push("repeated patterns (-10 bits)");
        }
        if (seqs.length > 0) {
            entropy -= 10;
            deductions.push("keyboard walk (-10 bits)");
        }
        if (year) {
            entropy -= 15;
            deductions.push("year pattern (-15 bits)");
        }
        
        return {
            entropy: Math.max(0.0, Math.round(entropy * 100) / 100),
            deductions: deductions
        };
    }

    function localEstimateCrackTime(entropy) {
        const guesses = 0.5 * Math.pow(2, entropy);
        
        function format(seconds) {
            if (seconds < 0.001) return "Instant";
            if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
            if (seconds < 60) return `${Math.round(seconds * 10) / 10} sec`;
            if (seconds < 3600) return `${Math.round((seconds / 60) * 10) / 10} min`;
            if (seconds < 86400) return `${Math.round((seconds / 3600) * 10) / 10} hours`;
            if (seconds < 31536000) return `${Math.round((seconds / 86400) * 10) / 10} days`;
            if (seconds < 3153600000) return `${Math.round((seconds / 31536000) * 10) / 10} years`;
            
            const years = seconds / 31536000;
            if (years < 1000000) return `${Math.round((years / 100) * 10) / 10} centuries`;
            if (years < 1000000000) return `${Math.round((years / 1000000) * 10) / 10}M years`;
            return `${Math.round((years / 1000000000) * 10) / 10}B years`;
        }
        
        return {
            online_throttled: format(guesses / 10),
            online_unthrottled: format(guesses / 1000),
            offline_cpu: format(guesses / 10000000),
            offline_gpu: format(guesses / 10000000000)
        };
    }

    function localCheckSequential(password) {
        const detected = [];
        const pwd = password.toLowerCase();
        
        for (let i = 0; i < pwd.length - 2; i++) {
            const chunk = pwd.slice(i, i+3);
            const c1 = chunk.charCodeAt(0);
            const c2 = chunk.charCodeAt(1);
            const c3 = chunk.charCodeAt(2);
            
            // Digits (48-57)
            if (c1 >= 48 && c1 <= 57 && c2 >= 48 && c2 <= 57 && c3 >= 48 && c3 <= 57) {
                if (c2 - c1 === 1 && c3 - c2 === 1) detected.push(chunk);
                else if (c2 - c1 === -1 && c3 - c2 === -1) detected.push(chunk);
            }
            // Letters (97-122)
            else if (c1 >= 97 && c1 <= 122 && c2 >= 97 && c2 <= 122 && c3 >= 97 && c3 <= 122) {
                if (c2 - c1 === 1 && c3 - c2 === 1) detected.push(chunk);
                else if (c2 - c1 === -1 && c3 - c2 === -1) detected.push(chunk);
            }
        }
        
        // Keyboard rows walk
        for (const row of KEYBOARD_ROWS) {
            for (let i = 0; i < pwd.length - 2; i++) {
                const chunk = pwd.slice(i, i+3);
                if (row.includes(chunk) || row.includes(chunk.split('').reverse().join(''))) {
                    detected.push(chunk);
                }
            }
        }
        
        return [...new Set(detected)];
    }

    function localCheckRepeated(password) {
        const detected = [];
        let i = 0;
        while (i < password.length - 2) {
            const char = password[i];
            let count = 1;
            while (i + count < password.length && password[i + count] === char) {
                count++;
            }
            if (count >= 3) {
                detected.push(char.repeat(count));
                i += count;
            } else {
                i++;
            }
        }
        return detected;
    }

    function localCheckLeet(password) {
        const pwd = password.toLowerCase();
        const leetMap = {
            '@': 'a', '4': 'a',
            '$': 's', '5': 's',
            '0': 'o',
            '3': 'e',
            '1': 'i', '!': 'i', '7': 't'
        };
        
        let hasLeetSymbol = false;
        const normalized = [];
        for (let j = 0; j < pwd.length; j++) {
            const char = pwd[j];
            if (leetMap[char]) {
                normalized.push(leetMap[char]);
                hasLeetSymbol = true;
            } else {
                normalized.push(char);
            }
        }
        
        if (!hasLeetSymbol) return false;
        
        const normStr = normalized.join('');
        return LOCAL_COMMON_PASSWORDS.some(word => word.length >= 4 && (normStr.includes(word) || word.includes(normStr)));
    }

    function localGenerateAlternative(password) {
        const leetMap = {
            'a': '@', 'A': '4',
            's': '$', 'S': '5',
            'o': '0', 'O': '0',
            'e': '3', 'i': '!', 't': '7'
        };
        let alt = password.split('').map(c => leetMap[c] && Math.random() < 0.8 ? leetMap[c] : c).join('');
        if (!/[0-9]/.test(alt)) alt += Math.floor(Math.random() * 10);
        if (!/[^a-zA-Z0-9]/.test(alt)) alt += '!';
        if (alt.length < 16) {
            const needed = 16 - alt.length;
            const pool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
            for (let k = 0; k < needed; k++) {
                alt += pool.charAt(Math.floor(Math.random() * pool.length));
            }
        }
        return alt;
    }

    /**
     * Visual SHA-256 generator in pure JS to show immediate results.
     */
    function localSha256(ascii) {
        const msgUint8 = new TextEncoder().encode(ascii);
        crypto.subtle.digest('SHA-256', msgUint8).then(hashBuffer => {
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            if (passwordInput.value === ascii) {
                hashDisplayValue.textContent = hashHex;
            }
        });
        return "Hashing...";
    }

    /**
     * Resets the entire report to empty state.
     */
    function resetAuditReport() {
        copyBtn.disabled = true;
        saveBtn.disabled = true;
        isPreviouslyUsedServerResponse = false;
        isBreachedServerResponse = false;
        cachedHibpCount = 0;
        
        strengthLabel.textContent = 'WEAK';
        strengthLabel.className = 'strength-lbl text-weak';
        
        scorePercentage.textContent = '0%';
        strengthProgress.style.width = '0%';
        strengthProgress.className = 'progress-bar bar-weak';
        
        hashDisplayValue.textContent = '----------------------------------------------------------------';
        
        overallRatingBadge.textContent = 'WEAK';
        overallRatingBadge.className = 'rating-badge badge-weak';
        
        entropyValue.innerHTML = `0.0 <span class="bits">bits</span>`;
        entropyDesc.textContent = 'No password analyzed yet.';
        
        breachStatus.textContent = 'CLEAN';
        breachStatus.className = 'status-clean';
        
        reuseStatus.textContent = 'NOT USED';
        reuseStatus.className = 'status-clean';
        
        patternWeaknessBlock.style.display = 'none';
        patternWeaknessList.innerHTML = '';
        
        // Reset checklist items to default failed state
        const items = [chkLength, chkLower, chkUpper, chkDigit, chkSpecial];
        items.forEach(el => {
            el.className = 'chk-fail';
            el.innerHTML = '<i class="fa-solid fa-xmark"></i> ' + el.textContent.substring(2);
        });
        
        chkSeq.className = 'chk-pass';
        chkSeq.innerHTML = '<i class="fa-solid fa-check"></i> Free of Sequential Patterns';
        chkRep.className = 'chk-pass';
        chkRep.innerHTML = '<i class="fa-solid fa-check"></i> Free of Repeated Characters';
        
        const crackCells = [crackOnlineThrottled, crackOnlineUnthrottled, crackOfflineCPU, crackOfflineGPU];
        crackCells.forEach(cell => {
            cell.textContent = 'Instant';
            cell.className = 'font-orbitron text-weak';
        });
        
        suggestionsList.innerHTML = '<p class="no-suggestions">Enter a password to generate security remediation steps.</p>';
        alternativeBox.style.display = 'none';
    }

    function toggleChecklistItem(element, passed) {
        const labels = {
            'chkLength': 'Minimum Length (12+ recommended)',
            'chkLower': 'Lowercase Letters (a-z)',
            'chkUpper': 'Uppercase Letters (A-Z)',
            'chkDigit': 'Numbers (0-9)',
            'chkSpecial': 'Special Characters (@, #, $, etc.)',
            'chkSeq': 'Free of Sequential Patterns',
            'chkRep': 'Free of Repeated Characters'
        };
        const labelText = labels[element.id];
        if (passed) {
            element.className = 'chk-pass';
            element.innerHTML = `<i class="fa-solid fa-check"></i> ${labelText}`;
        } else {
            element.className = 'chk-fail';
            element.innerHTML = `<i class="fa-solid fa-xmark"></i> ${labelText}`;
        }
    }

    function setCrackTimeStyling(element, timeText) {
        element.className = 'font-orbitron';
        const lower = timeText.toLowerCase();
        
        if (lower.includes('instant') || lower.includes('ms') || lower.includes('sec') || lower.includes('min')) {
            element.classList.add('text-weak');
        } else if (lower.includes('hour') || lower.includes('day') || lower.includes('month')) {
            element.classList.add('text-medium');
        } else if (lower.includes('year') && !lower.includes('m') && !lower.includes('b')) {
            element.classList.add('text-strong');
        } else {
            element.classList.add('text-very-strong');
        }
    }

    function showToast(message, isError = false) {
        toastMsg.textContent = message;
        const icon = toast.querySelector('.toast-icon');
        if (isError) {
            toast.style.borderColor = 'var(--neon-red)';
            toast.style.boxShadow = '0 5px 25px rgba(0, 0, 0, 0.5), 0 0 15px var(--neon-red-glow)';
            icon.className = 'fa-solid fa-circle-exclamation text-weak';
        } else {
            toast.style.borderColor = 'var(--neon-blue)';
            toast.style.boxShadow = '0 5px 25px rgba(0, 0, 0, 0.5), 0 0 15px var(--neon-blue-glow)';
            icon.className = 'fa-solid fa-circle-check neon-blue-text';
        }
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    }
});
