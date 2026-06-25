(() => {
  const passwordInput = document.getElementById('passwordInput');
  const toggleVisibilityButton = document.getElementById('toggleVisibility');
  const scoreValue = document.getElementById('scoreValue');
  const strengthLabel = document.getElementById('strengthLabel');
  const analysisSummary = document.getElementById('analysisSummary');
  const strengthFill = document.getElementById('strengthFill');
  const entropyFill = document.getElementById('entropyFill');
  const strengthPercent = document.getElementById('strengthPercent');
  const entropyText = document.getElementById('entropyText');
  const statLength = document.getElementById('statLength');
  const statEntropy = document.getElementById('statEntropy');
  const statPool = document.getElementById('statPool');
  const statUniqueRatio = document.getElementById('statUniqueRatio');
  const statCombinations = document.getElementById('statCombinations');
  const statClasses = document.getElementById('statClasses');
  const liveChecklist = document.getElementById('liveChecklist');
  const crackTimes = document.getElementById('crackTimes');
  const securityTips = document.getElementById('securityTips');
  const detectionList = document.getElementById('detectionList');
  const suggestionsGrid = document.getElementById('suggestionsGrid');
  const generatedPassword = document.getElementById('generatedPassword');
  const generatorLength = document.getElementById('generatorLength');
  const lengthLabel = document.getElementById('lengthLabel');
  const copyGenerated = document.getElementById('copyGenerated');
  const regenerateGenerated = document.getElementById('regenerateGenerated');
  const optUpper = document.getElementById('optUpper');
  const optLower = document.getElementById('optLower');
  const optNumbers = document.getElementById('optNumbers');
  const optSymbols = document.getElementById('optSymbols');
  const optSimilar = document.getElementById('optSimilar');
  const optAmbiguous = document.getElementById('optAmbiguous');
  const chart = document.getElementById('distributionChart');
  const chartContext = chart.getContext('2d');

  const unicodeLetterRegex = /\p{L}/u;
  const unicodeNumberRegex = /\p{N}/u;
  const emojiRegex = /\p{Extended_Pictographic}/u;
  const asciiLetters = 'abcdefghijklmnopqrstuvwxyz';
  const uppercaseLetters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const digits = '0123456789';
  const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?/`~";
  const ambiguousCharacters = 'Il1O0o|`"\\/{}[]()<>,.;:';
  const similarCharacters = 'oO0iIlL1S5Z2';
  const commonKeyboardRows = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890'];
  const keyboardPatterns = ['qwerty', 'asdfgh', 'zxcvbn', '12345', '09876', 'abcdef', 'fedcba', 'poiuy', 'qazwsx', 'wsxedc'];
  const dictionaryWords = ['india', 'apple', 'google', 'welcome', 'hello', 'summer', 'winter', 'password', 'football', 'love', 'admin', 'computer', 'school', 'family', 'security', 'secret', 'project', 'system', 'network', 'cyber', 'matrix', 'browser', 'keyboard', 'orange', 'finance', 'office'];
  const crackModels = [
    { label: 'Online attack', rate: 100 },
    { label: 'Dictionary attack', rate: 12000 },
    { label: 'Offline attack', rate: 250000000 },
    { label: 'GPU attack', rate: 1500000000000 },
    { label: 'Brute-force attack', rate: 9000000000000 }
  ];
  const checklistItems = [
    { key: 'length', label: '12+ characters', description: 'Longer passwords expand the search space quickly.' },
    { key: 'uppercase', label: 'Uppercase', description: 'Adds another character class to the pool.' },
    { key: 'lowercase', label: 'Lowercase', description: 'Useful, but should not be the only class.' },
    { key: 'number', label: 'Number', description: 'Numbers improve complexity when they are not appended only.' },
    { key: 'symbol', label: 'Special character', description: 'Symbols significantly raise entropy.' },
    { key: 'entropy', label: 'High entropy', description: 'Entropy should be substantial for offline safety.' },
    { key: 'notSequential', label: 'Not sequential', description: 'Remove keyboard rows and ordered runs.' },
    { key: 'notDictionary', label: 'Not dictionary word', description: 'Dictionary roots are easy to guess.' },
    { key: 'noPatterns', label: 'No repeated pattern', description: 'Repeats shrink effective security.' },
    { key: 'noWhitespace', label: 'No whitespace', description: 'Whitespace can reduce usability and introduce mistakes.' }
  ];

  function normalize(value) {
    return String(value || '').normalize('NFKC').trim().toLowerCase();
  }

  function getCssVar(name) {
    return window.getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function splitUnicodeCharacters(value) {
    return Array.from(value || '');
  }

  function isEmoji(character) {
    return emojiRegex.test(character);
  }

  function detectRepeatedCharacters(value) {
    return /(.)\1{2,}/u.test(value);
  }

  function detectRepeatedWords(value) {
    const words = normalize(value).match(/[a-z]+/g) || [];
    const seen = new Set();
    for (const word of words) {
      if (seen.has(word)) return true;
      seen.add(word);
    }
    return false;
  }

  function detectSequentialRun(value) {
    const compact = normalize(value).replace(/[^a-z0-9]/g, '');
    for (let index = 0; index <= compact.length - 4; index += 1) {
      const slice = compact.slice(index, index + 4);
      if (isOrderedSequence(slice) || isOrderedSequence(slice.split('').reverse().join(''))) {
        return true;
      }
    }
    return false;
  }

  function isOrderedSequence(slice) {
    return 'abcdefghijklmnopqrstuvwxyz'.includes(slice) || '0123456789'.includes(slice);
  }

  function containsKeyboardPattern(value) {
    const lowered = normalize(value);
    return keyboardPatterns.some((pattern) => lowered.includes(pattern)) || commonKeyboardRows.some((row) => {
      for (let index = 0; index <= row.length - 4; index += 1) {
        const slice = row.slice(index, index + 4);
        if (lowered.includes(slice) || lowered.includes(slice.split('').reverse().join(''))) {
          return true;
        }
      }
      return false;
    });
  }

  function containsDictionaryWord(value) {
    const lowered = normalize(value);
    return dictionaryWords.some((word) => lowered.includes(word));
  }

  function containsBirthYear(value) {
    const currentYear = new Date().getFullYear();
    return (value.match(/(?:19|20)\d{2}/g) || []).some((year) => {
      const numericYear = Number(year);
      return numericYear >= 1900 && numericYear <= currentYear;
    });
  }

  function containsDate(value) {
    return /(\b\d{2}[/-]\d{2}[/-]\d{2,4}\b)|(\b\d{4}[/-]\d{2}[/-]\d{2}\b)/.test(value) || /(?:19|20)\d{2}[/-]\d{1,2}[/-]\d{1,2}/.test(value);
  }

  function containsEmail(value) {
    return /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(value);
  }

  function containsPhoneNumber(value) {
    const cleaned = value.replace(/[\s().-]/g, '');
    return /(?:\+?\d{1,3})?\d{10,15}/.test(cleaned);
  }

  function detectUsername(value, username) {
    const normalizedPassword = normalize(value);
    const normalizedUsername = normalize(username);
    return normalizedUsername.length >= 3 && normalizedPassword.includes(normalizedUsername);
  }

  function detectWhitespace(value) {
    return /\s/.test(value);
  }

  function detectCommonSubstitutions(value) {
    const lowered = normalize(value);
    return [['a', '@'], ['o', '0'], ['i', '1'], ['e', '3'], ['s', '$'], ['t', '7']].some(([letter, symbol]) => lowered.includes(letter) && lowered.includes(symbol));
  }

  function isHexOnly(value) {
    return /^[0-9a-f]+$/i.test(value) && value.length >= 8;
  }

  function isBinaryOnly(value) {
    return /^[01]+$/.test(value) && value.length >= 8;
  }

  function collectPasswordStats(password) {
    const characters = splitUnicodeCharacters(password);
    const counts = { uppercase: 0, lowercase: 0, digit: 0, symbol: 0, emoji: 0, unicode: 0, whitespace: 0 };

    characters.forEach((character) => {
      if (/\s/u.test(character)) {
        counts.whitespace += 1;
      } else if (isEmoji(character)) {
        counts.emoji += 1;
        counts.unicode += 1;
      } else if (/[A-Z]/.test(character)) {
        counts.uppercase += 1;
      } else if (/[a-z]/.test(character)) {
        counts.lowercase += 1;
      } else if (/\d/.test(character)) {
        counts.digit += 1;
      } else if (unicodeLetterRegex.test(character) || unicodeNumberRegex.test(character)) {
        counts.unicode += 1;
      } else {
        counts.symbol += 1;
      }
    });

    const uniqueCharacters = new Set(characters);
    const uniqueRatio = characters.length === 0 ? 0 : uniqueCharacters.size / characters.length;
    const hasUppercase = counts.uppercase > 0;
    const hasLowercase = counts.lowercase > 0;
    const hasDigit = counts.digit > 0;
    const hasSymbol = counts.symbol > 0;
    const hasUnicode = counts.unicode > 0 || counts.emoji > 0;
    const charPool = getCharacterPoolSize({ hasUppercase, hasLowercase, hasDigit, hasSymbol, hasUnicode, password });
    const entropyBits = characters.length * Math.log2(Math.max(1, charPool));
    const combinationsLog10 = characters.length * Math.log10(Math.max(1, charPool));

    return { length: characters.length, counts, uniqueRatio, hasUppercase, hasLowercase, hasDigit, hasSymbol, hasUnicode, charPool, entropyBits, combinationsLog10, combinationsDisplay: formatScientificFromLog10(combinationsLog10) };
  }

  function getCharacterPoolSize({ hasUppercase, hasLowercase, hasDigit, hasSymbol, hasUnicode, password }) {
    let pool = 0;
    if (hasLowercase) pool += 26;
    if (hasUppercase) pool += 26;
    if (hasDigit) pool += 10;
    if (hasSymbol) pool += 33;
    if (hasUnicode) {
      pool += Math.max(40, Math.min(800, splitUnicodeCharacters(password).filter((character) => unicodeLetterRegex.test(character) || unicodeNumberRegex.test(character) || isEmoji(character)).length * 16));
    }
    if (pool === 0 && password.length > 0) pool = 26;
    return pool;
  }

  function formatScientificFromLog10(log10Value) {
    if (!isFinite(log10Value) || log10Value <= 0) return '1';
    const exponent = Math.floor(log10Value);
    const mantissa = 10 ** (log10Value - exponent);
    return `${mantissa.toFixed(2)}e+${exponent}`;
  }

  function estimateAttackTime(entropyBits, ratePerSecond) {
    if (!isFinite(entropyBits) || entropyBits <= 0 || ratePerSecond <= 0) return 0;
    const logSeconds = entropyBits * Math.log10(2) - Math.log10(ratePerSecond);
    return 10 ** logSeconds;
  }

  function formatDuration(seconds) {
    if (!isFinite(seconds) || seconds <= 0) return 'Instant';
    const minute = 60;
    const hour = minute * 60;
    const day = hour * 24;
    const month = day * 30.4375;
    const year = day * 365.25;
    const millionYears = year * 1000000;

    if (seconds < 1) return 'Instant';
    if (seconds < minute) return 'Few seconds';
    if (seconds < hour) return `${Math.max(1, Math.round(seconds / minute))} minute${seconds / minute >= 2 ? 's' : ''}`;
    if (seconds < day) return `${Math.max(1, Math.round(seconds / hour))} hour${seconds / hour >= 2 ? 's' : ''}`;
    if (seconds < month) return `${Math.max(1, Math.round(seconds / day))} day${seconds / day >= 2 ? 's' : ''}`;
    if (seconds < year) return `${Math.max(1, Math.round(seconds / month))} month${seconds / month >= 2 ? 's' : ''}`;
    if (seconds < 100 * year) return `${Math.max(1, Math.round(seconds / year))} year${seconds / year >= 2 ? 's' : ''}`;
    if (seconds < millionYears) return 'Centuries';
    if (seconds < millionYears * 1000) return 'Millions of years';
    return 'Astronomically long';
  }

  function getStrengthLabel(score) {
    if (score < 20) return 'Very Weak';
    if (score < 40) return 'Weak';
    if (score < 55) return 'Fair';
    if (score < 70) return 'Good';
    if (score < 85) return 'Strong';
    return 'Very Strong';
  }

  function scorePassword(password, stats) {
    let score = 0;
    const penaltyReasons = [];

    if (stats.length >= 12) score += 16;
    else if (stats.length >= 8) score += 8;
    else score += stats.length * 1.2;

    if (stats.entropyBits >= 80) score += 24;
    else if (stats.entropyBits >= 50) score += 16;
    else if (stats.entropyBits >= 30) score += 8;
    else score += stats.entropyBits / 5;

    const classes = [stats.hasUppercase, stats.hasLowercase, stats.hasDigit, stats.hasSymbol, stats.hasUnicode].filter(Boolean).length;
    score += classes * 8;
    score += Math.min(10, stats.uniqueRatio * 20);

    if (!stats.hasUppercase || !stats.hasLowercase) score -= 6;
    if (!stats.hasDigit) score -= 4;
    if (!stats.hasSymbol) score -= 8;
    if (containsDictionaryWord(password)) {
      score -= 18;
      penaltyReasons.push('Contains dictionary words');
    }
    if (detectSequentialRun(password)) {
      score -= 14;
      penaltyReasons.push('Contains sequential characters');
    }
    if (containsKeyboardPattern(password)) {
      score -= 16;
      penaltyReasons.push('Contains keyboard pattern');
    }
    if (detectRepeatedCharacters(password)) {
      score -= 10;
      penaltyReasons.push('Contains repeated character runs');
    }
    if (detectRepeatedWords(password)) {
      score -= 10;
      penaltyReasons.push('Contains repeated words');
    }
    if (detectCommonSubstitutions(password)) {
      score -= 6;
      penaltyReasons.push('Uses common substitutions');
    }
    if (containsEmail(password) || containsPhoneNumber(password) || containsDate(password) || containsBirthYear(password)) {
      score -= 16;
      penaltyReasons.push('Contains personal-data pattern');
    }
    if (detectWhitespace(password)) {
      score -= 4;
      penaltyReasons.push('Contains whitespace');
    }
    if (isHexOnly(password)) {
      score -= 10;
      penaltyReasons.push('Hex-only format is predictable');
    }
    if (isBinaryOnly(password)) {
      score -= 16;
      penaltyReasons.push('Binary-only format is extremely weak');
    }
    if (/^\d+$/.test(password)) {
      score -= 22;
      penaltyReasons.push('Numeric-only password');
    }
    if (/^[a-zA-Z\p{L}]+$/u.test(password) && password.length > 0) {
      score -= 14;
      penaltyReasons.push('Alphabetic-only password');
    }
    if (/^(.)\1+$/.test(password) && password.length > 0) {
      score = 0;
      penaltyReasons.push('Uniform repeated character');
    }
    if (password.length < 8) {
      score -= 18;
      penaltyReasons.push('Short password');
    }

    return { score: Math.max(0, Math.min(100, Math.round(score))), penaltyReasons };
  }

  function buildDetections(password, stats) {
    return [
      ['Length', `${stats.length} characters`, stats.length >= 12 ? 'Good' : 'Weak'],
      ['Uppercase', `${stats.counts.uppercase} found`, stats.hasUppercase ? 'Yes' : 'No'],
      ['Lowercase', `${stats.counts.lowercase} found`, stats.hasLowercase ? 'Yes' : 'No'],
      ['Digits', `${stats.counts.digit} found`, stats.counts.digit > 0 ? 'Yes' : 'No'],
      ['Symbols', `${stats.counts.symbol} found`, stats.counts.symbol > 0 ? 'Yes' : 'No'],
      ['Unicode', `${stats.counts.unicode + stats.counts.emoji} found`, stats.hasUnicode ? 'Yes' : 'No'],
      ['Repeated characters', detectRepeatedCharacters(password) ? 'Detected' : 'None', detectRepeatedCharacters(password) ? 'Risk' : 'Clear'],
      ['Repeated words', detectRepeatedWords(password) ? 'Detected' : 'None', detectRepeatedWords(password) ? 'Risk' : 'Clear'],
      ['Sequential run', detectSequentialRun(password) ? 'Detected' : 'None', detectSequentialRun(password) ? 'Risk' : 'Clear'],
      ['Keyboard pattern', containsKeyboardPattern(password) ? 'Detected' : 'None', containsKeyboardPattern(password) ? 'Risk' : 'Clear'],
      ['Dictionary words', containsDictionaryWord(password) ? 'Detected' : 'None', containsDictionaryWord(password) ? 'Risk' : 'Clear'],
      ['Email pattern', containsEmail(password) ? 'Detected' : 'None', containsEmail(password) ? 'Risk' : 'Clear'],
      ['Phone pattern', containsPhoneNumber(password) ? 'Detected' : 'None', containsPhoneNumber(password) ? 'Risk' : 'Clear'],
      ['Date pattern', containsDate(password) ? 'Detected' : 'None', containsDate(password) ? 'Risk' : 'Clear'],
      ['Birth year', containsBirthYear(password) ? 'Detected' : 'None', containsBirthYear(password) ? 'Risk' : 'Clear'],
      ['Username match', detectUsername(password, document.getElementById('usernameInput')?.value || '') ? 'Detected' : 'None', detectUsername(password, document.getElementById('usernameInput')?.value || '') ? 'Risk' : 'Clear'],
      ['Whitespace', detectWhitespace(password) ? 'Detected' : 'None', detectWhitespace(password) ? 'Risk' : 'Clear'],
      ['Emoji', stats.counts.emoji > 0 ? 'Detected' : 'None', stats.counts.emoji > 0 ? 'Supported' : 'Clear'],
      ['Hexadecimal only', isHexOnly(password) ? 'Yes' : 'No', isHexOnly(password) ? 'Weak' : 'Clear'],
      ['Binary only', isBinaryOnly(password) ? 'Yes' : 'No', isBinaryOnly(password) ? 'Weak' : 'Clear'],
      ['Numeric only', /^\d+$/.test(password) ? 'Yes' : 'No', /^\d+$/.test(password) ? 'Weak' : 'Clear'],
      ['Alphabetic only', /^[a-zA-Z\p{L}]+$/u.test(password) && password.length > 0 ? 'Yes' : 'No', /^[a-zA-Z\p{L}]+$/u.test(password) && password.length > 0 ? 'Weak' : 'Clear'],
      ['Mixed classes', `${[stats.hasUppercase, stats.hasLowercase, stats.hasDigit, stats.hasSymbol, stats.hasUnicode].filter(Boolean).length} types`, classesToLabel(stats)],
      ['Unique ratio', `${Math.round(stats.uniqueRatio * 100)}%`, stats.uniqueRatio > 0.6 ? 'Good' : 'Low']
    ];
  }

  function classesToLabel(stats) {
    const classCount = [stats.hasUppercase, stats.hasLowercase, stats.hasDigit, stats.hasSymbol, stats.hasUnicode].filter(Boolean).length;
    if (classCount >= 4) return 'Strong';
    if (classCount === 3) return 'Mixed';
    if (classCount === 2) return 'Limited';
    return 'Weak';
  }

  function analyzePassword(password) {
    const stats = collectPasswordStats(password);
    const { score, penaltyReasons } = scorePassword(password, stats);
    const attackTimes = crackModels.map((model) => ({
      label: model.label,
      seconds: estimateAttackTime(model.label === 'Dictionary attack' && containsDictionaryWord(password) ? Math.min(stats.entropyBits, 18) : stats.entropyBits, model.rate),
      labelText: formatDuration(estimateAttackTime(model.label === 'Dictionary attack' && containsDictionaryWord(password) ? Math.min(stats.entropyBits, 18) : stats.entropyBits, model.rate))
    }));

    return {
      password,
      stats,
      classes: [stats.hasUppercase, stats.hasLowercase, stats.hasDigit, stats.hasSymbol, stats.hasUnicode].filter(Boolean).length,
      score,
      strengthLabel: getStrengthLabel(score),
      penaltyReasons,
      attackTimes,
      flags: {
        length: stats.length >= 12,
        uppercase: stats.hasUppercase,
        lowercase: stats.hasLowercase,
        number: stats.hasDigit,
        symbol: stats.hasSymbol,
        entropy: stats.entropyBits >= 60,
        notSequential: !detectSequentialRun(password),
        notDictionary: !containsDictionaryWord(password),
        noPatterns: !(detectRepeatedCharacters(password) || detectRepeatedWords(password)),
        noWhitespace: !detectWhitespace(password)
      },
      detections: buildDetections(password, stats)
    };
  }

  function renderChecklist(analysis) {
    liveChecklist.innerHTML = checklistItems.map((item) => {
      const value = Boolean(analysis.flags[item.key]);
      return `<li class="${value ? 'good' : 'bad'}"><span class="checkmark" aria-hidden="true">${value ? '✓' : '✕'}</span><div class="check-text"><strong>${escapeHtml(item.label)}</strong><small>${escapeHtml(item.description)}</small></div></li>`;
    }).join('');
  }

  function renderCrackTimes(analysis) {
    crackTimes.innerHTML = analysis.attackTimes.map((model) => {
      const severity = model.seconds < 1 ? 'Critical' : model.seconds < 60 ? 'Very fast' : model.seconds < 3600 ? 'Fast' : model.seconds < 86400 ? 'Moderate' : 'Slow';
      return `<div class="crack-item"><div><strong>${escapeHtml(model.label)}</strong><small>${escapeHtml(severity)}</small></div><span>${escapeHtml(model.labelText)}</span></div>`;
    }).join('');
  }

  function renderSecurityTips(analysis) {
    const tips = [];
    if (analysis.stats.length < 16) tips.push('Increase length to at least 16 characters for stronger resistance.');
    if (!analysis.stats.hasSymbol) tips.push('Add symbols to expand the character pool.');
    if (!analysis.stats.hasDigit) tips.push('Include a number, but avoid predictable suffixes.');
    if (containsDictionaryWord(analysis.password)) tips.push('Remove dictionary words or replace them with unrelated fragments.');
    if (detectSequentialRun(analysis.password)) tips.push('Remove ordered runs like abc, 123, or qwerty.');
    if (detectRepeatedCharacters(analysis.password)) tips.push('Avoid repeated characters and repeated blocks.');
    if (analysis.stats.entropyBits < 60) tips.push('Aim for higher entropy or use a longer passphrase.');
    if (!tips.length) tips.push('Current password looks strong, but never reuse it across services.');
    tips.push('Enable MFA wherever possible.');
    tips.push('Store the password in a reputable password manager.');
    securityTips.innerHTML = tips.slice(0, 6).map((tip) => `<div class="tip-item"><strong>Tip</strong><small>${escapeHtml(tip)}</small></div>`).join('');
  }

  function renderDetections(analysis) {
    detectionList.innerHTML = analysis.detections.map(([label, value, flag]) => {
      const flagClass = /Risk|Critical|Weak/.test(flag) ? 'danger' : /Good|Strong|Clear|Yes|Supported/.test(flag) ? 'success' : 'neutral';
      return `<div class="detection-item"><div><span class="label">${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div><span class="flag ${flagClass}">${escapeHtml(flag)}</span></div>`;
    }).join('');
  }

  function renderSuggestions() {
    const suggestions = generateSuggestions(5);
    suggestionsGrid.innerHTML = suggestions.map((password) => `<button class="suggestion-card" type="button" data-password="${escapeHtml(password)}"><code>${escapeHtml(password)}</code><small>Click to load into the analyzer</small></button>`).join('');
    suggestionsGrid.querySelectorAll('[data-password]').forEach((button) => {
      button.addEventListener('click', () => {
        passwordInput.value = button.getAttribute('data-password') || '';
        analyzeAndRender(passwordInput.value);
        passwordInput.focus();
      });
    });
  }

  function updateSummary(analysis) {
    const { score, strengthLabel: strengthText, stats, penaltyReasons } = analysis;
    scoreValue.textContent = score;
    strengthLabel.textContent = strengthText;
    analysisSummary.textContent = passwordInput.value ? `${penaltyReasons.length ? `${penaltyReasons[0]}.` : 'Analysis complete.'}` : 'Start typing to see the live security analysis.';
    strengthPercent.textContent = `${score}%`;
    entropyText.textContent = `${stats.entropyBits.toFixed(1)} bits`;
    statLength.textContent = `${stats.length}`;
    statEntropy.textContent = `${stats.entropyBits.toFixed(1)} bits`;
    statPool.textContent = `${stats.charPool}`;
    statUniqueRatio.textContent = `${Math.round(stats.uniqueRatio * 100)}%`;
    statCombinations.textContent = stats.length > 0 ? stats.combinationsDisplay : '0';
    statClasses.textContent = `${analysis.classes}`;
    strengthFill.style.width = `${score}%`;
    entropyFill.style.width = `${Math.min(100, (stats.entropyBits / 120) * 100)}%`;
    strengthFill.style.background = score < 40
      ? 'linear-gradient(90deg, var(--bad), var(--warn))'
      : score < 70
        ? 'linear-gradient(90deg, var(--warn), var(--good))'
        : 'linear-gradient(90deg, var(--good), var(--accent))';
    renderRing(score);
  }

  function renderRing(score) {
    const ring = document.querySelector('.score-ring');
    if (!ring) return;
    const angle = Math.max(0, Math.min(360, score * 3.6));
    const color = score < 40 ? 'var(--bad)' : score < 70 ? 'var(--warn)' : 'var(--good)';
    ring.style.background = `conic-gradient(${color} ${angle}deg, rgba(255, 255, 255, 0.08) 0deg)`;
  }

  function renderChart(analysis) {
    const width = 640;
    const height = 280;

    chartContext.setTransform(1, 0, 0, 1, 0, 0);
    chartContext.clearRect(0, 0, chart.width, chart.height);

    chartContext.scale(2, 2);

    chartContext.fillStyle = 'rgba(255,255,255,0.02)';
    chartContext.fillRect(0, 0, width, height);

    const bars = [
      { label: 'Uppercase', value: analysis.stats.counts.uppercase, color: getCssVar('--accent') },
      { label: 'Lowercase', value: analysis.stats.counts.lowercase, color: getCssVar('--good') },
      { label: 'Digits', value: analysis.stats.counts.digit, color: getCssVar('--warn') },
      { label: 'Symbols', value: analysis.stats.counts.symbol, color: getCssVar('--bad') },
      { label: 'Unicode', value: analysis.stats.counts.unicode + analysis.stats.counts.emoji, color: getCssVar('--accent-2') }
    ];
    const maxValue = Math.max(1, ...bars.map((bar) => bar.value));

    chartContext.font = '600 24px Inter, sans-serif';
    chartContext.fillStyle = 'rgba(236, 245, 255, 0.95)';
    chartContext.fillText('Character Distribution', 32, 40);
    chartContext.font = '500 14px Inter, sans-serif';
    chartContext.fillStyle = 'rgba(155, 178, 209, 0.85)';
    chartContext.fillText('Counts detected in the current password', 32, 64);

    bars.forEach((bar, index) => {
      const x = 54 + index * 112;
      const barWidth = 84;
      const barHeight = (bar.value / maxValue) * (height - 130);
      const y = height - barHeight - 42;
      const fill = chartContext.createLinearGradient(0, y, 0, height - 42);
      fill.addColorStop(0, bar.color);
      fill.addColorStop(1, 'rgba(255,255,255,0.08)');
      chartContext.fillStyle = fill;

      chartContext.beginPath();
      const r = Math.min(8, barHeight);
      if (typeof chartContext.roundRect === 'function') {
        chartContext.roundRect(x, y, barWidth, barHeight, [r, r, 0, 0]);
      } else {
        chartContext.rect(x, y, barWidth, barHeight);
      }
      chartContext.fill();

      chartContext.fillStyle = 'rgba(236,245,255,0.95)';
      chartContext.font = '600 14px Inter, sans-serif';
      chartContext.fillText(bar.label, x, height - 18);
      chartContext.fillStyle = 'rgba(155,178,209,0.8)';
      chartContext.fillText(String(bar.value), x, y - 10);
    });
  }

  function analyzeAndRender(password) {
    const analysis = analyzePassword(password);
    updateSummary(analysis);
    renderChecklist(analysis);
    renderCrackTimes(analysis);
    renderSecurityTips(analysis);
    renderDetections(analysis);
    renderChart(analysis);
  }

  function defaultGeneratorOptions() {
    return {
      length: Number(generatorLength.value),
      uppercase: optUpper.checked,
      lowercase: optLower.checked,
      numbers: optNumbers.checked,
      symbols: optSymbols.checked,
      excludeSimilar: optSimilar.checked,
      excludeAmbiguous: optAmbiguous.checked
    };
  }

  function randomIndex(max) {
    const buffer = new Uint32Array(1);
    const limit = Math.max(1, max);
    const threshold = Math.floor(0xffffffff / limit) * limit;
    let value = 0;
    do {
      crypto.getRandomValues(buffer);
      value = buffer[0];
    } while (value >= threshold);
    return value % limit;
  }

  function randomChoice(pool) {
    return pool[randomIndex(pool.length)];
  }

  function secureShuffle(values) {
    const array = [...values];
    for (let index = array.length - 1; index > 0; index -= 1) {
      const random = randomIndex(index + 1);
      [array[index], array[random]] = [array[random], array[index]];
    }
    return array;
  }

  function buildCharacterPool(options) {
    let pool = '';
    if (options.lowercase) pool += asciiLetters;
    if (options.uppercase) pool += uppercaseLetters;
    if (options.numbers) pool += digits;
    if (options.symbols) pool += symbols;
    if (options.excludeSimilar) pool = Array.from(pool).filter((character) => !similarCharacters.includes(character)).join('');
    if (options.excludeAmbiguous) pool = Array.from(pool).filter((character) => !ambiguousCharacters.includes(character)).join('');
    return Array.from(new Set(pool.split(''))).join('');
  }

  function filterGroup(group, options) {
    let characters = Array.from(group);
    if (options.excludeSimilar) {
      characters = characters.filter((c) => !similarCharacters.includes(c));
    }
    if (options.excludeAmbiguous) {
      characters = characters.filter((c) => !ambiguousCharacters.includes(c));
    }
    return characters;
  }

  function generateSecurePassword(length, options) {
    const pool = buildCharacterPool(options);
    if (!pool) return generateSecurePassword(length, { ...options, lowercase: true });

    const characters = [];
    const requiredGroups = [];
    if (options.lowercase) {
      const g = filterGroup(asciiLetters, options);
      if (g.length > 0) requiredGroups.push(randomChoice(g));
    }
    if (options.uppercase) {
      const g = filterGroup(uppercaseLetters, options);
      if (g.length > 0) requiredGroups.push(randomChoice(g));
    }
    if (options.numbers) {
      const g = filterGroup(digits, options);
      if (g.length > 0) requiredGroups.push(randomChoice(g));
    }
    if (options.symbols) {
      const g = filterGroup(symbols, options);
      if (g.length > 0) requiredGroups.push(randomChoice(g));
    }
    requiredGroups.forEach((character) => characters.push(character));

    while (characters.length < length) {
      characters.push(randomChoice(pool.split('')));
    }

    return secureShuffle(characters).join('').slice(0, length);
  }

  function generateSuggestions(count) {
    const options = defaultGeneratorOptions();
    const suggestions = new Set();
    while (suggestions.size < count) {
      suggestions.add(generateSecurePassword(Math.max(16, options.length), { ...options, excludeSimilar: true, excludeAmbiguous: true }));
    }
    return Array.from(suggestions);
  }

  function syncGeneratorLength() {
    lengthLabel.textContent = generatorLength.value;
  }

  function generateAndRenderPassword() {
    syncGeneratorLength();
    generatedPassword.value = generateSecurePassword(Number(generatorLength.value), defaultGeneratorOptions());
  }

  async function copyGeneratedPassword() {
    if (!generatedPassword?.value) return;
    try {
      await navigator.clipboard.writeText(generatedPassword.value);
      if (copyGenerated) {
        copyGenerated.textContent = 'Copied';
        setTimeout(() => {
          copyGenerated.textContent = 'Copy';
        }, 1200);
      }
    } catch {
      generatedPassword.select();
      generatedPassword.setSelectionRange(0, generatedPassword.value.length);
    }
  }

  function setupEvents() {
    const usernameInput = document.getElementById('usernameInput');
    const emailInput = document.getElementById('emailInput');
    const copyPasswordButton = document.getElementById('copyPassword');
    const regenerateSuggestionsButton = document.getElementById('regenerateSuggestions');

    passwordInput.addEventListener('input', (event) => analyzeAndRender(event.target.value));
    usernameInput.addEventListener('input', () => analyzeAndRender(passwordInput.value));
    emailInput.addEventListener('input', () => analyzeAndRender(passwordInput.value));

    toggleVisibilityButton.addEventListener('click', () => {
      const showing = passwordInput.type === 'text';
      passwordInput.type = showing ? 'password' : 'text';
      toggleVisibilityButton.setAttribute('aria-pressed', String(!showing));
      toggleVisibilityButton.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
      toggleVisibilityButton.classList.toggle('password-visible', !showing);
    });

    copyPasswordButton?.addEventListener('click', async () => {
      if (!passwordInput.value) return;
      try {
        await navigator.clipboard.writeText(passwordInput.value);
        const originalHtml = copyPasswordButton.innerHTML;
        copyPasswordButton.innerHTML = `
          <svg class="icon icon-check" viewBox="0 0 24 24" fill="none" stroke="var(--good)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
        `;
        setTimeout(() => {
          copyPasswordButton.innerHTML = originalHtml;
        }, 1200);
      } catch (err) {
        console.error('Failed to copy password: ', err);
      }
    });

    generatorLength.addEventListener('input', () => {
      syncGeneratorLength();
      generateAndRenderPassword();
    });

    [optUpper, optLower, optNumbers, optSymbols, optSimilar, optAmbiguous].forEach((input) => {
      input.addEventListener('change', generateAndRenderPassword);
    });

    copyGenerated?.addEventListener('click', copyGeneratedPassword);
    regenerateGenerated?.addEventListener('click', generateAndRenderPassword);
    regenerateSuggestionsButton?.addEventListener('click', () => renderSuggestions());
  }

  function initialize() {
    setupEvents();
    generateAndRenderPassword();
    analyzeAndRender('');
    renderSuggestions();
  }

  initialize();
})();
