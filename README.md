# 🛡️ Password Security Analyzer

An interactive, premium, client-side cybersecurity dashboard for password strength analysis, entropy measurement, and secure password generation. Built entirely with HTML5, CSS3 (Vanilla CSS with CSS Variables), and modern ES6+ vanilla JavaScript.

![License](https://img.shields.io/github/license/JEFFERSON-007/Password-Strength-Checker?color=blue)
![Prerequisites](https://img.shields.io/badge/prerequisites-None-brightgreen)
![Local Only](https://img.shields.io/badge/privacy-Local%20Only-blueviolet)

---

## 🌟 Key Features

*   **⚡ Keystroke-Level Real-Time Analysis**: Instantly evaluates password complexity, entropy, character distribution, and crack time estimates on every keystroke.
*   **📊 Dynamic Character Distribution Chart**: High-DPI/Retina scaled canvas visualization illustrating the frequency of character classes (Uppercase, Lowercase, Digits, Symbols, Unicode).
*   **🔐 Cryptographically Secure Generator**: Built-in generator leveraging the Web Cryptography API (`crypto.getRandomValues`) for maximum security.
*   **🚫 Smart Exclusions**: Configurable options to exclude similar (e.g., `i, l, 1, o, 0`) and ambiguous (e.g., `{, }, [, ]`) characters, guaranteeing strictly compliant passwords.
*   **🕵️ Extensive Pattern Detections**: Automatically flags:
    *   Dictionary words (against a common root list)
    *   Keyboard layout runs (e.g., sequential keys or row blocks like `qwerty`)
    *   Sequential runs (e.g., `abcd`, `1234`)
    *   Uniform or repeated character/word sequences (e.g., `aaaa`, `passpass`)
    *   Personal data leakage (dates, birth years, emails, phone numbers, matched username)
*   **♿ Full Accessibility & UX Conformance**: Keyboard-navigable UI, proper semantic labelling, ARIA state variables, live announcement regions, and micro-interactive feedbacks (success copy transitions).

---

## 🧠 Scientific Security Modeling

### 1. Entropy Estimation

Entropy represents the logarithmic measure of password unpredictability based on the size of the symbol pool from which characters are drawn:

$$\text{Entropy (bits)} = L \times \log_2(N)$$

Where:
*   $L$ is the number of characters in the password.
*   $N$ is the size of the active character pool size determined by classes present:
    *   *Lowercase letters*: $+26$
    *   *Uppercase letters*: $+26$
    *   *Digits*: $+10$
    *   *Symbols*: $+33$
    *   *Unicode/Emoji*: Dynamically scaled based on character frequency.

### 2. Attack Estimates

Crack times are modeled using typical attack rates across different levels of adversary computing resources:

*   **Online Attack**: 100 guesses/sec (throttled APIs).
*   **Dictionary Attack**: 12,000 guesses/sec (targeted wordlist guessing).
*   **Offline Attack**: 250,000,000 guesses/sec (standard server hashing).
*   **GPU Attack**: 1.5 trillion guesses/sec (multi-GPU cracking rig).
*   **Brute-Force Attack**: 9 trillion guesses/sec (custom cracking hardware).

---

## 📁 Project Structure

```
├── index.html       # Semantic dashboard shell & markup templates
├── style.css        # Responsive stylesheet, custom grid, and CSS variables
├── script.js        # Core analysis engine, Web Crypto generator, and canvas chart
└── README.md        # Comprehensive project documentation
```

---

## 🚀 Running Locally

The project is completely static and serverless. No server setups or dependencies are required.

### Method 1: Local Server (Recommended)
Launch a simple static file server to test all features:
```bash
# Using Python
python -m http.server 8000

# Using Node.js (http-server)
npx http-server
```
Navigate to `http://localhost:8000` (or `8080`) in your browser.

### Method 2: Direct Open
Double-click `index.html` to open it directly in any modern browser.

---

## 🔒 Privacy & Security Commitments

*   **Zero Remote Storage**: No inputs, usernames, or passwords are saved or sent over the network.
*   **Client-Side Execution**: All processing (including entropy calculation and random number generation) is done locally in your browser.
*   **No Third-Party Scripts**: Built with raw web assets only, ensuring there are no CDN vulnerabilities or supply chain vectors.
