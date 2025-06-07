import random
import math
import string
from flask import Flask, render_template_string, request, jsonify
import os
import threading
import webbrowser

def open_browser():
    webbrowser.open("http://127.0.0.1:8080/")
    
app = Flask(__name__)

# --- Wordlist for passphrase (short, for demo; use a larger list in production) ---
WORDLIST = [
    "apple", "banana", "car", "delta", "echo", "forest", "grape", "hotel", "india",
    "jungle", "kite", "lemon", "mountain", "night", "orange", "pizza", "quiet",
    "river", "sun", "tree", "umbrella", "violet", "wolf", "xenon", "yellow", "zebra"
]

# --- Helper functions ---

def generate_password(length=16, upper=True, lower=True, digits=True, symbols=True, exclude_ambiguous=False, no_repeat=False, no_sequence=False):
    charsets = []
    if upper:
        charsets.append(string.ascii_uppercase)
    if lower:
        charsets.append(string.ascii_lowercase)
    if digits:
        charsets.append(string.digits)
    if symbols:
        charsets.append("!@#$%^&*()-_=+[]{};:,.<>?/|")
    chars = ''.join(charsets)
    if exclude_ambiguous:
        for c in "O0Il1|":
            chars = chars.replace(c, "")
    if not chars:
        return ""
    password = ""
    last_char = ""
    for i in range(length):
        while True:
            c = random.choice(chars)
            if no_repeat and password and c == password[-1]:
                continue
            if no_sequence and password and ord(c) == ord(password[-1]) + 1:
                continue
            break
        password += c
    return password

def generate_passphrase(num_words=4, separator="-", capitalize=False):
    words = [random.choice(WORDLIST) for _ in range(num_words)]
    if capitalize:
        words = [w.capitalize() for w in words]
    return separator.join(words)

def password_entropy(password, charset_size):
    # Shannon entropy: E = L * log2(R)
    return len(password) * math.log2(charset_size) if password else 0

def estimate_crack_time(entropy_bits):
    # Rough estimate: 1 billion guesses/sec (modern GPU)
    guesses = 2 ** entropy_bits
    seconds = guesses / 1e9
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    else:
        return f"{seconds/31536000:.2f} years"

def check_patterns(password):
    patterns = []
    if password.lower() in ["password", "123456", "qwerty", "letmein"]:
        patterns.append("Common password")
    if any(password == c * len(password) for c in set(password)):
        patterns.append("Repeated characters")
    if any(seq in password.lower() for seq in ["abcd", "1234", "qwer", "asdf"]):
        patterns.append("Sequential pattern")
    if len(set(password)) < len(password) // 2:
        patterns.append("Low character variety")
    return patterns

def charset_size(upper, lower, digits, symbols, exclude_ambiguous):
    size = 0
    if upper:
        size += 26
        if exclude_ambiguous:
            size -= 2  # O, I
    if lower:
        size += 26
        if exclude_ambiguous:
            size -= 2  # l, o
    if digits:
        size += 10
        if exclude_ambiguous:
            size -= 2  # 0, 1
    if symbols:
        size += len("!@#$%^&*()-_=+[]{};:,.<>?/|")
        if exclude_ambiguous:
            size -= 1  # |
    return max(size, 1)

# --- HTML Template ---

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Password Generator & Strength Checker</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .strength-bar { height: 8px; border-radius: 4px; }
        .strength-weak { background: #dc3545; }
        .strength-medium { background: #ffc107; }
        .strength-strong { background: #28a745; }
        .pw-box { font-family: monospace; font-size: 1.3em; letter-spacing: 2px; }
    </style>
</head>
<body class="bg-dark text-light">
<div class="container py-4">
    <h1 class="mb-3">🔐 Password Generator & Strength Checker</h1>
    <form id="pwform" class="row g-3">
        <div class="col-md-2"><label>Password length</label>
            <input type="number" min="6" max="64" class="form-control" name="length" value="16">
        </div>
        <div class="col-md-2"><label>Uppercase</label>
            <input type="checkbox" name="upper" checked>
        </div>
        <div class="col-md-2"><label>Lowercase</label>
            <input type="checkbox" name="lower" checked>
        </div>
        <div class="col-md-2"><label>Digits</label>
            <input type="checkbox" name="digits" checked>
        </div>
        <div class="col-md-2"><label>Symbols</label>
            <input type="checkbox" name="symbols" checked>
        </div>
        <div class="col-md-2"><label>Exclude ambiguous</label>
            <input type="checkbox" name="exclude_ambiguous">
        </div>
        <div class="col-md-2"><label>No repeats</label>
            <input type="checkbox" name="no_repeat">
        </div>
        <div class="col-md-2"><label>No sequences</label>
            <input type="checkbox" name="no_sequence">
        </div>
        <div class="col-md-2"><label>Passphrase</label>
            <input type="checkbox" name="passphrase">
        </div>
        <div class="col-md-2"><label># Words</label>
            <input type="number" min="3" max="8" class="form-control" name="num_words" value="4">
        </div>
        <div class="col-md-2"><label>Capitalize words</label>
            <input type="checkbox" name="capitalize">
        </div>
        <div class="col-md-2"><label>Separator</label>
            <input type="text" maxlength="2" class="form-control" name="separator" value="-">
        </div>
        <div class="col-md-12 mt-3">
            <button class="btn btn-primary" type="submit">Generate</button>
        </div>
    </form>
    <hr>
    <div id="pwresult" style="display:none;">
        <div class="mb-2">
            <span class="pw-box" id="pwbox"></span>
            <button class="btn btn-outline-info btn-sm" onclick="copyPw()">Copy</button>
        </div>
        <div class="mb-2">
            <div class="strength-bar" id="strengthbar"></div>
            <span id="strengthlabel"></span>
        </div>
        <div class="mb-2">
            <b>Entropy:</b> <span id="entropy"></span> bits,
            <b>Estimated crack time:</b> <span id="cracktime"></span>
        </div>
        <div class="mb-2">
            <b>Patterns:</b> <span id="patterns"></span>
        </div>
    </div>
    <footer class="mt-5 text-center">
        <small>All password generation and checking is done locally. No data leaves your device. | &copy; 2025</small>
    </footer>
</div>
<script>
function copyPw() {
    let pw = document.getElementById("pwbox").textContent;
    navigator.clipboard.writeText(pw);
}
document.getElementById("pwform").onsubmit = async function(e) {
    e.preventDefault();
    let fd = new FormData(this);
    let data = {};
    fd.forEach((v,k) => data[k]=v);
    data["upper"] = !!fd.get("upper");
    data["lower"] = !!fd.get("lower");
    data["digits"] = !!fd.get("digits");
    data["symbols"] = !!fd.get("symbols");
    data["exclude_ambiguous"] = !!fd.get("exclude_ambiguous");
    data["no_repeat"] = !!fd.get("no_repeat");
    data["no_sequence"] = !!fd.get("no_sequence");
    data["passphrase"] = !!fd.get("passphrase");
    data["capitalize"] = !!fd.get("capitalize");
    let res = await fetch("/api/generate", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify(data)
    });
    let result = await res.json();
    document.getElementById("pwbox").textContent = result.password;
    let bar = document.getElementById("strengthbar");
    let label = document.getElementById("strengthlabel");
    if (result.strength == "Strong") {
        bar.className = "strength-bar strength-strong";
        label.textContent = "Strong";
    } else if (result.strength == "Medium") {
        bar.className = "strength-bar strength-medium";
        label.textContent = "Medium";
    } else {
        bar.className = "strength-bar strength-weak";
        label.textContent = "Weak";
    }
    bar.style.width = (result.entropy/128*100) + "%";
    document.getElementById("entropy").textContent = result.entropy.toFixed(2);
    document.getElementById("cracktime").textContent = result.crack_time;
    document.getElementById("patterns").textContent = result.patterns.length ? result.patterns.join(", ") : "None";
    document.getElementById("pwresult").style.display = "block";
}
</script>
</body>
</html>
"""

# --- API route ---

@app.route("/api/generate", methods=["POST"])
def api_generate():
    data = request.json
    if data.get("passphrase"):
        num_words = int(data.get("num_words", 4))
        separator = data.get("separator", "-")
        capitalize = bool(data.get("capitalize"))
        password = generate_passphrase(num_words, separator, capitalize)
        entropy = math.log2(len(WORDLIST)) * num_words
        crack_time = estimate_crack_time(entropy)
        patterns = check_patterns(password)
        strength = "Strong" if entropy > 60 else "Medium" if entropy > 40 else "Weak"
    else:
        length = int(data.get("length", 16))
        upper = bool(data.get("upper"))
        lower = bool(data.get("lower"))
        digits = bool(data.get("digits"))
        symbols = bool(data.get("symbols"))
        exclude_ambiguous = bool(data.get("exclude_ambiguous"))
        no_repeat = bool(data.get("no_repeat"))
        no_sequence = bool(data.get("no_sequence"))
        password = generate_password(length, upper, lower, digits, symbols, exclude_ambiguous, no_repeat, no_sequence)
        cs = charset_size(upper, lower, digits, symbols, exclude_ambiguous)
        entropy = password_entropy(password, cs)
        crack_time = estimate_crack_time(entropy)
        patterns = check_patterns(password)
        strength = "Strong" if entropy > 80 and not patterns else "Medium" if entropy > 50 else "Weak"
    return jsonify({
        "password": password,
        "entropy": entropy,
        "crack_time": crack_time,
        "patterns": patterns,
        "strength": strength
    })

# --- Main route ---

@app.route("/", methods=["GET"])
def home():
    return render_template_string(HTML)

if __name__ == "__main__":
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        threading.Timer(1, open_browser).start()
    app.run(debug=True, port=8080)