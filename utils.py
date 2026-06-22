import math
import re
import random
import string
import requests
import hashlib

# Predefined list of common passwords for breached simulation and dictionary lookup
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "qwerty", "12345678", "12345", "1234567",
    "1234567890", "1234", "password123", "admin", "12345678901", "letmein",
    "iloveyou", "football", "welcome", "123123", "computer", "111111", "monkey",
    "secret", "login", "charlie", "hunter2", "ashley", "qwertyuiop", "dragon",
    "superman", "mustang", "shadow", "master", "rookie", "killer", "password1",
    "michael", "jessica", "daniel", "andrew", "matthew", "chelsea", "mariah",
    "princesa", "santiago", "justin", "nicolas", "alexander", "sebastian",
    "alejandro", "carlos", "cristian", "fernando", "roberto", "diego", "javier",
    "gabriel", "andres", "ricardo", "juan", "pedro", "luis", "miguel", "jorge",
    "carlos1", "jose", "manuel", "felipe", "hugo", "martin", "lucas", "mateo",
    "querty", "qwerty123", "password!23", "drowssap", "pass123", "admin123",
    "root", "testing", "password12", "hello", "goodmorning", "goodnight",
    "iloveme", "lovelove", "soccer", "baseball", "basketball", "starwars",
    "superstar", "ninja", "wizard", "hacker", "anonymous", "matrix", "cyber",
    "security", "hackme", "donotuse", "changeit", "password!"
}

# Keyboard row sequences (forward check)
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]

# In-memory cache for HIBP range API queries to prevent network spamming
# Format: { sha1_prefix_5_chars: { suffix_35_chars: breach_count } }
HIBP_CACHE = {}

def check_hibp_api(password):
    """
    Query the Have I Been Pwned API (k-anonymity) to check if the password is breached.
    Only queries for passwords of length >= 6.
    Returns:
        int: Number of times breached.
        0: If not breached.
        None: If the API is offline or request timed out.
    """
    if len(password) < 6:
        return 0 # Save API rate limits for trivial short passwords
        
    # Compute SHA-1 hash (uppercase)
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    
    # 1. Hit cache first
    if prefix in HIBP_CACHE:
        return HIBP_CACHE[prefix].get(suffix, 0)
        
    # 2. Query k-anonymity endpoint
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=2.5)
        if response.status_code == 200:
            suffixes = {}
            for line in response.text.splitlines():
                if ':' in line:
                    s, count = line.split(':')
                    suffixes[s.strip().upper()] = int(count)
            # Store in cache
            HIBP_CACHE[prefix] = suffixes
            return suffixes.get(suffix, 0)
    except (requests.RequestException, ValueError) as e:
        print(f"HIBP API rate-limit/timeout fallback triggered: {e}")
        return None
        
    return 0

def check_sequential_patterns(password):
    """
    Dynamically detect ascending and descending alphabetical, numerical,
    and keyboard sequences of length >= 3.
    e.g. 'abc', 'cba', '123', '543', 'qwe', 'ewq'.
    """
    detected = []
    pwd_lower = password.lower()
    
    # 1. Dynamic Alphabetic/Numeric scans (distance checking)
    for i in range(len(pwd_lower) - 2):
        chunk = pwd_lower[i:i+3]
        c1, c2, c3 = chunk[0], chunk[1], chunk[2]
        
        # Numeric sequences (123, 765, etc.)
        if c1.isdigit() and c2.isdigit() and c3.isdigit():
            if ord(c2) - ord(c1) == 1 and ord(c3) - ord(c2) == 1:
                detected.append(chunk)
            elif ord(c2) - ord(c1) == -1 and ord(c3) - ord(c2) == -1:
                detected.append(chunk)
                
        # Alphabetic sequences (abc, zyx, etc.)
        elif c1.isalpha() and c2.isalpha() and c3.isalpha():
            if ord(c2) - ord(c1) == 1 and ord(c3) - ord(c2) == 1:
                detected.append(chunk)
            elif ord(c2) - ord(c1) == -1 and ord(c3) - ord(c2) == -1:
                detected.append(chunk)
                
    # 2. Keyboard walks (qwerty, asdf, and reverse)
    for row in KEYBOARD_ROWS:
        for i in range(len(pwd_lower) - 2):
            chunk = pwd_lower[i:i+3]
            if chunk in row or chunk[::-1] in row:
                detected.append(chunk)
                
    return list(set(detected))

def check_repeated_characters(password):
    """
    Detect character repetition sequences of length >= 3 (e.g. 'aaa', '1111').
    """
    detected = []
    i = 0
    while i < len(password) - 2:
        char = password[i]
        count = 1
        while i + count < len(password) and password[i + count] == char:
            count += 1
        if count >= 3:
            detected.append(char * count)
            i += count
        else:
            i += 1
    return detected

def check_leet_substitutions(password):
    """
    Check if the password contains common character substitutions (l33tspeak).
    Normalizes symbols back to letters and checks if they match a common dictionary word.
    """
    pwd_lower = password.lower()
    leet_map = {
        '@': 'a', '4': 'a',
        '$': 's', '5': 's',
        '0': 'o',
        '3': 'e',
        '1': 'i', '!': 'i', '7': 't'
    }
    
    # Check if leet characters are present
    has_leet = any(char in leet_map for char in pwd_lower)
    if not has_leet:
        return False
        
    # Translate password
    normalized = [leet_map.get(char, char) for char in pwd_lower]
    normalized_str = "".join(normalized)
    
    # Verify if normalized string contains any common dictionary word >= 4 letters
    for word in COMMON_PASSWORDS:
        if len(word) >= 4 and (word in normalized_str or normalized_str in word):
            return True
            
    return False

def calculate_entropy(password):
    """
    Calculate the Shannon entropy, adjusted with deductions for human patterns.
    
    Shannon Baseline: E = L * log2(pool_size)
    Deductions:
    - Dictionary words: -15 bits
    - Repeated chunks (e.g. 'abcabc'): -10 bits
    - Keyboard walks: -10 bits
    - Year patterns (e.g. '2004', '2026'): -15 bits
    """
    if not password:
        return 0.0, []
        
    pool_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_special: pool_size += len(string.punctuation)
    
    other_chars = sum(1 for c in password if not (c.isalnum() or c in string.punctuation))
    if other_chars > 0:
        pool_size += 20
        
    if pool_size == 0:
        pool_size = 1
        
    length = len(password)
    entropy = length * math.log2(pool_size)
    deductions = []
    pwd_lower = password.lower()
    
    # 1. Dictionary / Name Penalty
    contains_common = False
    for word in COMMON_PASSWORDS:
        if len(word) >= 4 and word in pwd_lower:
            contains_common = True
            break
    if contains_common:
        entropy -= 15
        deductions.append("Dictionary word/phrase detected (-15 bits)")
        
    # 2. Repeated Chunks (zxcvbn-style, e.g. 'passpass', '123123')
    # Using regex to find repeating substrings of length 2-6
    has_rep_chunks = re.search(r'(.{2,6})\1+', password)
    if has_rep_chunks:
        entropy -= 10
        deductions.append("Repeated chunk sequence detected (-10 bits)")
        
    # 3. Keyboard walks
    has_kbd_walk = False
    for row in KEYBOARD_ROWS:
        for i in range(len(pwd_lower) - 2):
            chunk = pwd_lower[i:i+3]
            if chunk in row or chunk[::-1] in row:
                has_kbd_walk = True
                break
    if has_kbd_walk:
        entropy -= 10
        deductions.append("Keyboard walk pattern detected (-10 bits)")
        
    # 4. Year patterns (e.g. 19xx or 20xx)
    has_year = re.search(r'(19|20)\d{2}', password)
    if has_year:
        entropy -= 15
        deductions.append("Common year pattern detected (-15 bits)")
        
    entropy = max(0.0, round(entropy, 2))
    return entropy, deductions

def estimate_crack_time(entropy):
    """
    Estimate time to crack based on entropy using 4 attack models:
    1. Online Throttled (10 guesses/sec)
    2. Online Unthrottled (1,000 guesses/sec)
    3. Offline CPU (10^7 guesses/sec)
    4. Offline GPU (10^10 guesses/sec)
    """
    guesses = 0.5 * (2 ** entropy)
    
    def format_time(seconds):
        if seconds < 0.001:
            return "Instant"
        elif seconds < 1:
            return f"{round(seconds * 1000, 2)} ms"
        elif seconds < 60:
            return f"{round(seconds, 2)} sec"
        elif seconds < 3600:
            return f"{round(seconds / 60, 1)} min"
        elif seconds < 86400:
            return f"{round(seconds / 3600, 1)} hours"
        elif seconds < 31536000:
            return f"{round(seconds / 86400, 1)} days"
        elif seconds < 3153600000:
            return f"{round(seconds / 31536000, 1)} years"
        else:
            years = seconds / 31536000
            if years < 1e6:
                return f"{round(years / 100, 1)} centuries"
            elif years < 1e9:
                return f"{round(years / 1e6, 1)}M years"
            else:
                return f"{round(years / 1e9, 1)}B years"
                
    return {
        "online_throttled": format_time(guesses / 10),
        "online_unthrottled": format_time(guesses / 1000),
        "offline_cpu": format_time(guesses / 10000000),
        "offline_gpu": format_time(guesses / 10000000000)
    }

def generate_strong_alternative(password):
    """
    Suggests a stronger version of the password by applying leetspeak
    replacements, adding digits/symbols, and padding to >= 16 characters.
    """
    if not password:
        return generate_random_password(16)
        
    replacements = {
        'a': '@', 'A': '4',
        's': '$', 'S': '5',
        'o': '0', 'O': '0',
        'i': '1', 'I': '!', 'l': '1', 'L': '1',
        'e': '3', 'E': '3',
        't': '7', 'T': '7',
        'g': '9', 'G': '9',
        'b': '8', 'B': '8'
    }
    
    modified = []
    for char in password:
        if char in replacements and random.random() < 0.8:
            modified.append(replacements[char])
        else:
            modified.append(char)
            
    alt = "".join(modified)
    
    if not any(c.isdigit() for c in alt):
        alt += str(random.randint(0, 9))
    if not any(c in string.punctuation for c in alt):
        alt += random.choice("!@#$%^&*")
        
    if len(alt) < 16:
        needed = 16 - len(alt)
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
        padding = "".join(random.choice(chars) for _ in range(needed))
        alt += padding
        
    return alt

def generate_random_password(length=16):
    """
    Generate a cryptographically secure random password of specified length.
    """
    if length < 8:
        length = 8
        
    req_upper = [random.choice(string.ascii_uppercase) for _ in range(2)]
    req_lower = [random.choice(string.ascii_lowercase) for _ in range(2)]
    req_digits = [random.choice(string.digits) for _ in range(2)]
    req_symbols = [random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?") for _ in range(2)]
    
    password_chars = req_upper + req_lower + req_digits + req_symbols
    
    all_pool = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    remaining_length = length - len(password_chars)
    if remaining_length > 0:
        password_chars += [random.choice(all_pool) for _ in range(remaining_length)]
        
    try:
        sr = random.SystemRandom()
        sr.shuffle(password_chars)
    except NotImplementedError:
        random.shuffle(password_chars)
        
    return "".join(password_chars)

def analyze_password(password, is_previously_used=False):
    """
    Performs a comprehensive audit of the password, calculating a weighted score,
    identifying zxcvbn-style pattern weaknesses, running HIBP checks, and generating
    suggestions.
    """
    length = len(password)
    
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    # 1. Pattern checks
    seq_patterns = check_sequential_patterns(password)
    rep_patterns = check_repeated_characters(password)
    has_leet = check_leet_substitutions(password)
    
    # 2. Year check
    has_year = re.search(r'(19|20)\d{2}', password)
    
    # 3. Dictionary word check
    pwd_lower = password.lower()
    detected_words = [word for word in COMMON_PASSWORDS if len(word) >= 4 and word in pwd_lower]
    
    # 4. Have I Been Pwned check (online API)
    hibp_count = check_hibp_api(password)
    is_breached = False
    if hibp_count is not None and hibp_count > 0:
        is_breached = True
    elif hibp_count is None:
        # Fallback to local dictionary checks if API fails
        is_breached = password.lower() in COMMON_PASSWORDS or password in COMMON_PASSWORDS
        hibp_count = "API Offline (Local Check)" if is_breached else 0
        
    # 5. Entropy computation
    entropy, entropy_deductions = calculate_entropy(password)
    crack_times = estimate_crack_time(entropy)
    
    # --- WEIGHTED SCORING ENGINE ---
    score = 0
    score_details = []
    
    # Length > 12: +25 points
    if length > 12:
        score += 25
        score_details.append("Length > 12 (+25)")
    else:
        # Partial credit
        if length >= 8:
            score += 15
            score_details.append("Length 8-12 (+15)")
        else:
            score += 5
            score_details.append("Length < 8 (+5)")
            
    # Complexity elements
    if has_upper:
        score += 15
        score_details.append("Uppercase present (+15)")
    if has_lower:
        score += 15
        score_details.append("Lowercase present (+15)")
    if has_digit:
        score += 15
        score_details.append("Numbers present (+15)")
    if has_special:
        score += 20
        score_details.append("Symbols present (+20)")
        
    # High entropy: +20 points (scaled up to 60 bits)
    entropy_contrib = min(20, round((entropy / 60) * 20, 1))
    score += entropy_contrib
    score_details.append(f"Entropy contribution (+{entropy_contrib})")
    
    # PENALTY DEDUCTIONS
    # Common password: -40
    if is_breached or (password.lower() in COMMON_PASSWORDS):
        score -= 40
        score_details.append("Common breached password (-40)")
    # Sequential: -20
    if seq_patterns:
        score -= 20
        score_details.append("Sequential sequences (-20)")
    # Repeated chars: -20
    if rep_patterns:
        score -= 20
        score_details.append("Repeated characters (-20)")
    # Reused password: -30
    if is_previously_used:
        score -= 30
        score_details.append("Reused password history (-30)")
        
    # Clamp final score to [0, 100]
    score = max(0, min(100, int(score)))
    
    # Map final score to categories
    if length < 8 or is_breached:
        rating = "Weak"
    elif score < 45:
        rating = "Weak"
    elif score < 70:
        rating = "Medium"
    elif score < 85:
        rating = "Strong"
    else:
        rating = "Very Strong"
        
    # Build pattern weakness explanations
    pattern_weaknesses = []
    if detected_words:
        pattern_weaknesses.append(f"Contains common word/name: '{detected_words[0]}'")
    if seq_patterns:
        pattern_weaknesses.append(f"Contains sequence/keyboard walk: '{seq_patterns[0]}'")
    if rep_patterns:
        pattern_weaknesses.append(f"Contains repeated characters: '{rep_patterns[0]}'")
    if has_year:
        pattern_weaknesses.append(f"Contains year pattern: '{has_year.group(0)}'")
    if has_leet:
        pattern_weaknesses.append("Uses common character substitutions (l33tspeak)")
        
    # Build suggestions
    suggestions = []
    if length < 12:
        suggestions.append("Increase length to at least 12 characters (16+ is ideal).")
    if not has_upper:
        suggestions.append("Add uppercase letters (A-Z).")
    if not has_lower:
        suggestions.append("Add lowercase letters (a-z).")
    if not has_digit:
        suggestions.append("Add numbers (0-9).")
    if not has_special:
        suggestions.append("Add special characters or punctuation (e.g., @, #, $, %).")
    if seq_patterns:
        suggestions.append("Avoid sequential letters, numbers, or keyboard rows.")
    if rep_patterns:
        suggestions.append("Avoid repeating characters sequentially.")
    if is_breached:
        suggestions.append(f"CRITICAL: Found in Have I Been Pwned breach database ({hibp_count} times). Choose another password!")
    if is_previously_used:
        suggestions.append("WARNING: This password hash was committed to your history. Avoid reusing it.")
    if has_leet:
        suggestions.append("Avoid obvious leetspeak substitutions (e.g. '@' for 'a', '0' for 'o'), as standard attack tools easily decode them.")
        
    if not suggestions:
        suggestions.append("Excellent password! It meets all dynamic security audit guidelines.")
        
    alternative = generate_strong_alternative(password)
    
    return {
        "password_length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_special": has_special,
        "sequential_patterns": seq_patterns,
        "repeated_characters": rep_patterns,
        "is_breached": is_breached,
        "hibp_count": hibp_count,
        "is_previously_used": is_previously_used,
        "entropy": entropy,
        "entropy_deductions": entropy_deductions,
        "crack_times": crack_times,
        "score": score,
        "score_details": score_details,
        "rating": rating,
        "suggestions": suggestions,
        "alternative": alternative,
        "pattern_weaknesses": pattern_weaknesses
    }
