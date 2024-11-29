make aes debug const loginForm = document.getElementById("login-form");
const resetPasswordForm = document.getElementById("reset-password-form");
const registerForm = document.getElementById("register-form");

// Gera uma chave AES de 256 bits
async function generateAESKey() {
    return crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Converte uma string para ArrayBuffer
function stringToArrayBuffer(str) {
    return new TextEncoder().encode(str);
}

// Converte um ArrayBuffer para Base64
function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// Criptografa os dados usando AES-GCM
async function encryptData(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // Vetor de inicialização
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        stringToArrayBuffer(data)
    );
    return {
        iv: arrayBufferToBase64(iv),
        ciphertext: arrayBufferToBase64(encrypted),
    };
}

// Inicializa a chave AES
let aesKey;
generateAESKey().then(key => aesKey = key);

// Validação de senha
function isPasswordValid(password) {
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
    return passwordRegex.test(password);
}

// Verifica se a senha foi comprometida
async function isPasswordCompromised(password) {
    const hash = await generateSHA1Hash(password);
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);

    const response = await fetch(https://api.pwnedpasswords.com/range/${prefix});
    const data = await response.text();

    const isCompromised = data.split('\r\n').some(line => line.startsWith(suffix));
    return isCompromised;
}

function generateSHA1Hash(password) {
    return crypto.subtle.digest('SHA-1', new TextEncoder().encode(password))
        .then(buffer => Array.from(new Uint8Array(buffer))
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('')
        );
}

// Lida com o formulário de login
loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    try {
        const { iv, ciphertext } = await encryptData(password, aesKey);

        const response = await fetch("http://localhost:3000/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, iv, password: ciphertext }),
        });

        const result = await response.json();
        document.getElementById("login-result").innerText =
            response.ok ? result.message : result.error;
    } catch (error) {
        console.error("Error during login:", error);
        document.getElementById("login-result").innerText = "Login failed.";
    }
});

// Lida com o formulário de registro
registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("reg-username").value;
    const password = document.getElementById("reg-password").value;

    if (!isPasswordValid(password)) {
        document.getElementById("register-result").innerText =
            "Senha deve ter 6 ou mais caracteres alfanuméricos.";
        return;
    }

    try {
        const isCompromised = await isPasswordCompromised(password);
        if (isCompromised) {
            document.getElementById("register-result").innerText =
                'Password has been compromised. Please choose a different one.';
            return;
        }

        const { iv, ciphertext } = await encryptData(password, aesKey);

        const response = await fetch("http://localhost:3000/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, iv, password: ciphertext }),
        });

        const result = await response.json();
        document.getElementById("register-result").innerText =
            response.ok ? result.message : result.error;
    } catch (error) {
        console.error("Error during registration:", error);
        document.getElementById("register-result").innerText = "Registration failed.";
    }
});

// Lida com o formulário de redefinição de senha
resetPasswordForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("reset-username").value;
    const newPassword = document.getElementById("new-password").value;

    if (!isPasswordValid(newPassword)) {
        document.getElementById("reset-result").innerText =
            "Senha deve ter 6 ou mais caracteres alfanuméricos.";
        return;
    }

    try {
        const isCompromised = await isPasswordCompromised(newPassword);
        if (isCompromised) {
            document.getElementById("reset-result").innerText =
                'Password has been compromised. Please choose a different one.';
            return;
        }

        const { iv, ciphertext } = await encryptData(newPassword, aesKey);

        const response = await fetch("http://localhost:3000/reset-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, iv, password: ciphertext }),
        });

        const result = await response.json();
        document.getElementById("reset-result").innerText =
            response.ok ? result.message : result.error;
    } catch (error) {
        console.error("Error during password reset:", error);
        document.getElementById("reset-result").innerText = "Password reset failed.";
    }
});
