const loginForm = document.getElementById("login-form");
const resetPasswordForm = document.getElementById("reset-password-form");
const registerForm = document.getElementById("register-form");

async function isPasswordCompromised(password) {
    const hash = await generateSHA1Hash(password);
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
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

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    try {
        const response = await fetch("http://localhost:3000/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });

        const result = await response.json();
        document.getElementById("login-result").innerText =
            response.ok ? result.message : result.error;
    } catch (error) {
        console.error("Error during login:", error);
        document.getElementById("login-result").innerText = "Login failed.";
    }
});

// Helper function to validate passwords
function isPasswordValid(password) {
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
    return passwordRegex.test(password);
}


registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("reg-username").value;
    const password = document.getElementById("reg-password").value;

    // Validate password before sending the request
    if (!isPasswordValid(password)) {
        document.getElementById("register-result").innerText =
            "Senha deve ter 6 ou mais caracteres alfanuméricos.";
        return;
    }

    // Check if the password is compromised
    try {
        const isCompromised = await isPasswordCompromised(password);
        if (isCompromised) {
            document.getElementById("register-result").innerText =
                'Password has been compromised. Please choose a different one.';
            return; // Exit if the password is compromised
        } else {
            console.log('Password is secure.');
        }
    } catch (error) {
        console.error("Error checking password:", error);
        document.getElementById("register-result").innerText = "Error checking password.";
        return; // Exit if there was an error checking the password
    }

    // Proceed with registration if the password is secure
    try {
        const response = await fetch("http://localhost:3000/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });

        const result = await response.json();
        document.getElementById("register-result").innerText =
            response.ok ? result.message : result.error;
    } catch (error) {
        console.error("Error during registration:", error);
        document.getElementById("register-result").innerText = "Registration failed.";
    }
});

resetPasswordForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("reset-username").value;
    const newPassword = document.getElementById("new-password").value;

    // Validate password before sending the request
    if (!isPasswordValid(newPassword)) {
        document.getElementById("reset-result").innerText =
            "Senha deve ter 6 ou mais caracteres alfanuméricos.";
        return;
    }

    // Check if the new password is compromised
    try {
        const isCompromised = await isPasswordCompromised(newPassword);
        if (isCompromised) {
            document.getElementById("reset-result").innerText =
                'Password has been compromised. Please choose a different one.';
            return; // Exit if the password is compromised
        } else {
            console.log('Password is secure.');
        }
    } catch (error) {
        console.error("Error checking password:", error);
        document.getElementById("reset-result").innerText = "Error checking password.";
        return; // Exit if there was an error checking the password
    }

    // Proceed with password reset if the new password is secure
    try {
        const response = await fetch("http://localhost:3000/reset-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, newPassword }),
        });

        const result = await response.json();
        document.getElementById("reset-result").innerText =
            response.ok ? result.message : result.error;
    } catch (error) {
        console.error("Error during password reset:", error);
        document.getElementById("reset-result").innerText = "Password reset failed.";
    }
});

