const loginForm = document.getElementById("login-form");
const resetPasswordForm = document.getElementById("reset-password-form");

// Handle login
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

const registerForm = document.getElementById("register-form");

// Handle user registration
registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("reg-username").value;
    const password = document.getElementById("reg-password").value;

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
// Handle password reset
resetPasswordForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("reset-username").value;
    const newPassword = document.getElementById("new-password").value;

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
