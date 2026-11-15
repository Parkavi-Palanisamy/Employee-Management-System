
const loginForm = document.getElementById("loginForm");
const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");
const message = document.getElementById("message");

if (togglePassword) {
    togglePassword.addEventListener("click", () => {
        const isPassword = passwordInput.type === "password";
        passwordInput.type = isPassword ? "text" : "password";
        togglePassword.textContent = isPassword ? "Hide" : "Show";
    });
}

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("username").value.trim();
    const password = passwordInput.value;

    message.textContent = "Checking login...";
    message.style.color = "#2563eb";

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.success) {
            message.textContent = "Login successful!";
            message.style.color = "green";
            window.location.href = data.redirect_url;
        } else {
            message.textContent = data.message;
            message.style.color = "red";
        }

    } catch (error) {
        message.textContent = "Unable to connect to server.";
        message.style.color = "red";
    }
});
