/**
 * Login View Controller
 * Handles challenge-response login submission and alert UI.
 */
document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("login-form");
    const btn = document.getElementById("btn-login");
    const spinner = document.getElementById("spinner");
    const alertBox = document.getElementById("alert-box");

    if (!form) return;

    function showAlert(msg, isError = true) {
        if (!alertBox) return;
        alertBox.textContent = msg;
        alertBox.className = "alert " + (isError ? "alert-error" : "alert-success");
        alertBox.classList.remove("hidden");
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (alertBox) alertBox.classList.add("hidden");
        if (btn) btn.disabled = true;
        if (spinner) spinner.classList.remove("hidden");

        const usernameInput = document.getElementById("username");
        const passwordInput = document.getElementById("password");
        const username = usernameInput ? usernameInput.value.trim() : "";
        const password = passwordInput ? passwordInput.value : "";

        try {
            await executeChallengeResponseLogin(username, password);
            showAlert("Authentication successful! Redirecting...", false);
            setTimeout(() => {
                window.location.href = "/dashboard";
            }, 600);
        } catch (err) {
            showAlert(err.message || "Authentication failed. Please verify credentials.", true);
            if (btn) btn.disabled = false;
            if (spinner) spinner.classList.add("hidden");
        }
    });
});

