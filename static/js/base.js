/**
 * Global Base Functionality & Session Teardown
 * Complies with strict CSP by binding event listeners without inline handlers.
 */
async function handleLogout() {
    try {
        const match = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
        const csrfToken = match ? decodeURIComponent(match[1]) : "";
        await fetch("/api/auth/logout", {
            method: "POST",
            headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {}
        });
        window.location.href = "/login";
    } catch (err) {
        window.location.href = "/login";
    }
}

document.addEventListener("DOMContentLoaded", () => {
    // Bind all logout buttons across navigation, dashboard, and admin console
    const logoutButtons = document.querySelectorAll(
        ".btn-nav-logout, .btn-dashboard-logout, .btn-admin-logout, .btn-logout, #btn-nav-logout"
    );
    logoutButtons.forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.preventDefault();
            handleLogout();
        });
    });
});

