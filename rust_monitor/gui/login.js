function login() {
    const username = document.getElementById("username").value.trim();

    if (!username) return;

    localStorage.setItem("username", username);

    if (username.toLowerCase() === "admin") {
        window.location.href = "http://localhost:3000/";
    } else {
        window.location.href = "/dashboard.html";
    }
}