const toggle = document.querySelector(".toggle");
const menu = document.querySelector(".menu");

// Toggle mobile menu
function toggleMenu() {
    if (menu.classList.contains("active")) {
        menu.classList.remove("active");

        // adds menu icon
        toggle.querySelector("a").innerHTML = "<i class='fas fa-bars'></i>"
    } else {
        menu.classList.add("active");
        // adds close (x) icon
        toggle.querySelector("a").innerHTML = "<i class='fas fa-times'></i>"
    }
}

// Event listener
toggle.addEventListener("click", toggleMenu, false);