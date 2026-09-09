"use strict";
const form = document.getElementById("lab-form");
const button = document.getElementById("lab-button");
const progress = document.getElementById("lab-progress");
form.addEventListener("submit", () => { button.disabled = true; progress.hidden = false; });
window.addEventListener("pageshow", () => { button.disabled = false; progress.hidden = true; });
