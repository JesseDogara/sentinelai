"use strict";
const scanType = document.getElementById("scan_type");
const target = document.getElementById("target");
const help = document.getElementById("scan-help");
const reverse = document.getElementById("reverse-option");
const button = document.getElementById("scan-button");
const progress = document.getElementById("scan-progress");
const descriptions = {
  website: ["Website URL", "https://example.com", "Checks HTTPS and common security headers using a GET request. Website redirects are followed."],
  api: ["API URL or endpoint", "https://api.example.com/v1/status", "One GET without credentials or redirects. Response bodies are not inspected. Saved query values are redacted."],
  domain: ["Domain name", "example.com", "Reads A, AAAA, CNAME, MX, NS, TXT and CAA records for the exact name. No subdomain discovery. DNS queries use your configured resolver and have a 15-second total budget."],
  ip: ["IPv4 or IPv6 address", "127.0.0.1", "Explains the address locally. Enable reverse DNS to send one PTR query to your configured resolver. No ports or services are probed."]
};
function updateForm() {
  const [label, placeholder, description] = descriptions[scanType.value];
  document.getElementById("target-label").textContent = label;
  target.placeholder = placeholder;
  help.textContent = description;
  reverse.hidden = scanType.value !== "ip";
  reverse.querySelector("input").disabled = reverse.hidden;
}
scanType.addEventListener("change", updateForm);
scanType.form.addEventListener("submit", () => {
  button.disabled = true;
  button.textContent = "Assessing…";
  progress.hidden = false;
});
window.addEventListener("pageshow", () => {
  button.disabled = false;
  button.textContent = "Run assessment";
  progress.hidden = true;
  updateForm();
});
updateForm();
