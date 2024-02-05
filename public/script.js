document.addEventListener("DOMContentLoaded", function () {
  // Get all elements with the class "section-toggle"
  var sectionToggles = document.querySelectorAll(".section-toggle");

  // Add click event listeners to each section toggle
  sectionToggles.forEach(function (toggle) {
    toggle.addEventListener("click", function () {
      // Toggle the "is-open" class on the parent element (.mb-3)
      this.parentNode.classList.toggle("is-open");
    });
  });
});
