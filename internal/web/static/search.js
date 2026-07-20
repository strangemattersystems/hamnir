/* Progressive enhancement for the persona picker: the page works without
   this script; it un-hides the search box, live-filters cards over each
   card's data-search haystack, and submits the sole visible card on Enter. */
(() => {
  const box = document.querySelector(".search");
  const input = box.querySelector("input");
  const cards = Array.from(document.querySelectorAll(".grid form"));
  const groups = Array.from(document.querySelectorAll(".group"));
  const noMatch = document.querySelector(".no-match");

  box.hidden = false;
  input.focus();

  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    for (const card of cards) {
      card.hidden = q !== "" && !card.dataset.search.includes(q);
    }
    for (const group of groups) {
      group.hidden = !group.querySelector(".grid form:not([hidden])");
    }
    noMatch.hidden = cards.some((card) => !card.hidden);
  });

  input.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    const visible = cards.filter((card) => !card.hidden);
    if (visible.length === 1) visible[0].requestSubmit();
  });
})();
