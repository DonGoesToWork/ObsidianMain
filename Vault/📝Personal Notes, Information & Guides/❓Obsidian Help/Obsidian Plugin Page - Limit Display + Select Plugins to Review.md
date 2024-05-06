Obsidian Git:
https://github.com/denolehov/obsidian-git

Flashcard Plugin:
https://github.com/st3v3nmw/obsidian-spaced-repetition

Table Plugin:
https://github.com/tgrosinger/advanced-tables-obsidian

Omnisearch:
https://github.com/scambier/obsidian-omnisearch



Filter Plugins to only show one's with more than 50k downloads.

```javascript
// Find all elements with content at or above 100,000 and containing the word 'downloads', and highlight them
[...document.querySelectorAll('*')].forEach(element => {
	if (!(element.className === "u-muted")) {
    return;
  }

  const elementContent = element.textContent.replace(/\D/g, ''); // Remove all non-numeric characters
  if (elementContent !== '' && parseInt(elementContent) < 50000) {
    element.parentElement.parentElement.hidden = true;
  }
});
```

https://obsidian.md/plugins