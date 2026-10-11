# docs/wiki

The source of the GitHub wiki (https://github.com/0xAndersen/witness-log/wiki).
Pages are plain Markdown with wiki-style links (`[Text](Page-Name)`), so
they render here on GitHub too. To publish them to the wiki:

```sh
# once: create any page in the wiki UI so the wiki repository exists, then
git clone https://github.com/0xAndersen/witness-log.wiki.git /tmp/wiki
rsync -a --delete --exclude .git --exclude README.md docs/wiki/ /tmp/wiki/
cd /tmp/wiki && git add -A && git commit -m "wiki: sync from docs/wiki" && git push
```

Edit here, not in the wiki UI, so the docs are reviewed with the code.
