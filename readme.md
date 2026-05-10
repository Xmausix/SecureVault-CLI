
---

## Commit Order

```bash
git init
git add .gitignore requirements.txt
git commit -m ‘init project structure’

git add database.py
git commit -m ‘add sqlite support with vault config and credentials tables’

git add crypto.py
git commit -m ‘implement fernet encryption with pbkdf2 key derivation’

git add password_generator.py
git commit -m ‘add cryptographically secure password generator’

git add main.py
git commit -m ‘add cli commands: init, add, list, show, generate’

git add README.md
git commit -m ‘add readme with usage and security documentation’
```