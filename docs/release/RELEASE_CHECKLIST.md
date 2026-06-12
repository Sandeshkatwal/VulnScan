# Release Checklist

- [ ] Backend tests pass.
- [ ] Dashboard build passes.
- [ ] Demo data safety check passes.
- [ ] Evidence redaction tests pass.
- [ ] No secrets in repository.
- [ ] README links checked.
- [ ] Screenshots updated or screenshot placeholders documented.
- [ ] Demo walkthrough tested.
- [ ] GitHub Actions pass.
- [ ] Version tag created.
- [ ] Release notes written.

## Verification Commands

```powershell
.\.venv311\Scripts\python.exe -m pytest
.\.venv311\Scripts\python.exe scripts\check_demo_safety.py
.\.venv311\Scripts\python.exe scripts\verify_release.py
.\.venv311\Scripts\python.exe scripts\check_docs_links.py
cd dashboard
npm run build
```

