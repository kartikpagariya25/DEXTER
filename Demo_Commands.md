# Dexter Demo Commands

Run from `F:\Dexter-CLI`. Paste one block at a time.

> **Check before running:** you typed `MailJion` as the repo name — this looks
> like it might be a typo (possibly "MailJi" merged with "on"). Confirm the
> real repo URL before the demo and fix Step 3 below if needed.

---

## 1. Scan CampusHub (local vulnerable demo codebase)

```powershell
dexter --target "F:\campushub" -n --run-name demo-campushub
```

```powershell
dexter report demo-campushub --format human
```

---

## 2. Scan CardioXAI (GitHub repo)

```powershell
dexter --target https://github.com/VikrantKadam028/CardioXAI -n --run-name demo-cardioxai-repo
```

```powershell
dexter report demo-cardioxai-repo --format human
```

---

## 3. Scan MailJi (GitHub repo)

```powershell
dexter --target https://github.com/VikrantKadam028/MailJion -n --run-name demo-mailji-repo
```

```powershell
dexter report demo-mailji-repo --format human
```

---

## 4. Scan the live site (cardio-xai.tech)

Live targets need explicit authorization first — do this once, before the demo:

```powershell
dexter authorize https://www.cardio-xai.tech/
```

Then the actual scan:

```powershell
dexter --target https://www.cardio-xai.tech/ -n --run-name demo-cardioxai-live
```

```powershell
dexter report demo-cardioxai-live --format human
```

---

## Optional — show all four runs quickly at the end

```powershell
dexter view demo-campushub
dexter view demo-cardioxai-repo
dexter view demo-mailji-repo
dexter view demo-cardioxai-live
```
