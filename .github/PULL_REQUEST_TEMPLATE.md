## What and why

<!-- What does this change do, and why is it needed? Link related issues: "Closes #123". -->

## How it was tested

<!-- Commands you ran, platforms, manual checks. -->

## Roadmap

<!-- Task IDs from docs/ROADMAP.md, for example F-5. Write "none" if not applicable. -->

## Risks

<!-- What could break? Anything reviewers should look at closely? -->

## Checklist

- [ ] Tests added or updated
- [ ] No secrets end up in output, logs, exception messages or `ToString()`
- [ ] `dotnet publish src/SafeNook.Cli -c Release -r <rid>` (native AOT) passes without warnings
- [ ] `docs/ROADMAP.md` updated (task checkbox ticked)
- [ ] For vault format or cryptography changes: ADR added or `docs/vault-format.md` updated
