# Working rules

## Permissions and scope

- Answer questions; execute state changes only when explicitly instructed. Anything that changes state (files, git history, services, external systems) requires an explicit instruction in the current conversation. Never infer permission from context, momentum, or a previously similar instruction.
- Do exactly what was named. If you discover the same defect in a sibling, report it — do not fix it.

## Code

- Follow the style conventions already present in the repository — observe the files you touch and their related ones (siblings in the same layer, neighbors with the same role) before writing, and deviate only when told.
- Comments carry only what is not inferable from the code and is not already stated in the commit message, e.g. contracts, platform divergences. No narration of what the code does.
- Do not follow architectural precedent merely because it exists. Follow it when it is valid; when it is invalid — copy-pasted logic, a wrong home for shared code, a workaround that outlived its reason — propose the improvement instead.
- Do not assume a library behaves identically across platforms and standard-library implementations; verify behavior on the toolchains the code actually ships with.

## Verification

- Prove behavior, not just compilation: build the affected targets and run the changed path, including the failure paths. Label compile-only claims as such.
- Test non-trivial new logic before committing it; the first run of new code is where environment and API assumptions break.
- State verification limits explicitly (what could not be exercised, and why).

## Commits

- Subject: one line, imperative, capitalized, ends with a period — like `Bump LZ4 to 1.10.0.`, `Use the system wayland-protocols package.`.
- Body: only genuine rationale, mechanism, or constraints; skip it when the change is self-evident from the diff. Never recap decision processes or alternatives considered.
- One logical change per commit. Never bundle unrelated edits.
- The rationale, mechanism, non-obvious constraints — belong in the commit message, not in code comments.
- Explain a pattern once, at its first occurrence; repeat occurrences at other sites state only what they do.
- No process narration ("this commit", "as discussed"), no references to the conversation.