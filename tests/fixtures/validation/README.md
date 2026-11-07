# Validation Set (public)

These are the organizers' public Validation Set files, released at kickoff, copied unchanged from `RSH2026_public_validation_set.zip`. NFR-10 requires them in the repo as test fixtures.

- `V1`–`V6b`: nmap XML scans (`nmap -sS -sU -sV --script http-title -oX`).
- `V7_broken.xml`: deliberately truncated. The tool must report `ERROR` and continue with the other files.
- `expected_findings.csv`: the answer key, with 24 rows. Rows are sorted by file, then IP, then port number, then finding code.
- `expected_scores.csv`: expected network scores, with `ERROR` for V7.

Don't edit these files. The golden test (#17) compares our output with them byte for byte.
