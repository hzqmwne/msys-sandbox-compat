# PowerShell scripts

- Write repository scripts for both Windows PowerShell 5.1 and PowerShell 7. Prefer shared syntax and APIs, and reuse the existing quoting and test process helpers when applicable.
- Save scripts containing non-ASCII text as UTF-8 with BOM so Windows PowerShell 5.1 reads them correctly. Write PSEC policy JSON as UTF-8 without BOM.
- Exercise new or changed script behavior in both shells with the smallest relevant check.
