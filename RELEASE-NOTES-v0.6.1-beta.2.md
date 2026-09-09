# BC Sentinel v0.6.1-beta.2

Windows installer ACL bootstrap fix.

- Harden the Program Files root once, then reset descendants to inherit the hardened ACL.
- Avoid recursive `(OI)(CI)` grant application to frozen files after inheritance removal.
- Validate deployment ACLs with `icacls /verify`.
- Fail loudly and print the deployed EXE ACL when bootstrap execution fails.
- Apply the same inheritance-safe strategy to ProgramData children.
- Recover and remove a stranded prior BC Sentinel Program Files tree if beta.1 left unusable ACLs.
- Preserves v0.6.1-beta.1 NTFS ChangeTime integrity-cache fix.
