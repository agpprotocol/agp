# Go TPE Phase 4.1F Duty Separation and Mutual Exclusion

This increment ports `separation_of_duties` and `mutual_exclusion`.

`separation_of_duties` evaluates exactly two canonical participant roles over
the authorized and role-eligible signer projection. `mutual_exclusion` rejects
simultaneous presence of two canonical signer identities while allowing zero
or one of them.
