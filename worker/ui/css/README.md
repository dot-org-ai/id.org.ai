# Component CSS modules

`build:ui` concatenates `../tokens.css`, `../ui.css`, then every `*.css` here
(sorted) into `/auth/ui.<hash>.css`. Use a module for a component family
(for example `signin.css` for the sign-in screens' own components); shared
components live in `../ui.css`. Tokens only: a test fails on any colour literal.
