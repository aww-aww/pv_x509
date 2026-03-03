## 2025-02-14 - Optimize regex initialization in hot path
**Learning:** Re-evaluating regular expressions for split operations or global matches (e.g. `split(new RegExp(rEolGroup, "g"))`) inside loops in JavaScript has overhead. The `X509Certificate` often requires checking PEMs, and the conversion is heavily used.
**Action:** Create pre-compiled module-level global regular expression objects. Reset `lastIndex = 0` between uses. Prefer fast native string methods `indexOf(":")` and `split("\n")` instead of regular expressions for structured multi-line parsing.
