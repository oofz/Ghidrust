# Region construction growth and lossless fallback

The first stack-overflow fix bounded recursive structuring, but a subsequent
SQLite validation run exposed a separate failure: region construction could
still grow combinatorially. Switch cases and converging branches rebuilt shared
destinations and large subgraphs instead of reusing them. One 54-block function
expanded to 11,105 region leaves and over 21 MiB of pseudocode; several workers
then exhausted their memory budget.

The fix tracks visited destinations across switch cases, selects the nearest
common post-dominator for converging branches, and charges region construction
against a per-function budget before expensive expansions. When structuring
exceeds that budget, the partial tree is discarded and the renderer emits the
complete reachable CFG as labeled blocks with explicit goto edges. The fallback
retains every reachable block and edge; it does not truncate pseudocode.

Synthetic regressions cover successive diamonds, switches with common
destinations, nested loops, irreducible control flow, multiple convergences, and
deep graphs. They check block and edge preservation. The structural crate's
19 tests and core's 142 library tests pass under the Windows memory watchdog.

The SQLite audit also found a distinct function-boundary bug: the PE function
start pass used a linear `grow_function` result that stopped at the first
`ret`, even when `.pdata` supplied an authoritative later end. That shrank
functions and allowed false starts inside them. The function-start pass now
preserves exact `.pdata` ends and overlapping runtime-function records; batch
disassembly uses those exact bounds. Inferred function bounds retain their
previous linear behavior. A regression fixture verifies an early `ret` does not
shorten the `.pdata` range.

The batch JSONL distinguishes structured success, complete unstructured
fallback, partial output caused by the instruction cap, and failure. The
fallback remains reviewable as low-level control flow rather than presenting a
partial structured tree as complete.
