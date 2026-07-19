# Stage-1 readability rubric 

Human / semi-auto checklist for recovered C quality. Use alongside
`token_similarity` from `ghidrust ghidra-headtohead` — Jaccard alone does not
capture expression nesting or naming.

## Scoring (per function)

Score each item 0 / 1. Report mean across a fixed function set.

| # | Check | Pass when |
|---|--------|-----------|
| 1 | **Expression nesting** | Fewer single-use `tN#v` / `reg#v` temps than SSA ops; compound `a + b * c` present when arithmetic chains exist |
| 2 | **Named calls** | Import / known function calls print as `Name()` not bare `sub_<addr>()` when the program has that symbol |
| 3 | **Typed locals** | Stack locals declared with non-`undefined` types when evidence exists |
| 4 | **Control flow** | Natural `if` / `while` / `switch` used; `goto_rate` for the function `< 0.15` preferred |
| 5 | **Early exit** | Early returns use `return` not `goto L_ret` when the target is a return block |
| 6 | **OO (when RTTI)** | Methods show `this` / class pointer; virtual calls annotated when vtable known |
| 7 | **Honesty** | No invented structs/enums; `/* unimplemented */` left for unlifted ops |

## How to run

1. Pick N functions from a fixture PE (or shared-entry head-to-head set).
2. `ghidrust decompile <bin> --addr <va> --json` — inspect `pseudo_c`, `folded_temps`, `goto_rate`.
3. Optional: `ghidrust ghidra-headtohead …` for `token_similarity`.
4. Fill the table; track mean score over time. Do **not** claim Hex-Rays parity from this rubric alone.

## Fixture themes (expand under `fixtures/`)

- Expression-heavy arithmetic
- Call-heavy (imports)
- Loop / switch
- Float/XMM (`movss` / `movsd` notes)
- One medium public PE slice (no private install paths in docs)
