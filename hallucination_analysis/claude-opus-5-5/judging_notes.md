# Judging conventions (claude-opus-5-5)

How `../prompt.md` was applied in borderline cases. A second judge given only `prompt.md` may
decide some of these differently; compare on these cases first.

1. **Facts copied from the description are "supported"**, even when the snippet shows nothing of
   them (versions, patch hashes, VDB IDs, "attack can be launched remotely", recommended upgrade).
   Such pairs get `answerable_from_code = false`.
2. **`answerable_from_code` depends on this snippet.** If the snippet does not contain the flaw
   (unrelated test, helper or neighbouring function), questions about the flaw's type, cause or
   location are `false`. Questions about what the shown code does are `true`.
3. **Location answers** are judged against the code. Pointing to code that is present but is not
   plausibly the flaw is "contradicted" (`wrong_location`). File or function names copied from the
   description, without pointing into the code, are "supported" with `answerable_from_code = false`.
   Answers saying there is no specific line are "supported" when the flaw is indeed not in the
   snippet, and "unsupported" (`generic_or_evasive`) when the flawed line is visible.
4. **Saying the snippet is unrelated** is "supported" when that is true.
5. **Fix answers** are "supported" when they point at the actual flaw, even if worded vaguely;
   "unsupported" (`generic_or_evasive`) when they are generic advice without naming what to check
   or change; "contradicted" (`inapplicable_fix`) when they could not work (e.g. try-except in C).
6. **Severity**: an invented level (Medium, High) next to an otherwise correct answer is
   "partly_supported" (`unfounded_severity`); a severity answer that only repeats the impact is
   "unsupported" (`generic_or_evasive`). "Rated as critical" in the description is support.
7. **Line numbers** cannot be derived from a snippet; an answer giving them is "unsupported"
   (`invented_identifier`).
8. **Meta-questions** about the snippet ("is the source code provided?", "is this test related?")
   count as relevant, since they are about the code.
9. An answer that **attributes the described vulnerability to "the provided code"** while naming
   the described function is "supported" (it names the right function); one that instead names a
   function from the snippet as the flaw is a location error.

## What Claude saw

Batch 0 was read in full from `../batches/batch_000.txt`. From batch 1 on, records were read through
`../judge_view.py`: code over 150 lines shows its first 110 and last 40 lines, and each answer is
followed by the identifiers it names that occur nowhere in the full code. Another judge should be
given the full batch files, as `prompt.md` assumes.
