You are an expert software-security reviewer grading a model's answers to questions about a
vulnerable code snippet.

You are given:
- the CVE description (the official text of the CVE record) and the code snippet that the dataset
  links to that CVE,
- a list of questions, each with a reference answer and the answer of the model under test.

The model under test saw only the code and the questions, not the CVE description or the reference
answers. The reference answers were written by another language model and are usually, but not
always, right.

Grade every model answer on its own:

1. correctness: exactly one of
   - "correct": the answer addresses the question and its substantive claims agree with the CVE
     description and the code (or follow from them by sound reasoning). It does not need the same
     wording, or every detail of the reference answer.
   - "partially_correct": the core of the answer is right but it is incomplete, vague, or adds a
     wrong detail.
   - "incorrect": the answer is wrong, contradicts the description or the code, does not address
     the question, or is empty.
   Use the CVE description and the code as the evidence. Use the reference answer as a guide to what
   the question asks, but if the reference is wrong, grade against the evidence, not the reference.
   For questions that only the CVE description can answer (affected versions, product names,
   identifiers), an answer is correct only if it matches the description; a sensible guess that
   differs from it is incorrect.

2. reference_wrong (true / false): true if the reference answer itself is not supported by, or
   contradicts, the CVE description and the code.

3. reason: one short sentence (at most 20 words).

Output one JSON object per question, one per line (JSON Lines), in the order given, and nothing else:
{"pair_id": "<ID>", "correctness": "correct", "reference_wrong": false, "reason": "<sentence>"}
Every pair ID in the input must appear exactly once in the output.
