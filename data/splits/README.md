# VulnCodeX splits

Five ways to split the dataset into train, validation and test, for different evaluation
questions. All are built from the released dataset (26,003 records, 119,118 question–answer pairs,
6,911 CVEs) by `pipeline/make_splits.py`. A split file lists **record ids only**; the records
themselves are in `../vulncodex.jsonl.gz`, and `vulncodex.load_split()` joins the two.

**If you are unsure, use `cve`.** It is the split the paper reports results on.

## Which split to use

| File | Question it answers | Train / validation / test records | Leakage |
|---|---|---|---|
| `cve.json` | How well does a model explain vulnerabilities it has not seen? | 20,832 / 2,595 / 2,576 | None |
| `temporal.json` | Does it work on CVEs disclosed after its training data (2023 or later)? | 21,437 / 2,656 / 1,910 | None |
| `cross_language.json` | Does knowledge from C, C++, PHP and JavaScript transfer to other languages? | 16,230 / 2,030 / 4,416 | None |
| `language/<Language>.json` | How well does it do on one language? | see below | None |
| `random.json` | Comparison with work that splits at random | 20,803 / 2,601 / 2,599 | **High** (see below) |

"Leakage" means that the same CVE or the same code snippet appears in both training and test data.

## How the splits are made

**Groups.** Records that share a CVE identifier or an identical code snippet are joined into one
group, and the joining is transitive: if record A shares a CVE with B, and B shares its snippet
with C, all three are one group. There are 6,545 groups. Every split except `random` keeps each
group in one split, so no CVE and no snippet appears in two splits. Splitting by CVE alone is not
enough, because 1,248 snippets are linked to more than one CVE.

**Balancing.** Groups are assigned so that each split has the same mix of sources (CVEfixes, Big-Vul),
languages and CVE years, and the same number of records per CVE, as the whole dataset. The
assignment is random but checked: 300 random orders are tried and the most balanced is kept. The
chosen seeds and the remaining imbalance are in `split_report.json`.

### `cve`: unseen vulnerabilities (recommended)

80 / 10 / 10% of the records; 5,531 / 687 / 693 CVEs. Source and language shares differ by less
than one percentage point between the splits.

### `temporal`: recent vulnerabilities

The test set is every group with a CVE from 2023 or later: 1,910 records of 567 CVEs (565 from 2023
or later, and 2 older CVEs that share code with them). The other groups are split 8:1 into train and
validation. Because most models were trained on data from before 2023, the test set limits the
advantage of having memorised CVE records.

The test set contains no Big-Vul records (Big-Vul CVEs date from 2019 or earlier), so its language mix
differs from the training data: C is 33% of the test set and 45% of the training set.

### `cross_language`: unseen languages

Train and validation contain only C, C++, PHP and JavaScript/TypeScript, the four largest
languages; the test set contains only the other languages: Java (29%), Python (29%), Ruby (22%),
Go (12%), C# (3%), Rust (2%) and a few rarer ones. Groups that contain both seen and unseen
languages are **left out** of this split (112 groups, 3,327 records), because keeping them would put
the same CVE in training and test. These records are in none of the three lists of
`cross_language.json`.

### `language/<Language>`: one language at a time

The records of one language, with the same assignment as `cve`, so these files never leak into
each other or into `cve`.

| File | Language | Train | Validation | Test |
|---|---|---|---|---|
| `C` | C | 9,281 | 1,161 | 1,155 |
| `PHP` | PHP | 3,228 | 405 | 408 |
| `Cpp` | C++ | 2,261 | 288 | 272 |
| `JavaScript_TypeScript` | JavaScript or TypeScript | 2,057 | 249 | 243 |
| `Java` | Java | 1,117 | 140 | 139 |
| `Python` | Python | 1,079 | 138 | 139 |
| `Ruby` | Ruby | 885 | 113 | 111 |
| `Go` | Go | 428 | 54 | 55 |

Only languages with at least 500 records have a file. C# (257 records) and Rust (99) would get
test sets of a few dozen records; they are in the test set of `cross_language`. Languages are
predicted from the code, so a few labels are wrong (estimated accuracy 98.8%); a C++ function that
uses no C++-specific syntax is labelled C.

### `random`: random records (not recommended for evaluation)

Records are shuffled within each source and language and cut 80 / 10 / 10. Groups are ignored, so
**85.9% of test records share their CVE with a training record, and 15.5% have an identical snippet
in training**. A model can score well on this test set by remembering training answers. It is
provided only for comparison with work that splits at random.

## Files

```
cve.json  temporal.json  cross_language.json  random.json   {"train": [ids], "validation": [ids], "test": [ids]}
language/<Language>.json                                   the same, per language
split_report.json   sizes, CVEs, source and language shares of every split; seeds; leakage
```

Ids are in dataset order. To load a split with its records:

```python
from vulncodex import load_split
test = load_split("cve", "test")               # list of records
c_train = load_split("language/C", "train")
```

To rebuild every split (about two minutes): `python pipeline/make_splits.py`. The output is
deterministic.
