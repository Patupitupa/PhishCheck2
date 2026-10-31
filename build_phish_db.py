# ===== Build phish.db: known-phishing links for the app's lookup step =====
# Run in the BasicTests notebook AFTER the helper cells (canon, root_domain, extract_domain,
# TRANCO_SET, SHORTENER_DOMAINS must exist). Upload the CSVs to Colab first.
import os, sqlite3
import pandas as pd

# (file, url column, label column, label value that means PHISH)
SOURCES = [
    ("dataset4.csv",               "url", "label", 1),   # dataset2 convention: 1 = phish
    ("Mixed_Phishing_dataset.csv", "url", "label", 0),   # Mixed convention:    0 = phish
]
# phiusiil_holdout.csv is deliberately NOT a source, so it stays a clean test of the model.
DB_FILE = "phish.db"
MAX_LEN = 2048                                            # same cap as the app's input check

parts = []
for path, ucol, lcol, phish_val in SOURCES:
    d = pd.read_csv(path, encoding="latin1", on_bad_lines="skip")
    d.columns = [str(c).replace("\ufeff", "").strip().lower() for c in d.columns]
    d = d.dropna(subset=[ucol, lcol])
    d = d[d[lcol].astype(int) == phish_val].copy()
    d["u"] = d[ucol].astype(str).map(canon)
    d["src"] = os.path.basename(path)
    pop = d["u"].map(lambda u: root_domain(extract_domain(u)) in TRANCO_SET).mean()
    print(f"{path}: {len(d):,} phish rows | Tranco-popular share {pop:.2f} (phish should be well under 0.6)")
    if pop > 0.6:
        raise ValueError(f"{path}: these rows look LEGIT, not phish. Check the label value in SOURCES.")
    parts.append(d[["u", "src"]])

db = pd.concat(parts).drop_duplicates("u")
n0 = len(db)

# same junk filters as training, plus a length cap
db = db[~(db["u"].str.contains("@") & ~db["u"].str.contains("/"))]
db = db[db["u"].str.contains(r"\.") & (db["u"].str.len() <= MAX_LEN)]

# never store a bare popular/shortener domain (would flag google.com, bit.ly ...)
root = db["u"].map(lambda u: root_domain(extract_domain(u)))
bare = ~db["u"].str.contains("/") & ~db["u"].str.contains(r"\?", regex=True)
drop = bare & (root.isin(TRANCO_SET) | root.isin(SHORTENER_DOMAINS))
print("dropped bare popular/shortener entries:", int(drop.sum()))
db = db[~drop]
print(f"entries: {n0:,} before filters -> {len(db):,} kept")
print("entries on Tranco-popular domains (exact links, kept):", int(root[db.index].isin(TRANCO_SET).sum()))

if os.path.exists(DB_FILE):
    os.remove(DB_FILE)
con = sqlite3.connect(DB_FILE)
con.execute("CREATE TABLE phish (url TEXT PRIMARY KEY, src TEXT) WITHOUT ROWID")
con.executemany("INSERT INTO phish (url, src) VALUES (?, ?)",
                db[["u", "src"]].itertuples(index=False, name=None))
con.commit()
con.execute("VACUUM")

# sanity checks: a stored link is found, google.com is not
sample = db["u"].iloc[0]
found = con.execute("SELECT 1 FROM phish WHERE url = ?", (sample,)).fetchone() is not None
google = con.execute("SELECT 1 FROM phish WHERE url = ?", (canon("https://www.google.com/"),)).fetchone() is not None
print("rows in table:", con.execute("SELECT COUNT(*) FROM phish").fetchone()[0])
print("sample found:", found, "| google.com found (must be False):", google)
con.close()
print("size MB:", round(os.path.getsize(DB_FILE) / 1e6, 1), "(GitHub web upload limit is 25 MB)")

try:
    from google.colab import files
    files.download(DB_FILE)
except ImportError:
    pass
