from pathlib import Path
p=Path(__file__).with_name("coverage_index.py")
s=p.read_text()
i=s.index("TAGS={")
j=s.index("\nCOMPILED=",i)
bs=chr(92)
before=s[i:j]
after=before.replace(bs+bs,bs)
assert before!=after
p.write_text(s[:i]+after+s[j:])
print("REGEX_PATTERNS_FIXED",before.count(bs+bs),"doubled escape spans")
