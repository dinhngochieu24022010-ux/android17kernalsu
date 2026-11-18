import glob, re
for p in glob.glob("/home/runner/KernelSU/kernel/**/*.c", recursive=True):
    txt = open(p).read()
    orig = txt
    txt = re.sub(r"void\s+ksu_lsm_hook_init\s*\([^)]*\)\s*\{", "void ksu_lsm_hook_init(void) { return;", txt)
    txt = re.sub(r"int\s+ksu_lsm_hook_init\s*\([^)]*\)\s*\{", "int ksu_lsm_hook_init(void) { return 0;", txt)
    if txt != orig:
        open(p, "w").write(txt)
        print("PATCHED_NO_PANIC:", p)
