#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/stdarg.h>

static unsigned long ksu_lookup(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;
    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

#define DEFINE_SHIM(ret, name, args, call) \
    typedef ret (*fn_##name) args; \
    static fn_##name ptr_##name; \
    ret name args { \
        if (!ptr_##name) ptr_##name = (fn_##name)ksu_lookup(#name); \
        return ptr_##name ? ptr_##name call : (ret)0; \
    }

#define DEFINE_SHIM_VOID(name, args, call) \
    typedef void (*fn_##name) args; \
    static fn_##name ptr_##name; \
    void name args { \
        if (!ptr_##name) ptr_##name = (fn_##name)ksu_lookup(#name); \
        if (ptr_##name) ptr_##name call; \
    }

DEFINE_SHIM_VOID(sidtab_destroy, (void *s), (s))
DEFINE_SHIM(int, mls_context_to_sid, (void *p, char oldc, char *scontext, void *context, void *s, u32 def_sid), (p, oldc, scontext, context, s, def_sid))
DEFINE_SHIM(int, policydb_context_isvalid, (void *p, void *c), (p, c))
DEFINE_SHIM(int, sidtab_context_to_sid, (void *s, void *context, u32 *sid), (s, context, sid))
DEFINE_SHIM_VOID(ebitmap_destroy, (void *e), (e))
DEFINE_SHIM(void *, sidtab_search_entry, (void *s, u32 sid), (s, sid))
DEFINE_SHIM(int, sidtab_sid2str_get, (void *s, void *entry, char **out, u32 *out_len), (s, entry, out, out_len))
DEFINE_SHIM(u32, mls_compute_context_len, (void *p, void *context), (p, context))
DEFINE_SHIM_VOID(mls_sid_to_context, (void *p, void *context, char **scontext), (p, context, scontext))
DEFINE_SHIM_VOID(sidtab_sid2str_put, (void *s, void *entry, int locked), (s, entry, locked))
DEFINE_SHIM(int, cond_compute_av, (void *ctab, void *key, void *avd, void *xperms), (ctab, key, avd, xperms))
DEFINE_SHIM(int, ebitmap_cmp, (const void *e1, const void *e2), (e1, e2))
DEFINE_SHIM(int, ebitmap_contains, (const void *e1, const void *e2, u32 last_e2bit), (e1, e2, last_e2bit))
DEFINE_SHIM(int, cap_capable, (const void *cred, void *ns, int cap, unsigned int opts), (cred, ns, cap, opts))
DEFINE_SHIM(bool, inode_owner_or_capable, (struct user_namespace *mnt_userns, const struct inode *inode), (mnt_userns, inode))
DEFINE_SHIM(void *, audit_log_start, (void *ctx, gfp_t gfp_mask, int type), (ctx, gfp_mask, type))
DEFINE_SHIM_VOID(audit_log_n_untrustedstring, (void *ab, const char *string, size_t len), (ab, string, len))
DEFINE_SHIM_VOID(audit_log_end, (void *ab), (ab))
DEFINE_SHIM(int, security_validate_transition, (void *state, u32 oldsid, u32 newsid, u32 tasksid, u16 tclass), (state, oldsid, newsid, tasksid, tclass))

typedef void (*fn_audit_log_vformat)(void *ab, const char *fmt, va_list args);
static fn_audit_log_vformat ptr_audit_log_vformat;
void audit_log_format(void *ab, const char *fmt, ...) {
    va_list args;
    if (!ptr_audit_log_vformat) ptr_audit_log_vformat = (fn_audit_log_vformat)ksu_lookup("audit_log_vformat");
    if (ptr_audit_log_vformat) {
        va_start(args, fmt);
        ptr_audit_log_vformat(ab, fmt, args);
        va_end(args);
    }
}
