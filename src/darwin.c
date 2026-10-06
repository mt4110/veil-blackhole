/* SDK-derived ABI boundary; no packet sender and no promiscuous request. */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/bpf.h>
#include <bsm/audit.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <libproc.h>
#include <unistd.h>
#include <stdlib.h>

int veil_single_threaded(void) { return pthread_is_threaded_np() ? EBUSY : 0; }

/* Refuse inherited non-stdio descriptors rather than blindly close host FDs. */
int veil_check_inherited(void) {
    int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (size <= 0 || size > 1048576) return EINVAL;
    /* proc_pidinfo sizes may grow; a full buffer is treated as ambiguous. */
    int capacity = size + (int)sizeof(struct proc_fdinfo) * 16;
    struct proc_fdinfo *entries = calloc(1, (size_t)capacity);
    if (!entries) return ENOMEM;
    int actual = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, entries, capacity);
    int error = 0;
    if (actual <= 0 || actual >= capacity || actual % sizeof(*entries)) {
        error = EINVAL;
    } else {
        for (size_t i = 0; i < (size_t)actual / sizeof(*entries); i++) {
            if (entries[i].proc_fd > 2) { error = EBUSY; break; }
        }
    }
    free(entries);
    return error;
}

/* Apple xnu bsd/net/bpf_private.h: absent from the public SDK.
 * Unsupported running kernels MUST fail rather than widen directions. */
#define VEIL_BIOCGDIRECTION _IOR('B', 138, int)
#define VEIL_BIOCSDIRECTION _IOW('B', 139, int)
#define VEIL_BPF_D_OUT 2

_Static_assert(sizeof(struct bpf_hdr) == 20, "classic Darwin header size");
_Static_assert(offsetof(struct bpf_hdr, bh_caplen) == 8, "caplen offset");
_Static_assert(offsetof(struct bpf_hdr, bh_datalen) == 12, "datalen offset");
_Static_assert(offsetof(struct bpf_hdr, bh_hdrlen) == 16, "hdrlen offset");
_Static_assert(offsetof(struct bpf_hdr, bh_hdrlen) + sizeof(u_short) == 18,
    "classic Darwin wire header ends at byte 18, not sizeof(struct bpf_hdr)");
_Static_assert(BPF_ALIGNMENT == 4, "classic Darwin alignment");
_Static_assert(sizeof(struct bpf_insn) == 8, "filter instruction size");

int veil_audit_uid(uint32_t *uid) {
    struct auditinfo_addr info = {0};
    if (getaudit_addr(&info, sizeof(info)) == -1) return errno;
    if (info.ai_auid == 0 || info.ai_auid == (au_id_t)-1) return EPERM;
    *uid = info.ai_auid;
    return 0;
}

/* Return errno rather than relying on Rust observing C's transient errno. */
int veil_bpf_configure(int fd, const char *name,
    const struct bpf_insn *instructions, uint32_t count, uint32_t *length) {
    struct bpf_version version = {0};
    if (ioctl(fd, BIOCVERSION, &version) == -1) return errno;
    if (version.bv_major != BPF_MAJOR_VERSION ||
        version.bv_minor < BPF_MINOR_VERSION) return EPROTONOSUPPORT;
    /* Block everything before interface attachment, including initialization. */
    struct bpf_insn reject[] = { BPF_STMT(BPF_RET | BPF_K, 0) };
    struct bpf_program program = {1, reject};
    if (ioctl(fd, BIOCSETF, &program) == -1) return errno;
    unsigned int size = 65536;
    if (ioctl(fd, BIOCSBLEN, &size) == -1) return errno;
    int direction = VEIL_BPF_D_OUT;
    if (ioctl(fd, VEIL_BIOCSDIRECTION, &direction) == -1) return errno;
    direction = 0;
    if (ioctl(fd, VEIL_BIOCGDIRECTION, &direction) == -1) return errno;
    if (direction != VEIL_BPF_D_OUT) return EPROTONOSUPPORT;
    struct ifreq request = {0};
    size_t name_length = strlen(name);
    if (name_length == 0 || name_length >= IFNAMSIZ) return EINVAL;
    memcpy(request.ifr_name, name, name_length);
    if (ioctl(fd, BIOCSETIF, &request) == -1) return errno;
    unsigned int dlt = 0;
    if (ioctl(fd, BIOCGDLT, &dlt) == -1) return errno;
    if (dlt != DLT_EN10MB) return EPROTONOSUPPORT;
    unsigned int immediate = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &immediate) == -1) return errno;
    if (ioctl(fd, BIOCGBLEN, &size) == -1) return errno;
    if (size < sizeof(struct bpf_hdr) || size > 1048576) return EINVAL;
    /* Kernel copies the program synchronously; its pointer is not retained. */
    program.bf_len = count;
    program.bf_insns = (struct bpf_insn *)(uintptr_t)instructions;
    if (ioctl(fd, BIOCSETF, &program) == -1) return errno;
    *length = size;
    return 0;
}

int veil_bpf_stats(int fd, uint32_t *received, uint32_t *dropped) {
    struct bpf_stat stats = {0};
    if (ioctl(fd, BIOCGSTATS, &stats) == -1) return errno;
    *received = stats.bs_recv;
    *dropped = stats.bs_drop;
    return 0;
}
