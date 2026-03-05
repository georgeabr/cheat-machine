/*
 * cheatmachine.cpp — Linux memory scanner/editor
 * Build:  g++ -O3 -std=c++17 -o cheatmachine cheatmachine.cpp -lncurses -lpthread
 * Run:    sudo ./cheatmachine [pid]
 */
#include <cmath>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <future>
#include <mutex>
#include <ncurses.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <vector>

// ── Data types ────────────────────────────────────────────────────────────────
enum DType { DT_I8, DT_U8, DT_I16, DT_U16, DT_I32, DT_U32, DT_I64, DT_U64, DT_F32, DT_F64, DT_COUNT };
static const char* dtype_name[] = { "i8","u8","i16","u16","i32","u32","i64","u64","f32","f64" };
static const int   dtype_size[] = {  1,   1,   2,    2,    4,    4,    8,    8,    4,    8   };

static int dtype_size_of(DType dt) { return dtype_size[(int)dt]; }

// ── Colors ────────────────────────────────────────────────────────────────────
enum Colors {
    C_NORMAL = 1, C_TITLE, C_HEADER, C_SEL, C_FROZEN, C_WARN, C_OK, C_DIM, C_INPUT
};

void init_colors() {
    start_color();
    use_default_colors();
    init_pair(C_NORMAL, COLOR_WHITE, -1);
    init_pair(C_TITLE, COLOR_WHITE, COLOR_BLUE);
    init_pair(C_HEADER, COLOR_CYAN, -1);
    init_pair(C_SEL, COLOR_BLACK, COLOR_GREEN);
    init_pair(C_FROZEN, COLOR_YELLOW, -1);
    init_pair(C_WARN, COLOR_RED, -1);
    init_pair(C_OK, COLOR_GREEN, -1);
    init_pair(C_DIM, COLOR_WHITE, -1); // Faked dim
    init_pair(C_INPUT, COLOR_BLACK, COLOR_WHITE);
}

// ── Maps Parsing & Caching ────────────────────────────────────────────────────
struct Region {
    uint64_t start, end;
    char perms[8];
    char name[128];
    bool writable() const { return perms[1] == 'w'; }
};

static std::vector<Region> cached_maps;

static std::atomic<bool> float_tolerance{false};

static void refresh_maps(int pid) {
    cached_maps.clear();
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        Region r{};
        char perms[8], name[256]={};
        unsigned long long s, e;
        sscanf(line, "%llx-%llx %7s %*x %*x:%*x %*u %255[^\n]", &s, &e, perms, name);
        r.start = s; r.end = e;
        strncpy(r.perms, perms, 7); r.perms[7] = '\0';
        const char* np = name; while (*np == ' ') np++;
        strncpy(r.name, np, 127); r.name[127] = '\0';
        if (perms[0] != 'r') continue;
        if (strcmp(r.name, "[vvar]")==0 || strcmp(r.name,"[vsyscall]")==0) continue;
        cached_maps.push_back(r);
    }
    fclose(f);
}

static bool addr_info_cached(uint64_t addr, char* perms_out, char* name_out) {
    for (const auto& r : cached_maps) {
        if (addr >= r.start && addr < r.end) {
            if (perms_out) { strncpy(perms_out, r.perms, 7); perms_out[7] = '\0'; }
            if (name_out)  { strncpy(name_out,  r.name, 127); name_out[127] = '\0'; }
            return true;
        }
    }
    if (perms_out) { strcpy(perms_out, "?????"); }
    if (name_out) { name_out[0] = '\0'; }
    return false;
}

// ── Memory access ─────────────────────────────────────────────────────────────
static bool mem_read(int pid, uint64_t addr, void* buf, size_t sz) {
    struct iovec local[1], remote[1];
    local[0].iov_base = buf; local[0].iov_len = sz;
    remote[0].iov_base = (void*)addr; remote[0].iov_len = sz;
    ssize_t r = process_vm_readv(pid, local, 1, remote, 1, 0);
    return r == (ssize_t)sz;
}

static bool mem_write(int pid, uint64_t addr, const void* buf, size_t sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return false;
    ssize_t w = pwrite(fd, buf, sz, (off_t)addr);
    close(fd);
    return w == (ssize_t)sz;
}

// ── Value Parsing & Formatting ────────────────────────────────────────────────
static bool pack_value(const char* s, DType dt, uint8_t* out) {
    memset(out, 0, 8);
    char* end;
    switch (dt) {
        case DT_I8:  *(int8_t*)out=(int8_t)strtol(s,&end,0); break;
        case DT_U8:  *(uint8_t*)out=(uint8_t)strtoul(s,&end,0); break;
        case DT_I16: *(int16_t*)out=(int16_t)strtol(s,&end,0); break;
        case DT_U16: *(uint16_t*)out=(uint16_t)strtoul(s,&end,0); break;
        case DT_I32: *(int32_t*)out=(int32_t)strtol(s,&end,0); break;
        case DT_U32: *(uint32_t*)out=(uint32_t)strtoul(s,&end,0); break;
        case DT_I64: *(int64_t*)out=strtoll(s,&end,0); break;
        case DT_U64: *(uint64_t*)out=strtoull(s,&end,0); break;
        case DT_F32: *(float*)out=strtof(s,&end); break;
        case DT_F64: *(double*)out=strtod(s,&end); break;
        default: return false;
    }
    return (*end == 0 || *end == '\n');
}

static std::string fmt_value(const uint8_t* buf, DType dt) {
    char tmp[64];
    switch(dt) {
        case DT_I8:  snprintf(tmp,sizeof(tmp),"%d",  *(int8_t*)buf);   break;
        case DT_U8:  snprintf(tmp,sizeof(tmp),"%u",  *(uint8_t*)buf);  break;
        case DT_I16: snprintf(tmp,sizeof(tmp),"%d",  *(int16_t*)buf);  break;
        case DT_U16: snprintf(tmp,sizeof(tmp),"%u",  *(uint16_t*)buf); break;
        case DT_I32: snprintf(tmp,sizeof(tmp),"%d",  *(int32_t*)buf);  break;
        case DT_U32: snprintf(tmp,sizeof(tmp),"%u",  *(uint32_t*)buf); break;
        case DT_I64: snprintf(tmp,sizeof(tmp),"%lld",(long long)*(int64_t*)buf);  break;
        case DT_U64: snprintf(tmp,sizeof(tmp),"%llu",(unsigned long long)*(uint64_t*)buf); break;
        case DT_F32: snprintf(tmp,sizeof(tmp),"%.6g",*(float*)buf);    break;
        case DT_F64: snprintf(tmp,sizeof(tmp),"%.10g",*(double*)buf);  break;
        default:     snprintf(tmp,sizeof(tmp),"??");
    }
    return tmp;
}

static bool equal_value(const uint8_t* buf, const uint8_t* needle, DType dt) {
    switch (dt) {
        case DT_F32: {
            if (float_tolerance.load()) {
                float a = *(float*)buf, b = *(float*)needle;
                float tol = std::max(std::fabs(a), std::fabs(b)) * 1e-5f + 1e-4f;
                return std::fabs(a - b) <= tol;
            } else {
                // Exact bitwise equality for float (cheating use-case).
                return memcmp(buf, needle, sizeof(float)) == 0;
            }
        }
        case DT_F64: {
            if (float_tolerance.load()) {
                double a = *(double*)buf, b = *(double*)needle;
                double tol = std::max(std::fabs(a), std::fabs(b)) * 1e-9 + 1e-6;
                return std::fabs(a - b) <= tol;
            } else {
                // Exact bitwise equality for double (cheating use-case).
                return memcmp(buf, needle, sizeof(double)) == 0;
            }
        }
        default:
            return memcmp(buf, needle, dtype_size_of(dt)) == 0;
    }
}

static std::vector<DType> smart_types(const char* s) {
    std::vector<DType> out;
    char* end;
    long long iv = strtoll(s, &end, 0);
    if (*end && *end != '\n') {
        strtod(s, &end);
        if (!*end || *end=='\n') { out.push_back(DT_F32); out.push_back(DT_F64); }
        return out;
    }
    if (iv >= -2147483648LL && iv <= 2147483647LL) out.push_back(DT_I32);
    if (iv >= 0 && iv <= 4294967295LL)             out.push_back(DT_U32);
    if (iv >= -32768 && iv <= 32767)               out.push_back(DT_I16);
    if (iv >= 0 && iv <= 65535)                    out.push_back(DT_U16);
    out.push_back(DT_I64); out.push_back(DT_U64);
    return out;
}

// ── Helpers: safe unaligned loads ──────────────────────────────────────────────
static inline void safe_memcpy_load(void* dst, const void* src, size_t n) {
    memcpy(dst, src, n);
}

template<typename T>
static inline T read_unaligned_typed(const uint8_t* p) {
    T v;
    safe_memcpy_load(&v, p, sizeof(T));
    return v;
}

// ── Multi-threaded Scanner with Byte-based Work Distribution & process_vm_readv ─
template <typename T>
void scan_chunk_typed(int pid, T target, const std::vector<Region>& regions, std::vector<uint64_t>& results, std::atomic<uint64_t>& done, std::atomic<bool>& cancel) {
    const size_t CHUNK = 16 * 1024 * 1024; // 16 MiB
    std::vector<uint8_t> buf(CHUNK);
    const int sz = sizeof(T);

    // Reserve some space heuristically to reduce reallocations
    results.reserve(1024);

    for (const auto& r : regions) {
        if (cancel) break;
        uint64_t cursor = r.start;
        // align cursor to type size
        if ((cursor % sz) != 0) cursor += sz - (cursor % sz);

        while (cursor < r.end && !cancel) {
            uint64_t avail = r.end - cursor;
            size_t to_read = (size_t)std::min<uint64_t>((uint64_t)CHUNK, avail);
            to_read = (to_read / sz) * sz;
            if (to_read == 0) break;

            struct iovec local = { buf.data(), to_read };
            struct iovec remote = { (void*)cursor, to_read };
            ssize_t got = process_vm_readv(pid, &local, 1, &remote, 1, 0);

            if (got <= 0) {
                // nothing read: advance by to_read (account for progress) and continue
                done += to_read;
                cursor += to_read;
                continue;
            }

            // We may have read fewer than requested bytes; only consider full elements
            size_t valid = (size_t)got;
            size_t count = valid / sz;

            for (size_t i = 0; i < count; ++i) {
                const uint8_t* cell = buf.data() + i * sz;
                T v = read_unaligned_typed<T>(cell);
                if (v == target) {
                    results.push_back(cursor + (i * sz));
                }
            }

            done += valid;
            cursor += valid;

            // If partial read left a trailing incomplete piece, skip it forward
            size_t incomplete = (size_t)got % sz;
            if (incomplete) {
                // Advance cursor by the incomplete bytes to avoid rechecking the same incomplete area repeatedly
                cursor += (sz - incomplete);
                done += (sz - incomplete);
            }
        }
    }
}

static std::vector<std::vector<Region>> split_regions_by_bytes(const std::vector<Region>& regions, int num_parts) {
    std::vector<std::vector<Region>> out(num_parts);
    if (regions.empty()) return out;

    uint64_t total = 0;
    for (const auto& r : regions) total += (r.end - r.start);
    if (total == 0) return out;

    for (int part = 0; part < num_parts; ++part) {
        uint64_t byte_start = (uint64_t)((__int128)part * total / num_parts);
        uint64_t byte_end   = (uint64_t)((__int128)(part + 1) * total / num_parts);
        if (byte_end > total) byte_end = total;
        uint64_t acc = 0;
        for (const auto& r : regions) {
            uint64_t rsz = r.end - r.start;
            uint64_t region_start_byte = acc;
            uint64_t region_end_byte = acc + rsz;
            if (region_end_byte <= byte_start) { acc += rsz; continue; }
            if (region_start_byte >= byte_end) break;
            uint64_t off0 = (byte_start > region_start_byte) ? (byte_start - region_start_byte) : 0;
            uint64_t off1 = (byte_end < region_end_byte) ? (byte_end - region_start_byte) : rsz;
            Region sub = r;
            sub.start = r.start + off0;
            sub.end = r.start + off1;
            out[part].push_back(sub);
            acc += rsz;
        }
    }
    return out;
}

static std::vector<uint64_t> scan_memory(int pid, DType dt, const uint8_t* needle, std::atomic<float>& progress, std::atomic<bool>& cancel) {
    std::vector<uint64_t> results;
    std::vector<Region> writable_regions;
    for (const auto& r : cached_maps) if (r.writable()) writable_regions.push_back(r);

    uint64_t total = 0;
    for (auto& r : writable_regions) total += r.end - r.start;
    std::atomic<uint64_t> done{0};

    int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;

    // Byte-based split of regions across threads for better balance
    auto per_thread_regions = split_regions_by_bytes(writable_regions, num_threads);

    std::vector<std::future<void>> futures;
    std::vector<std::vector<uint64_t>> thread_results(num_threads);
    for (int i = 0; i < num_threads; ++i) {
        if (per_thread_regions[i].empty()) continue;

        auto scan_func = [&, i]() {
            switch(dt) {
                case DT_I8:  { int8_t target;  memcpy(&target, needle, sizeof(target));  scan_chunk_typed<int8_t>(pid,  target, per_thread_regions[i], thread_results[i], done, cancel); break; }
                case DT_U8:  { uint8_t target; memcpy(&target, needle, sizeof(target));  scan_chunk_typed<uint8_t>(pid, target, per_thread_regions[i], thread_results[i], done, cancel); break; }
                case DT_I16: { int16_t target; memcpy(&target, needle, sizeof(target));  scan_chunk_typed<int16_t>(pid, target, per_thread_regions[i], thread_results[i], done, cancel); break; }
                case DT_U16: { uint16_t target;memcpy(&target, needle, sizeof(target));  scan_chunk_typed<uint16_t>(pid, target, per_thread_regions[i], thread_results[i], done, cancel); break; }
                case DT_I32: { int32_t target; memcpy(&target, needle, sizeof(target));  scan_chunk_typed<int32_t>(pid, target, per_thread_regions[i], thread_results[i], done, cancel); break; }
                case DT_U32: { uint32_t target;memcpy(&target, needle, sizeof(target));  scan_chunk_typed<uint32_t>(pid, target, per_thread_regions[i], thread_results[i], done, cancel); break; }
                case DT_I64: { int64_t target; memcpy(&target, needle, sizeof(target));  scan_chunk_typed<int64_t>(pid, target, per_thread_regions[i], thread_results[i], done, cancel); break; }
                case DT_U64: { uint64_t target;memcpy(&target, needle, sizeof(target));  scan_chunk_typed<uint64_t>(pid, target, per_thread_regions[i], thread_results[i], done, cancel); break; }
                case DT_F32: { float target;    memcpy(&target, needle, sizeof(target));   scan_chunk_typed<float>(pid,    target, per_thread_regions[i], thread_results[i], done, cancel); break; }
                case DT_F64: { double target;   memcpy(&target, needle, sizeof(target));   scan_chunk_typed<double>(pid,   target, per_thread_regions[i], thread_results[i], done, cancel); break; }
                default: break;
            }
        };
        futures.push_back(std::async(std::launch::async, scan_func));
    }

    while (true) {
        bool all_done = true;
        for (auto& f : futures) {
            if (f.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
                all_done = false;
                break;
            }
        }
        if (total > 0) progress.store((float)done / total);
        if (all_done) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    for (const auto& tr : thread_results) {
        results.insert(results.end(), tr.begin(), tr.end());
    }

    progress.store(1.0f);
    return results;
}

// ── process_vm_readv Narrowing (reliable per-address batch) ───────────────────
static std::vector<uint64_t> narrow_memory(int pid, DType dt, const uint8_t* needle,
                                           const std::vector<uint64_t>& candidates,
                                           int& out_fail, int& out_checked) {
    std::vector<uint64_t> out;
    const int sz = dtype_size_of(dt);
    out_fail = 0;
    out_checked = 0;

    const int BATCH_SIZE = 64; // Linux allows up to 1024, but 64 is a sweet spot
    struct iovec local[BATCH_SIZE];
    struct iovec remote[BATCH_SIZE];
    uint8_t batch_buf[BATCH_SIZE][8];

    for (size_t i = 0; i < candidates.size(); i += BATCH_SIZE) {
        int current_batch = std::min((int)(candidates.size() - i), BATCH_SIZE);

        for (int j = 0; j < current_batch; j++) {
            local[j].iov_base = batch_buf[j];
            local[j].iov_len = sz;
            remote[j].iov_base = (void*)candidates[i + j];
            remote[j].iov_len = sz;
        }

        // process_vm_readv returns the total number of bytes read
        ssize_t total_read = process_vm_readv(pid, local, current_batch, remote, current_batch, 0);

        if (total_read <= 0) {
            out_fail += current_batch;
            continue;
        }

        // For each iovec, determine whether it was fully read.
        // total_read counts bytes read across the whole batch; any iovec where
        // (j+1)*sz <= total_read is fully present (this is a conservative check).
        for (int j = 0; j < current_batch; j++) {
            ssize_t offset_bytes = (ssize_t)j * sz;
            if (offset_bytes + (ssize_t)sz <= total_read) {
                out_checked++;
                if (equal_value(batch_buf[j], needle, dt)) {
                    out.push_back(candidates[i + j]);
                }
            } else {
                // This entry wasn't fully read; count as fail.
                out_fail++;
            }
        }
    }

    return out;
}

// ── Freeze engine ─────────────────────────────────────────────────────────────
struct FreezeEntry { int pid; uint64_t addr; uint8_t val[8]; int sz; };
static std::vector<FreezeEntry> freeze_list;
static std::mutex freeze_mutex;
static std::atomic<bool> freeze_run{true};

static void freeze_thread_fn() {
    while (freeze_run) {
        {
            std::lock_guard<std::mutex> lk(freeze_mutex);
            for (auto& e : freeze_list) mem_write(e.pid, e.addr, e.val, e.sz);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}
static bool is_frozen(int pid, uint64_t addr) {
    std::lock_guard<std::mutex> lk(freeze_mutex);
    for (auto& e : freeze_list) if (e.pid == pid && e.addr == addr) return true;
    return false;
}
static void set_frozen(int pid, uint64_t addr, const uint8_t* val, int sz) {
    std::lock_guard<std::mutex> lk(freeze_mutex);
    for (auto& e : freeze_list) {
        if (e.pid == pid && e.addr == addr) {
            memcpy(e.val, val, sz);
            mem_write(pid, addr, val, sz);  // immediate write so UI reflects value
            return;
        }
    }
    FreezeEntry fe{}; fe.pid=pid; fe.addr=addr; fe.sz=sz; memcpy(fe.val,val,sz);
    freeze_list.push_back(fe);
    mem_write(pid, addr, val, sz);          // immediate write for new entries too
}
static void unfreeze(int pid, uint64_t addr) {
    std::lock_guard<std::mutex> lk(freeze_mutex);
    freeze_list.erase(std::remove_if(freeze_list.begin(), freeze_list.end(), [&](auto& e){ return e.pid==pid && e.addr==addr; }), freeze_list.end());
}

// ── Process list ──────────────────────────────────────────────────────────────
struct ProcInfo { int pid; std::string name, cmd; };
static std::vector<ProcInfo> get_procs() {
    std::vector<ProcInfo> out;
    DIR* d = opendir("/proc"); if (!d) return out;
    struct dirent* e;
    while ((e = readdir(d))) {
        if (!isdigit(e->d_name[0])) continue;
        int pid = atoi(e->d_name);
        char path[64], buf[512]={};
        snprintf(path,sizeof(path),"/proc/%d/comm",pid);
        FILE* f = fopen(path,"r"); if(!f) continue;
        fgets(buf,64,f); fclose(f);
        std::string name(buf); if(!name.empty()&&name.back()=='\n') name.pop_back();
        snprintf(path,sizeof(path),"/proc/%d/cmdline",pid);
        f = fopen(path,"r");
        std::string cmd;
        if (f) {
            size_t n = fread(buf,1,511,f); fclose(f);
            for (size_t i=0;i<n;i++) if(buf[i]=='\0') buf[i]=' ';
            buf[n]=0; cmd = buf;
            if (cmd.size()>70) cmd = cmd.substr(0,70)+"…";
        }
        out.push_back({pid, name, cmd});
    }
    closedir(d);
    std::sort(out.begin(),out.end(),[](auto&a,auto&b){return a.pid<b.pid;});
    return out;
}

// ── UI Helpers ───────────────────────────────────────────────────────────────
static int clamp(int v, int lo, int hi) { return v<lo?lo:v>hi?hi:v; }

void draw_box(int r, int c, int h, int w, const char* title="") {
    attron(COLOR_PAIR(C_HEADER));
    mvhline(r, c, '-', w);
    mvhline(r+h-1, c, '-', w);
    mvvline(r, c, '|', h);
    mvvline(r, c+w-1, '|', h);
    mvaddch(r, c, '+'); mvaddch(r, c+w-1, '+');
    mvaddch(r+h-1, c, '+'); mvaddch(r+h-1, c+w-1, '+');
    if (title && *title) {
        attron(COLOR_PAIR(C_TITLE));
        mvprintw(r, c+2, " %s ", title);
    }
    attroff(COLOR_PAIR(C_TITLE) | COLOR_PAIR(C_HEADER));
}

std::string prompt_input(int r, int c, const char* label, int max_len=40) {
    attron(COLOR_PAIR(C_INPUT));
    mvprintw(r, c, " %s: ", label);
    for(int i=0; i<max_len+2; i++) addch(' ');
    move(r, c + strlen(label) + 3);
    echo(); curs_set(1);
    char buf[256] = {0};
    getnstr(buf, max_len);
    noecho(); curs_set(0);
    attroff(COLOR_PAIR(C_INPUT));
    return std::string(buf);
}

// ── Screen: Process Picker ────────────────────────────────────────────────────
static int screen_pick_process() {
    auto procs = get_procs();
    std::string search;
    int sel = 0, scroll = 0;

    while (true) {
        erase();
        int rows, cols; getmaxyx(stdscr, rows, cols);

        attron(COLOR_PAIR(C_TITLE) | A_BOLD);
        mvhline(0, 0, ' ', cols);
        mvprintw(0, (cols - 34) / 2, "  CHEAT MACHINE - Process Selector  ");
        attroff(COLOR_PAIR(C_TITLE) | A_BOLD);

        attron(COLOR_PAIR(C_HEADER) | A_BOLD);
        mvprintw(2, 2, "Filter: ");
        attroff(COLOR_PAIR(C_HEADER) | A_BOLD);
        attron(COLOR_PAIR(C_INPUT));
        mvprintw(2, 10, "%-40s", search.c_str());
        attroff(COLOR_PAIR(C_INPUT));

        attron(COLOR_PAIR(C_HEADER));
        mvprintw(4, 2, "  %7s  %-18s  %s", "PID", "NAME", "COMMAND");
        attroff(COLOR_PAIR(C_HEADER));

        std::vector<ProcInfo*> filtered;
        std::string ql = search; std::transform(ql.begin(),ql.end(),ql.begin(),::tolower);
        for (auto& p : procs) {
            std::string nl = p.name; std::transform(nl.begin(),nl.end(),nl.begin(),::tolower);
            std::string cl = p.cmd;  std::transform(cl.begin(),cl.end(),cl.begin(),::tolower);
            if (ql.empty() || nl.find(ql)!=std::string::npos || cl.find(ql)!=std::string::npos || std::to_string(p.pid)==search)
                filtered.push_back(&p);
        }

        int list_h = rows - 8;
        sel = clamp(sel, 0, std::max(0,(int)filtered.size()-1));
        scroll = clamp(scroll, 0, std::max(0,(int)filtered.size()-list_h));
        if (sel < scroll) scroll = sel;
        if (sel >= scroll+list_h) scroll = sel-list_h+1;

        for (int i = 0; i < list_h && (scroll+i) < (int)filtered.size(); i++) {
            auto* p = filtered[scroll+i];
            if (scroll+i == sel) attron(COLOR_PAIR(C_SEL));
            else attron(COLOR_PAIR(C_NORMAL));

            mvprintw(5+i, 2, "  %7d  %-18s  %-.*s", p->pid, p->name.c_str(), cols-36, p->cmd.c_str());

            if (scroll+i == sel) attroff(COLOR_PAIR(C_SEL));
            else attroff(COLOR_PAIR(C_NORMAL));
        }

        attron(COLOR_PAIR(C_DIM));
        mvprintw(rows-1, 1, " Type to filter | Up/Down | Enter: attach | r: refresh | Esc: quit");
        attroff(COLOR_PAIR(C_DIM));

        refresh();
        int k = getch();
        if (k == 27) return -1;
        if (k == '\n') return filtered.empty() ? -1 : filtered[sel]->pid;
        if (k == KEY_UP) sel--;
        if (k == KEY_DOWN) sel++;
        if (k == KEY_NPAGE) { sel += list_h; scroll += list_h; }
        if (k == KEY_PPAGE) { sel -= list_h; scroll -= list_h; }
        if (k == 'r' || k == 'R') { procs = get_procs(); sel=0; scroll=0; }
        if (k == KEY_BACKSPACE || k == 127 || k == 8) { if(!search.empty()) {search.pop_back(); sel=0; scroll=0;} }
        else if (k >= 32 && k <= 126) { search += (char)k; sel=0; scroll=0; }
    }
}

// ── Screen: Cheat ─────────────────────────────────────────────────────────────
static void screen_cheat(int pid) {
    char pname[64] = "?";
    {   char p[64]; snprintf(p, sizeof(p), "/proc/%d/comm", pid);
        FILE* f = fopen(p, "r"); if (f) { fgets(pname, 63, f); fclose(f); }
        size_t n = strlen(pname); if (n && pname[n - 1] == '\n') pname[n - 1] = 0;
    }

    refresh_maps(pid); // Cache maps immediately
    DType dt = DT_I32;
    DType last_scan_dt = dt;   // remember which type produced current candidates
    std::vector<uint64_t> candidates;
    int sel = 0, scroll_off = 0, scan_count = 0;
    int frozen_sel = 0, frozen_scroll = 0;
    enum Focus { F_RESULTS, F_FROZEN };
    Focus focus = F_RESULTS;
    std::string status_msg; bool status_ok = true;

    auto set_status = [&](const std::string& msg, bool ok = true) { status_msg = msg; status_ok = ok; };

    while (true) {
        erase();
        int rows, cols; getmaxyx(stdscr, rows, cols);

        attron(COLOR_PAIR(C_TITLE) | A_BOLD);
        mvhline(0, 0, ' ', cols);
        mvprintw(0, 0, "  CHEAT MACHINE  PID:%d (%s)  [%s/%dB]",
                 pid, pname, dtype_name[(int)dt], dtype_size_of(dt));
        attroff(COLOR_PAIR(C_TITLE) | A_BOLD);

        int panel_w = std::min(60, cols / 2);
        int list_h = rows - 8;
        int body_h = list_h - 1;  // leave one row for bottom border
        bool focus_results = (focus == F_RESULTS);

        draw_box(1, 0, list_h + 2, panel_w,
                 (std::string("Results (") + std::to_string(candidates.size()) + ")").c_str());

        attron(COLOR_PAIR(C_HEADER));
        mvprintw(2, 1, "  %-4s  %-18s  %-10s  %-5s %-8s F", "#", "ADDRESS", "VALUE", "PERMS", "REGION");
        attroff(COLOR_PAIR(C_HEADER));

        int disp_sel = clamp(sel, 0, std::max(0, (int)candidates.size() - 1));
        int sc = clamp(scroll_off, 0, std::max(0, (int)candidates.size() - body_h));
        if (disp_sel < sc) sc = disp_sel;
        if (disp_sel >= sc + body_h) sc = disp_sel - body_h + 1;
        scroll_off = sc;

        for (int i = 0; i < body_h && (sc + i) < (int)candidates.size(); i++) {
            uint64_t addr = candidates[sc + i];
            uint8_t buf[8] = {};
            bool ok = mem_read(pid, addr, buf, dtype_size_of(dt));
            std::string val_s = ok ? fmt_value(buf, dt) : "??";
            bool frz = is_frozen(pid, addr);

            char perms[8] = "?????", rname[128] = "";
            addr_info_cached(addr, perms, rname);

            std::string rshort(rname);
            if (!rshort.empty() && rshort[0] == '[') rshort = rshort.substr(1, rshort.find(']') - 1);
            else if (rshort.rfind('/') != std::string::npos) rshort = rshort.substr(rshort.rfind('/') + 1);
            if ((int)rshort.size() > 8) rshort = rshort.substr(0, 8);

            int color = C_NORMAL;
            if (focus_results && sc + i == disp_sel) color = C_SEL;
            else if (!focus_results && sc + i == disp_sel) color = C_DIM;
            else if (frz) color = C_FROZEN;
            else if (perms[1] != 'w') color = C_WARN;

            attron(COLOR_PAIR(color));
            mvprintw(3 + i, 1, "  %-4d  0x%016llx  %-10s  %-5s %-8s %s",
                     sc + i, (unsigned long long)addr, val_s.c_str(), perms, rshort.c_str(), frz ? "*" : " ");
            attroff(COLOR_PAIR(color));
        }

        // Right panel
        int rx = panel_w + 1;
        int rw = cols - rx - 1;
        if (rw > 20) {
            draw_box(1, rx, list_h + 2, rw, "Frozen");
            std::vector<FreezeEntry> frozen_copy;
            {
                std::lock_guard<std::mutex> lk(freeze_mutex);
                frozen_copy = freeze_list; // snapshot to avoid holding lock while drawing
            }
            int fh = body_h;
            int fcount = (int)frozen_copy.size();
            frozen_sel = clamp(frozen_sel, 0, std::max(0, fcount - 1));
            frozen_scroll = clamp(frozen_scroll, 0, std::max(0, fcount - fh));
            if (frozen_sel < frozen_scroll) frozen_scroll = frozen_sel;
            if (frozen_sel >= frozen_scroll + fh) frozen_scroll = frozen_sel - fh + 1;

            for (int i = 0; i < fh && (frozen_scroll + i) < fcount; ++i) {
                auto &fe = frozen_copy[frozen_scroll + i];
                uint8_t cur[8] = {}; mem_read(fe.pid, fe.addr, cur, fe.sz);
                bool is_sel = (focus == F_FROZEN && frozen_scroll + i == frozen_sel);
                int color = is_sel ? C_SEL : C_FROZEN;
                attron(COLOR_PAIR(color));
                mvprintw(3 + i, rx + 2, "0x%016llx = %-10s",
                         (unsigned long long)fe.addr, fmt_value(cur, dt).c_str());
                attroff(COLOR_PAIR(color));
            }
        }

        if (!status_msg.empty()) {
            attron(COLOR_PAIR(status_ok ? C_OK : C_WARN) | A_BOLD);
            mvprintw(rows - 3, 1, " %s", status_msg.c_str());
            attroff(COLOR_PAIR(status_ok ? C_OK : C_WARN) | A_BOLD);
        }

        attron(COLOR_PAIR(C_DIM));
        mvprintw(rows - 1, 1, "s:scan n:narrow a:add e:edit f:freeze u:thaw t:type c:clear p:procs q:quit  (Tab: switch pane)");
        attroff(COLOR_PAIR(C_DIM));

        refresh();
        int k = getch();
        if (k == 27 /*ESC*/ || k == 'q' || k == 'Q' || k == 'p' || k == 'P') return;

        int sz = dtype_size_of(dt);

        // Focus switching
        if (k == '\t') {
            focus = (focus == F_RESULTS) ? F_FROZEN : F_RESULTS;
        }

        // Navigation per focus
        if (focus == F_RESULTS) {
            if (k == KEY_UP) sel--;
            if (k == KEY_DOWN) sel++;
            if (k == KEY_NPAGE) { sel += body_h; scroll_off += body_h; }
            if (k == KEY_PPAGE) { sel -= body_h; scroll_off -= body_h; }
            sel = clamp(sel, 0, std::max(0, (int)candidates.size() - 1));
        } else { // frozen pane
            if (k == KEY_UP) frozen_sel--;
            if (k == KEY_DOWN) frozen_sel++;
            if (k == KEY_NPAGE) { frozen_sel += body_h; frozen_scroll += body_h; }
            if (k == KEY_PPAGE) { frozen_sel -= body_h; frozen_scroll -= body_h; }
        }

        if (k == 't' || k == 'T') {
            dt = (DType)(((int)dt + 1) % (int)DT_COUNT);
            set_status(std::string("Type -> ") + dtype_name[(int)dt]);
        }
        if (k == 'c' || k == 'C') { candidates.clear(); sel = 0; scroll_off = 0; scan_count = 0; set_status("Cleared."); }

        if (k == 's' || k == 'S') {
            refresh_maps(pid);
            std::string raw = prompt_input(rows - 2, 0, "Scan value", 32);
            if (raw.empty()) { set_status("Cancelled."); continue; }
            auto types = smart_types(raw.c_str());
            if (types.empty()) { set_status("Can't parse value.", false); continue; }

            DType best_dt = types[0];
            std::vector<uint64_t> best_cands;

            for (DType try_dt : types) {
                uint8_t needle[8] = {};
                if (!pack_value(raw.c_str(), try_dt, needle)) continue;
                std::atomic<float> p{0}; std::atomic<bool> cancel{false};

                auto res = scan_memory(pid, try_dt, needle, p, cancel);
                if (!res.empty()) {
                    best_dt = try_dt;
                    best_cands = std::move(res);
                    break; // take first successful type in preference order
                }
            }

            if (best_cands.empty()) {
                set_status("Scan found 0 hits.", false);
                continue;
            }

            candidates = std::move(best_cands);
            dt = best_dt; last_scan_dt = dt;
            scan_count = 1; sel = 0; scroll_off = 0;
            set_status("Scan complete -> " + std::string(dtype_name[(int)dt]) +
                       " (" + std::to_string(candidates.size()) + " hits).");
        }

        if (k == 'n' || k == 'N') {
            if (candidates.empty()) { set_status("Scan first.", false); continue; }
            if (dt != last_scan_dt) { set_status("Type changed since scan — rescan.", false); continue; }
            std::string raw = prompt_input(rows - 2, 0, "New value", 32);
            if (raw.empty()) continue;
            uint8_t needle[8] = {};
            if (!pack_value(raw.c_str(), dt, needle)) { set_status("Bad value", false); continue; }

            int n_fail = 0, n_checked = 0;
            candidates = narrow_memory(pid, dt, needle, candidates, n_fail, n_checked);
            scan_count++; sel = 0; scroll_off = 0;
            char tmp[128]; snprintf(tmp, sizeof(tmp), "Narrowed to %zu checked:%d fail:%d", candidates.size(), n_checked, n_fail);
            set_status(tmp);
        }

        if ((k == 'e' || k == 'E') && !candidates.empty()) {
            uint64_t addr = candidates[sel];
            std::string raw = prompt_input(rows - 2, 0, "New value", 32);
            if (!raw.empty()) {
                uint8_t val[8] = {};
                if (pack_value(raw.c_str(), dt, val)) {
                    if (mem_write(pid, addr, val, sz)) set_status("Written.");
                    else set_status("Write FAILED.", false);
                } else {
                    set_status("Bad value", false);
                }
            }
        }

        if ((k == 'f' || k == 'F') && !candidates.empty()) {
            uint64_t addr = candidates[sel];
            std::string raw = prompt_input(rows - 2, 0, "Freeze value", 32);
            uint8_t val[8] = {};
            if (!raw.empty() && pack_value(raw.c_str(), dt, val)) {
                set_frozen(pid, addr, val, sz);
                set_status("Frozen.");
            }
        }

        if ((k == 'u' || k == 'U')) {
            if (focus == F_RESULTS && !candidates.empty()) {
                unfreeze(pid, candidates[sel]); set_status("Thawed.");
            } else if (focus == F_FROZEN) {
                std::lock_guard<std::mutex> lk(freeze_mutex);
                if (!freeze_list.empty() && frozen_sel >= 0 && frozen_sel < (int)freeze_list.size()) {
                    freeze_list.erase(freeze_list.begin() + frozen_sel);
                    frozen_sel = clamp(frozen_sel, 0, (int)freeze_list.size() - 1);
                    set_status("Thawed frozen entry.");
                }
            }
        }
    }
}

int main(int argc, char** argv) {
    if (getuid() != 0) {
        fprintf(stderr, "\n  Reading/writing another process's memory requires root.\n  Run with sudo.\n\n");
        return 1;
    }

    std::thread ft(freeze_thread_fn);
    ft.detach();

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    init_colors();

    int start_pid = (argc > 1) ? atoi(argv[1]) : -1;

    while (true) {
        int pid = start_pid >= 0 ? start_pid : screen_pick_process();
        start_pid = -1;
        if (pid < 0) break;
        screen_cheat(pid);
    }

    freeze_run = false;
    endwin();
    return 0;
}
