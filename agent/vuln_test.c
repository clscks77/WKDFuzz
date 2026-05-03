#define __MINGW_USE_WS2_32 1
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600 // WSAPoll
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <winternl.h>
#include "nyx_api.h"
#include <psapi.h>
#include <winsvc.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
// for debuging
#include <iphlpapi.h>
#include <netlistmgr.h>
#include <objbase.h>
#include <wchar.h>
#include <initguid.h>
#include <stdbool.h>
#include <icmpapi.h>
DEFINE_GUID(CLSID_NetworkListManager, 0xDCB00C01,0x570F,0x4A9B,0x8D,0x69,0x19,0xA3,0xA3,0x9B,0x8F,0xA2);
DEFINE_GUID(IID_INetworkListManager, 0xDCB00000,0x570F,0x4A9B,0x8D,0x69,0x19,0xA3,0xA3,0x9B,0x8F,0xA2);
#include <string.h>
#define UNLEN 256
#include <fcntl.h>
#include <time.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "aflnet.h"

#define LOG_UPDATE_FREQ      5000
#define MAX_ATTEMPT          200000
#define MAX_IRP_COUNT        500
#define ARRAY_SIZE 1024
#define BUF_SIZE 0x10000

#define INFO_SIZE                       (128 << 10)             /* 128KB info string */
#define PAYLOAD_MAX_SIZE (128*1024)
#define MSG_NOSIGNAL 0


#define VULN_DRIVER_NAME "srv2.sys"
#define VULN_DRIVER_NAME2 "srv2.sys"
#define VULN_DRIVER_NAME3 "srv2.sys"

#define IOCTL 0x4f494f49 // 'IOIO'
#define WRITE 0x52575257 // 'WRITE'
#define REVERT 0x45524552 // 'RERE'
typedef unsigned int uint32_t;

//payload struct from fuzzer(should be change)
typedef struct __attribute__((__packed__)){
        uint32_t payload_length;
        uint8_t payload[PAYLOAD_MAX_SIZE-sizeof(uint32_t)];
} kAFL_custom;

unsigned char smb1_negotiate[] = {
    0x00, 0x00, 0x00, 0xD4, // NetBIOS Session Service length (212 bytes)

    // SMB Header
    0xFF, 0x53, 0x4D, 0x42, // SMB Protocol ID
    0x72,                   // Command: Negotiate Protocol
    0x00,                   // Error class
    0x00, 0x00,             // Reserved/error code
    0x00, 0x18,             // Flags
    0x43, 0xC8,             // Flags2
    0x00, 0x00,             // PID high
    0x00, 0x00, 0x00, 0x00, // Signature (8 bytes)
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,             // Reserved
    0x00, 0x00,
    0xFE, 0xFF, 0x00, 0x00, // TID
    0x00, 0x00,             // PID low
    0x00, 0xB1,             // UID
    0x00, 0x02,             // MID

    // Dialect Strings
    0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00,
    0x02, 0x4D, 0x49, 0x43, 0x52, 0x4F, 0x53, 0x4F, 0x46, 0x54, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x53, 0x20, 0x31, 0x2E, 0x30, 0x33, 0x00,
    0x02, 0x4D, 0x49, 0x43, 0x52, 0x4F, 0x53, 0x4F, 0x46, 0x54, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x53, 0x20, 0x33, 0x2E, 0x30, 0x00,
    0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00,
    0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,
    0x02, 0x44, 0x4F, 0x53, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00,
    0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00,
    0x02, 0x53, 0x61, 0x6D, 0x62, 0x61, 0x00,
    0x02, 0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x20, 0x31, 0x2E, 0x30, 0x00,
    0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
    0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x30, 0x30, 0x32, 0x00,
    0x02, 0x53, 0x4D, 0x42, 0x20, 0x32, 0x2E, 0x3F, 0x3F, 0x3F, 0x00

};

uint64_t T_IMG_base;
uint32_t T_IMG_size;

// for aux2 buffer
// 예: 게스트 사용자모드 C 코드
int aux2_publish(const uint32_t* seq, uint32_t seq_cnt,
                 const uint32_t* flags, uint32_t flag_cnt, const uint64_t image_base, const uint32_t image_size)
{
    nyx_aux2_desc_t d = {0};
    d.seq_ptr  = (uint32_t)(uintptr_t)seq;
    d.seq_len  = seq_cnt;
    d.flags_ptr= (uint32_t)(uintptr_t)flags;
    d.flag_cnt = flag_cnt;
    d.T_IMG_base = image_base;
    d.T_IMG_size = image_size;
    // for(int i=0; i<flag_cnt; i++){
    //     hprintf("[*main]flag_sequence[%d]: %d\n", i, flags[i]);
    // }
    // 하이퍼콜: RBX = op, RCX = &desc
    uint64_t rc = kAFL_hypercall(HYPERCALL_KAFL_USER_AUX2_PUBLISH,
                                 (uint64_t)(uintptr_t)&d);
    return (int)rc; // 0=OK, 음수=에러(아래에서 정의)
}

// int aux2_publish(const uint32_t* seq, uint32_t seq_cnt,
//                  const uint32_t* flags, uint32_t flag_cnt,
//                  uint64_t image_base, uint32_t image_size)
// {
//     nyx_aux2_desc_t d = {0};
//     d.seq_ptr  = (uint32_t)(uintptr_t)seq;
//     d.seq_len  = seq_cnt;
//     d.flags_ptr= (uint32_t)(uintptr_t)flags;
//     d.flag_cnt = flag_cnt;
//     d.image_base = image_base;
//     d.image_size = image_size;
//     for(int i=0; i<flag_cnt; i++){
//         hprintf("[*main]flag_sequence[%d]: %d\n", i, flags[i]);
//     }
//     // 하이퍼콜: RBX = op, RCX = &desc
//     uint64_t rc = kAFL_hypercall(HYPERCALL_KAFL_USER_AUX2_PUBLISH,
//                                  (uint64_t)(uintptr_t)&d);
//     return (int)rc; // 0=OK, 음수=에러(아래에서 정의)
// }


PCSTR ntoskrnl = "C:\\Windows\\System32\\ntoskrnl.exe";
PCSTR kernel_func1 = "KeBugCheck";
PCSTR kernel_func2 = "KeBugCheckEx";

FARPROC KernGetProcAddress(HMODULE kern_base, LPCSTR function){
    // error checking? bah...
    HMODULE kernel_base_in_user_mode = LoadLibraryA(ntoskrnl);
    return (FARPROC)((PUCHAR)GetProcAddress(kernel_base_in_user_mode, function) - (PUCHAR)kernel_base_in_user_mode + (PUCHAR)kern_base);
}   


UINT64 resolve_KeBugCheck(PCSTR kfunc){
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    FARPROC KeBugCheck = NULL;
    int cDrivers, i;

    if( EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)){ 
        TCHAR szDriver[ARRAY_SIZE];
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (i=0; i < cDrivers; i++){
            if(GetDeviceDriverFileName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))){
            // assuming ntoskrnl.exe is first entry seems save (FIXME)
                if (i == 0){
                    KeBugCheck = KernGetProcAddress((HMODULE)drivers[i], kfunc);
                    if (!KeBugCheck){
                        printf("[-] w00t?");
                        ExitProcess(0);
                    }
                    break;
                }
            }
        }
    }
    else{
        printf("[-] EnumDeviceDrivers failed; array size needed is %d\n", (UINT32)(cbNeeded / sizeof(LPVOID)));
        ExitProcess(0);
    }

    return  (UINT64) KeBugCheck;
}


void init_agent_handshake() {

    hprintf("Initiate fuzzer handshake...\n");

    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // Submit our CR3
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // Tell KAFL we're running in 64bit mode
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    /* Request information on available (host) capabilites (not optional) */
    volatile host_config_t host_config;
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    if (host_config.host_magic != NYX_HOST_MAGIC ||
        host_config.host_version != NYX_HOST_VERSION) {
    hprintf("host_config magic/version mismatch!\n");
    habort("GET_HOST_CNOFIG magic/version mismatch!\n");
    }

    hprintf("\thost_config.bitmap_size: 0x%lx\n", host_config.bitmap_size);
    hprintf("\thost_config.ijon_bitmap_size: 0x%lx\n", host_config.ijon_bitmap_size);
    hprintf("\thost_config.payload_buffer_size: 0x%lx\n", host_config.payload_buffer_size);

    /* reserved guest memory must be at least as large as host SHM view */
    if (PAYLOAD_MAX_SIZE < host_config.payload_buffer_size) {
        habort("Insufficient guest payload buffer!\n");
    }

    /* submit agent configuration */
    volatile agent_config_t agent_config = {0};
    agent_config.agent_magic = NYX_AGENT_MAGIC;
    agent_config.agent_version = NYX_AGENT_VERSION;

    agent_config.agent_tracing = 0; // trace by host!
    agent_config.agent_ijon_tracing = 0; // no IJON
    agent_config.agent_non_reload_mode = 1; // allow persistent
    agent_config.coverage_bitmap_size = host_config.bitmap_size;

    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

}

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;
 
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

void set_ip_range() {
    char* info_buffer = (char*)VirtualAlloc(0, INFO_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(info_buffer, 0xff, INFO_SIZE);
    memset(info_buffer, 0x00, INFO_SIZE);
    int pos = 0;

   LPVOID drivers[ARRAY_SIZE];
   DWORD cbNeeded;
   int cDrivers, i;
   NTSTATUS status;
   int index =0;

   if( EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
   {
        cDrivers = cbNeeded / sizeof(drivers[0]);
        PRTL_PROCESS_MODULES ModuleInfo;
 
        ModuleInfo=(PRTL_PROCESS_MODULES)VirtualAlloc(NULL,1024*1024,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
     
        if(!ModuleInfo){
            habort("set_ip_range: VirtualAlloc failed\n");
            goto fail;
        }
     
        if(!NT_SUCCESS(status=NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11,ModuleInfo,1024*1024,NULL))){
            VirtualFree(ModuleInfo,0,MEM_RELEASE);
            habort("set_ip_range: NtQuerySystemInformation failed\n");
            goto fail;
        }

        pos += sprintf(info_buffer + pos, "kAFL Windows x86-64 Kernel Addresses (%d Drivers)\n\n", cDrivers);
        // _tprintf(TEXT("kAFL Windows x86-64 Kernel Addresses (%d Drivers)\n\n"), cDrivers);      
        pos += sprintf(info_buffer + pos, "START-ADDRESS\t\tEND-ADDRESS\t\tDRIVER\n");
        // _tprintf(TEXT("START-ADDRESS\t\tEND-ADDRESS\t\tDRIVER\n"));      
        for (i=0; i < cDrivers; i++ ){
            pos += sprintf(info_buffer + pos, "0x%p\t0x%lld\t%s\n", drivers[i], ((UINT64)drivers[i]) + ModuleInfo->Modules[i].ImageSize, ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
            // hprintf("%s: driver FullPathName: %s\n", __func__, ModuleInfo->Modules[i].FullPathName);
        if(strstr((const char*)ModuleInfo->Modules[i].FullPathName, VULN_DRIVER_NAME) > 0 || 
        strstr((const char*)ModuleInfo->Modules[i].FullPathName, VULN_DRIVER_NAME2) > 0 ||
        strstr((const char*)ModuleInfo->Modules[i].FullPathName, VULN_DRIVER_NAME3) > 0
        ) {
                T_IMG_base = (UINT64)drivers[i];
                T_IMG_size = (UINT32)ModuleInfo->Modules[i].ImageSize;
                hprintf("[+] msFuzz: Found target driver base: 0x%llx, size: 0x%x\n", T_IMG_base, T_IMG_size);


                uint64_t buffer[3];
                buffer[0] = (UINT64)drivers[i];
                buffer[1] = (UINT64)drivers[i] + ModuleInfo->Modules[i].ImageSize;
                buffer[2] = index++;
                kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (UINT64)buffer);
        hprintf("[+] msFuzz: SET_IP_RANGE to %s\n",ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
            }
            // hprintf("0x%p\t0x%p\t%s\n", drivers[i], drivers[i]+ModuleInfo->Modules[i].ImageSize, ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
        }
   }
   else {
        hprintf("%s: EnumDeviceDrivers failed\n", __func__);
        goto fail;
   }
   if(index >=1)
    return;
    fail:
        habort("FAIL! NO MATCH!\n");
        exit(1);
}

void init_panic_handlers() {
    UINT64 panic_kebugcheck = 0x0;
    UINT64 panic_kebugcheck2 = 0x0;
    panic_kebugcheck = resolve_KeBugCheck(kernel_func1);
    panic_kebugcheck2 = resolve_KeBugCheck(kernel_func2);
    hprintf("Submitting bug check handlers\n");
    /* submit panic address */
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck);
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck2);
}

int net_send(SOCKET sockfd, DWORD timeout_ms, char *mem, unsigned int len) {
    unsigned int byte_count = 0;
    int n;
    // hprintf("%x %x %x %x %x %x %x, len: %u\n", mem[0], mem[1], mem[2], mem[3], mem[4], mem[5], mem[6], len);
    // hprintf("timeout: %d\n", timeout_ms);

    int err = 0;
    int err_len = sizeof(err);
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char*)&err, &err_len);
    // hprintf("SO_ERROR: %d\n", err);

    // WSAPOLLFD pfd[1];
    // pfd[0].fd = sockfd;
    // pfd[0].events = POLLOUT;
    // pfd[0].revents = 0;
    // // Set send timeout
    // hprintf("before poll check\n");
    // setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout_ms, sizeof(timeout_ms));
    // int rv = WSAPoll(pfd, 1, timeout_ms);  // 1 ms poll
    // hprintf("net_sent start\n");
    // if (rv > 0) {
    //     if (pfd[0].revents & POLLOUT) {
            while (byte_count < len) {
                hprintf("byte_count: %u, len: %u\n", byte_count, len);
                // // Sleep(1); // 1ms delay (closest to usleep(10))
                // sleep_ms(1000);
                // hprintf("send message(c): %c\n", mem[byte_count]);
                n = send(sockfd, &mem[byte_count], len - byte_count, 0); // no MSG_NOSIGNAL)
                hprintf("sent byte is %n\n", n);
                // hprintf("%c %c %c %c %c %c %c\n", mem[0], mem[1], mem[2], mem[3], mem[4], mem[5], mem[6]);
                if (n == 0) {
                    hprintf("send returned 0, byte_count: %u\n", byte_count);
                    return byte_count;
                }
                if (n == SOCKET_ERROR) {
                    hprintf("send failed with error\n");
                    return -1;
                }
                byte_count += n;
            }
        // }
    // }
    // else{
    //     hprintf("socket unwritable\n");
    // }
    // hprintf("net_send finish\n");
    hprintf("returned byte_count is %u\n", byte_count);
    return byte_count;
}

// return 0 = 성공(한 바이트라도 수신), 1 = 실패/종료
int net_recv(SOCKET s, DWORD budget, int step,
             unsigned char **response_buf, unsigned int *len)
{
    // 1) 반복/아이들 예산 (시간 의미 없음)
    int max_iters = 0;
    if (budget > 0 && step > 0) max_iters = (int)(budget / step);
    if (max_iters < 100)     max_iters = 3000;
    if (max_iters > 100000)  max_iters = 100000;

    // 2) Overlapped 준비
    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) {
        hprintf("CreateEvent failed: %lu\n", GetLastError());
        return 1;
    }

    char tmp[4096];
    WSABUF buf;
    buf.buf = tmp;
    buf.len = sizeof(tmp);

    DWORD flags = 0;
    DWORD recvd = 0;

    // 3) 비동기 수신 요청
    int r = WSARecv(s, &buf, 1, &recvd, &flags, &ov, NULL);
    if (r == 0) {
        // 즉시 완료
        if (recvd == 0) { CloseHandle(ov.hEvent); hprintf("net_recv: immediate recv 0 bytes\n"); return (recvd > 0) ? 0 : 1; }
        *response_buf = (unsigned char*)ck_realloc(*response_buf, *len + recvd + 1);
        if (!*response_buf) { CloseHandle(ov.hEvent); return 1; }
        memcpy(*response_buf + *len, tmp, recvd);
        (*response_buf)[*len + recvd] = '\0';
        *len += recvd;
        hprintf("net_recv: immediate recv %d bytes\n", recvd);
        CloseHandle(ov.hEvent);
        return 0;
    }

    if (r == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e != WSA_IO_PENDING) {
            // Overlapped 미지원/기타 오류 → 아래 대안 B로 폴백 가능
            hprintf("WSARecv error: %d\n", e);
            CloseHandle(ov.hEvent);
            return 1;
        }
    }

    // 4) 0ms 이벤트 폴링 (시간 의존 X)
    for (int it = 0; it < max_iters; ++it) {
        DWORD w = WaitForSingleObject(ov.hEvent, 0);
        if (w == WAIT_OBJECT_0) {
            BOOL ok = WSAGetOverlappedResult(s, &ov, &recvd, FALSE, &flags);
            if (!ok) {
                int e = WSAGetLastError();
                hprintf("WSAGetOverlappedResult error: %d\n", e);
                CloseHandle(ov.hEvent);
                return (recvd > 0) ? 0 : 1;
            }
            if (recvd == 0) { CloseHandle(ov.hEvent); return (*len > 0) ? 0 : 1; }

            *response_buf = (unsigned char*)ck_realloc(*response_buf, *len + recvd + 1);
            if (!*response_buf) { CloseHandle(ov.hEvent); return 1; }
            memcpy(*response_buf + *len, tmp, recvd);
            (*response_buf)[*len + recvd] = '\0';
            *len += recvd;
            hprintf("net_recv: immediate recv %d bytes\n", recvd);

            CloseHandle(ov.hEvent);
            return 0;
        }
        else if (w == WAIT_FAILED) {
            hprintf("WaitForSingleObject failed: %lu\n", GetLastError());
            CloseHandle(ov.hEvent);
            return (*len > 0) ? 0 : 1;
        }

        // 과도한 CPU 점유 방지
        if ((it & 0x3F) == 0) SwitchToThread();
    }

    // 5) 예산 소진 → 미완료 I/O 취소 후 종료
    CancelIoEx((HANDLE)s, &ov);   // Vista+
    CloseHandle(ov.hEvent);
    return (*len > 0) ? 0 : 1;
}

void extract_requests_SMB(unsigned char* buf, unsigned int buf_size, region_t** regions_out, uint32_t** flag_sequence_out, unsigned int* region_count_ref)
{
    const unsigned char smb3_signature[4] = {0xFD, 'S', 'M', 'B'};
    const unsigned char smb2_signature[4] = {0xFE, 'S', 'M', 'B'};
    const unsigned char smb1_signature[4] = {0xFF, 'S', 'M', 'B'};
  
    region_t *regions = NULL;
    unsigned int region_count = 0;

    unsigned int i =0;  // consider least 4bytes are NetBIOS header
    while (i + 4 <= buf_size) {
        // NetBIOS length field (3 bytes, big-endian)
        unsigned int netbios_len = (buf[i + 1] << 16) | (buf[i + 2] << 8) | buf[i + 3];
        unsigned int smb_msg_len = 4 + netbios_len;  // total: NetBIOS header + SMB message
        // hprintf("[** extract_requests_SMB] index i: %u, smb_msg_len: %u, buf_size: %u\n", i, smb_msg_len, buf_size);
        if (i + smb_msg_len > buf_size){
            hprintf("[** extract_requests_SMB] bad message: i: %u, smb_msg_len: %u, buf_size: %u\n", i, smb_msg_len, buf_size);
            break;
        }
        if (memcmp(buf + i + 4, smb3_signature, 4) == 0){
            //SMBv3
            unsigned int real_start = (i >= 4) ? i - 4 : i;

            if (region_count > 0) {
                regions[region_count - 1].end_byte = real_start - 1;
            }
        
            region_count++;
            regions = (region_t *)ck_realloc(regions, region_count * sizeof(region_t));
            regions[region_count - 1].start_byte = real_start;
            regions[region_count - 1].end_byte = buf_size - 1;  // temp
            regions[region_count - 1].state_sequence = NULL;
            regions[region_count - 1].state_count = 1;
            // int length = regions[region_count -1].end_byte - regions[region_count -1].start_byte+1;
            // hprintf("[** extract_requests_SMB] Region[%u]: length: %u\n", region_count, length);
            // hprintf("end_byte: %d, start_byte: %d\n", regions[region_count -1].end_byte, regions[region_count -1].start_byte);
            //   }
            // }
        }
        else if (memcmp(buf + i + 4, smb2_signature, 4) == 0) {
            // SMBv2+
            // hprintf("smbv2 netbios_len: %u, smb_msg_len: %u\n", netbios_len, smb_msg_len);
            if (i + 20 <= buf_size) {
                unsigned int flags = buf[i + 20] |
                                    (buf[i + 21] << 8) |
                                    (buf[i + 22] << 16) |
                                    (buf[i + 23] << 24);

                if ((flags & 0x00000001) == 0) {  // request if Response flag not set
                    hprintf("[** extract_requests_SMB] before Region[%u]: smb_msg_len: %u\n", region_count, smb_msg_len);
                    regions = (region_t *)ck_realloc(regions, (region_count+1) * sizeof(region_t));
                    regions[region_count].start_byte = i;
                    regions[region_count].end_byte = i + smb_msg_len - 1;  // temp
                    regions[region_count].state_sequence = NULL;
                    regions[region_count].state_count = 0;
                    unsigned int j = i;
                    while(j<i+smb_msg_len-1){
                        if(memcmp(buf + j, smb2_signature, 4) == 0){
                            regions[region_count].state_count += 1;
                        }
                        j++;
                    }
                    // hprintf("[** extract_requests_SMB] after Region[%u]: start_byte: %u, end_byte: %u\n", region_count, regions[region_count].start_byte, regions[region_count].end_byte);
                    region_count++;
                }
            }
        } else if (memcmp(buf + i + 4, smb1_signature, 4) == 0) {        
            // SMBv1
            hprintf("netbios_len: %u, smb_msg_len: %u\n", netbios_len, smb_msg_len);
            if (i + 10 <= buf_size) {
                unsigned char flags = buf[i + 13];
                unsigned char flags2 = buf[i + 14];
                unsigned short command = buf[i + 8];

                // SMBv1 request (Simple filter: Response flag not set)
                if ((flags & 0x80) == 0) {  // if bit7 == 1 then response
                    regions = (region_t *)ck_realloc(regions, (region_count+1) * sizeof(region_t));
                    regions[region_count].start_byte = i;
                    regions[region_count].end_byte = i+ smb_msg_len - 1;  // temp
                    regions[region_count].state_sequence = NULL;
                    regions[region_count].state_count = 1;
                    region_count++;
                }
            }
        }
        // hprintf("[** extract_requests_SMB] end loop Region[%u]: start_byte: %u, end_byte: %u\n", region_count, regions[region_count-1].start_byte, regions[region_count-1].end_byte);
        i += smb_msg_len;
    }
    
    if (region_count == 0 && buf_size > 0) {
        hprintf("[** extract_requests_SMB] bad message: Region[%u]: smb_msg_len: %u\n", region_count, buf_size);
        regions = (region_t *)ck_realloc(regions, sizeof(region_t));
        regions[0].start_byte = 0;
        regions[0].end_byte = buf_size - 1;
        regions[0].state_sequence = NULL;
        regions[0].state_count = 0;

        region_count = 1;
    }
    //for flag sequence
    uint32_t* flag_sequence = (uint32_t*)malloc(region_count * sizeof(uint32_t));
    for (i = 0; i < region_count; i++) {
        flag_sequence[i] = regions[i].state_count; // default 1
        hprintf("[** extract_requests_SMB] flag_sequence[%u]: %u\n", i, flag_sequence[i]);
    }

    *region_count_ref = region_count;
    *regions_out = regions;
    *flag_sequence_out = flag_sequence;
    // return regions, flag_sequence;
}

khash_t(32) *message_code_map = NULL;
static u32 message_code_counter = 1;

void init_message_code_map(){
  message_code_map = kh_init(32);
}

void destroy_message_code_map(){
  kh_destroy(32, message_code_map);
}

u32 get_mapped_message_code (u32 ori_message_code){
    u32 mapped_message_code = 0;
    khiter_t k = kh_get(32, message_code_map, ori_message_code);
    if (k == kh_end(message_code_map)) {
        int ret;
        k = kh_put(32, message_code_map, ori_message_code, &ret);
        
        kh_value(message_code_map, k) = message_code_counter;

        mapped_message_code = message_code_counter;

        message_code_counter++;
    }
    else {
        mapped_message_code = kh_value(message_code_map, k);
    }
    return mapped_message_code;
}
unsigned int* extract_response_codes_SMB(unsigned char* buf, unsigned int buf_size, unsigned int *state_count_ref)
{
    const unsigned char smb2_signature[4] = {0xFE, 'S', 'M', 'B'};
    const unsigned char smb1_signature[4] = {0xFF, 'S', 'M', 'B'};
    unsigned int *state_sequence = NULL;
    unsigned int state_count = 0;
    unsigned int i = 0;

    // 초기 상태 0 삽입
    state_sequence = (unsigned int *)ck_realloc(NULL, sizeof(unsigned int));
    state_sequence[state_count++] = 0;

    // state_sequence_counts = (unsigned int *)ck_realloc(NULL, sizeof(unsigned int));

    // printf("[******] Buffer size: %u bytes\n", buf_size); // @ see
    // printf("[******] Buffer preview (first 64 bytes):\n"); // @ see
    // for (unsigned int j = 0; j < buf_size; j++) {
    //     printf("%02X ", buf[j]);
    //     if ((j + 1) % 56 == 0) printf("\n");
    // }
    // printf("\n");
    
    // SMB2 헤더는 고정 64바이트
    while (i + 64 <= buf_size) {
        // SMB2 시그니처 확인
        if (memcmp(buf + i, smb2_signature, 4) == 0) {
        // Flags에서 응답인지 확인 (offset 16~19)
            unsigned int flags = buf[i + 16] |
                                (buf[i + 17] << 8) |
                                (buf[i + 18] << 16) |
                                (buf[i + 19] << 24);

            // SMB2_FLAGS_SERVER_TO_REDIR (0x00000001) 가 설정되어 있어야 응답
            // printf("[***response==1***] flags: 0x%08X\n", flags); // @
            if ((flags & 0x00000001) != 0) {
                // Command (offset 12~13, little endian)
                // hprintf("[** extract_response_codes_SMB] SIG2 command: %d %d\n", buf[i + 12], buf[i + 13]);
                unsigned int command = buf[i + 12] | (buf[i + 13] << 8);
                unsigned int message_code = get_mapped_message_code(command);

                state_sequence = (unsigned int *)ck_realloc(state_sequence, (state_count + 1) * sizeof(unsigned int));
                state_sequence[state_count++] = message_code;
            }

            // 다음 SMB2 시그니처로 이동
            i++;
        } 
        // SMB1
        else if (memcmp(buf + i, smb1_signature, 4) == 0) {
            // Flags (offset 9) - bit 7 = response
            unsigned char flags = buf[i + 9];
            if ((flags & 0x80) != 0) {
                // Command (offset 4)
                // hprintf("[** extract_response_codes_SMB] SIG1 command: %d\n", buf[i + 4]);
                unsigned int command = buf[i + 4];
                unsigned int message_code = get_mapped_message_code(command);

                state_sequence = (unsigned int *)ck_realloc(state_sequence, (state_count + 1) * sizeof(unsigned int));
                state_sequence[state_count++] = message_code;
            }
            i++;
        }
        
        else {
            i++;
        }
    }
    // hprintf("[** extract_response_codes_SMB] Extracted %u response codes\n", state_count-1);
    *state_count_ref = state_count;
    return state_sequence;
}


klist_t(lms) *construct_kl_messages(u8* payload, region_t *regions, uint32_t region_count)
{
    klist_t(lms) *kl_messages = kl_init(lms);
    if (!kl_messages) {
        habort("Failed to initialize kl_messages list\n");
    }
    for (uint32_t i = 0; i < region_count; i++) {
        uint32_t len = regions[i].end_byte - regions[i].start_byte + 1;
    
        message_t *m = (message_t *) ck_alloc(sizeof(message_t));
        m->mdata = (char *) ck_alloc(len);
        m->msize = len;
        memcpy(m->mdata, payload + regions[i].start_byte, len);
        // hprintf("region[%u]: kl_message len: %u\n", i, m->msize);
        // hprintf("end_byte: %d, start_byte: %d\n", regions[i].end_byte, regions[i].start_byte);
        // hprintf("kl_message data: %x %x %x %x %x %x %x\n", m->mdata[0], m->mdata[1], m->mdata[2], m->mdata[3], m->mdata[4], m->mdata[5], m->mdata[6]);

        *kl_pushp(lms, kl_messages) = m;
    }

    return kl_messages;
}


// debug for smb service open and running
#include <winsvc.h>
int is_smb_service_running() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        hprintf("OpenSCManager failed: %lu\n", GetLastError());
        return 0;
    }

    SC_HANDLE hService = OpenService(hSCManager, "lanmanserver", SERVICE_QUERY_STATUS);
    if (!hService) {
        hprintf("OpenService(lanmanserver) failed: %lu\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    BOOL success = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    if (!success) {
        hprintf("QueryServiceStatusEx failed: %lu\n", GetLastError());
        return 0;
    }

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        hprintf("[+] SMB service (lanmanserver) is running.\n");
        return 1;
    } else {
        hprintf("[-] SMB service is NOT running. Current state: %lu\n", ssp.dwCurrentState);
        return 0;
    }
}

int wait_for_smb_service_running(DWORD timeout_ms) {
    DWORD elapsed = 0;
    DWORD sleep_interval = 100; // ms

    while (elapsed < timeout_ms) {
        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!hSCManager) return 0;

        SC_HANDLE hService = OpenService(hSCManager, "lanmanserver", SERVICE_QUERY_STATUS);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return 0;
        }

        SERVICE_STATUS_PROCESS ssp;
        DWORD bytesNeeded;
        BOOL success = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded);

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);

        if (!success) return 0;

        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            hprintf("[+] SMB service is running.\n");
            return 1;
        }

        hprintf("[*] Waiting for SMB service to start... Current state: %lu\n", ssp.dwCurrentState);
        // subsititute sleep()
        LARGE_INTEGER freq, start, now;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);

        while (1) {
            QueryPerformanceCounter(&now);
            double elapsed_ms = 1000.0 * (now.QuadPart - start.QuadPart) / freq.QuadPart;
            if (elapsed_ms > 100) break;
        }
        elapsed += sleep_interval;
        // @@@@@@@@@@    
    }

    hprintf("[-] SMB service failed to reach RUNNING state within timeout.\n");
    return 0;
}

#include <iphlpapi.h>

//timer function
void sleep_ms(DWORD ms) {
    LARGE_INTEGER freq, start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    do {
        QueryPerformanceCounter(&now);
    } while ((1000.0 * (now.QuadPart - start.QuadPart) / freq.QuadPart) < ms);
}
//for static ip in guest @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
static int run(const wchar_t* cmd) {
    STARTUPINFOW si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",
                        (LPWSTR)cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        hprintf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}
// check ip,router
static uint32_t ip_to_u32(const char* ip) {
    return inet_addr(ip); // network byte order
}
static void u32_to_ip(uint32_t ip, char out[INET_ADDRSTRLEN]) {
    struct in_addr a; a.s_addr = ip;
    strncpy(out, inet_ntoa(a), INET_ADDRSTRLEN);
}

static void check_routes(uint32_t expect_ifindex, const char* cidr_net, uint32_t cidr_mask, const char* expect_gw) {
    PMIB_IPFORWARDTABLE tbl = NULL;
    ULONG sz = 0;
    if (GetIpForwardTable(NULL, &sz, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        tbl = (PMIB_IPFORWARDTABLE)malloc(sz);
    }
    if (!tbl || GetIpForwardTable(tbl, &sz, FALSE) != NO_ERROR) {
        hprintf("GetIpForwardTable failed\n");
        if (tbl) free(tbl);
        return;
    }
    hprintf("=== Routes (route print) ===\n");
    uint32_t net = ip_to_u32(cidr_net);
    uint32_t mask = cidr_mask;
    uint32_t gw_expect = ip_to_u32(expect_gw);

    bool got_onlink = false, got_default = false;
    for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
        MIB_IPFORWARDROW* r = &tbl->table[i];
        char dest[INET_ADDRSTRLEN], msk[INET_ADDRSTRLEN], gate[INET_ADDRSTRLEN];
        u32_to_ip(r->dwForwardDest, dest);
        u32_to_ip(r->dwForwardMask, msk);
        u32_to_ip(r->dwForwardNextHop, gate);
        hprintf("  %s  %s  gw %s  IfIndex=%lu  metric=%lu\n",
               dest, msk, gate, r->dwForwardIfIndex, r->dwForwardMetric1);

        if (r->dwForwardDest == net && r->dwForwardMask == mask) {
            if (r->dwForwardIfIndex == expect_ifindex) got_onlink = true;
        }
        if (r->dwForwardDest == 0 && r->dwForwardMask == 0 && r->dwForwardNextHop == gw_expect) {
            if (!expect_ifindex || r->dwForwardIfIndex == expect_ifindex) got_default = true;
        }
    }
    hprintf("  -> on-link %s/24 : %s\n", cidr_net, got_onlink ? "OK" : "MISSING");
    hprintf("  -> default via %s : %s\n", expect_gw, got_default ? "OK" : "MISSING");
    free(tbl);
}

static BOOL parse_mac_w(const wchar_t* mac_str, BYTE out[6]) {
    unsigned v[6];
    if (!mac_str) return FALSE;
    // 콜론(:), 하이픈(-) 둘 다 허용
    int n = swscanf(mac_str, L"%2x%*[:\\-]%2x%*[:\\-]%2x%*[:\\-]%2x%*[:\\-]%2x%*[:\\-]%2x",
                    &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
    if (n != 6) return FALSE;
    for (int i = 0; i < 6; i++) out[i] = (BYTE)v[i];
    return TRUE;
}

static BOOL mac_equal(const BYTE a[6], const BYTE b[6]) {
    for (int i = 0; i < 6; i++) if (a[i] != b[i]) return FALSE;
    return TRUE;
}

// MAC 으로 어댑터 FriendlyName 찾기
// out_name(길이 cch_out): 성공 시 FriendlyName을 넣어줌
static BOOL find_iface_name_by_mac(const wchar_t* target_mac_str, wchar_t* out_name, size_t cch_out) {
    BYTE target[6];
    if (!parse_mac_w(target_mac_str, target)) {
        hprintf("parse_mac_w() failed for: %ls\n", target_mac_str);
        return FALSE;
    }

    ULONG sz = 0;
    GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, NULL, &sz);
    IP_ADAPTER_ADDRESSES* aa = (IP_ADAPTER_ADDRESSES*)malloc(sz);
    if (!aa) {
        hprintf("malloc() failed for GetAdaptersAddresses\n");
        return FALSE;
    }
    DWORD rc = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, aa, &sz);
    if (rc != NO_ERROR) {
        hprintf("GetAdaptersAddresses failed: %lu\n", rc);
        free(aa);
        return FALSE;
    }

    BOOL found = FALSE;
    for (IP_ADAPTER_ADDRESSES* a = aa; a; a = a->Next) {
        if (a->PhysicalAddressLength == 6) {
            if (mac_equal(a->PhysicalAddress, target)) {
                // FriendlyName 반환
                wcsncpy(out_name, a->FriendlyName, cch_out - 1);
                out_name[cch_out - 1] = L'\0';
                found = TRUE;
                break;
            }
        }
    }

    if (!found) {
        // 디버깅 도움: 모든 NIC 목록/맥 찍기
        for (IP_ADAPTER_ADDRESSES* a = aa; a; a = a->Next) {
            if (a->PhysicalAddressLength == 6) {
                hprintf("[IF] %ls  MAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
                        a->FriendlyName,
                        a->PhysicalAddress[0], a->PhysicalAddress[1], a->PhysicalAddress[2],
                        a->PhysicalAddress[3], a->PhysicalAddress[4], a->PhysicalAddress[5]);
            } else {
                hprintf("[IF] %ls  (no MAC or non-ethernet)\n", a->FriendlyName);
            }
        }
        hprintf("target MAC not found: %ls\n", target_mac_str);
    }

    free(aa);
    return found;
}

// packet modifying for ntlm @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
typedef struct { uint8_t MsgType; uint8_t LenHi; uint16_t LenLo; } NBSS_HDR;

typedef struct {
    uint8_t  Proto[4]; /*FE 'S' 'M' 'B'*/
    uint16_t StructSize; uint16_t CreditCharge;
    uint32_t Status_or_ChanSeq;
    uint16_t Command; uint16_t Credit;
    uint32_t Flags; uint32_t NextCmd;
    uint64_t MessageId;
    uint32_t Reserved;
    uint32_t TreeId;
    uint64_t SessionId;
    uint64_t Signature[2];
} SMB2_HDR;

typedef struct {
    uint16_t StructureSize;     // 0x0008
    uint16_t SessionFlags;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    /* Buffer follows */
} SMB2_SESSSETUP_RESP;

// NTLM Type-2 최소 레이아웃(필요 필드만)
typedef struct {
    char     Sig[8];            // "NTLMSSP\0"
    uint32_t Type;              // 0x00000002
    uint16_t TargetNameLen, TargetNameMaxLen;
    uint32_t TargetNameOffset;
    uint32_t NegFlags;
    uint8_t  ServerChallenge[8];
    uint8_t  Reserved[8];
    uint16_t TargetInfoLen, TargetInfoMaxLen;
    uint32_t TargetInfoOffset;
    /* ... variable data ... */
} NTLM_TYPE2;
#pragma pack(pop)

// type3-nt/ln response make code
// ------------------ 작은 유틸 ------------------
static void write_u32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void write_u64le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

// UTF-8 → UTF-16LE 변환 (Windows API 사용)
static int utf8_to_utf16le(const char *s, WCHAR **out_wstr, DWORD *out_bytes) {
    if (!s || !out_wstr || !out_bytes) return 0;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (wlen <= 0) return 0;
    WCHAR *wbuf = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, wlen * sizeof(WCHAR));
    if (!wbuf) return 0;
    if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, wbuf, wlen)) {
        HeapFree(GetProcessHeap(), 0, wbuf);
        return 0;
    }
    // out_bytes: 널 포함한 바이트 길이(필요에 따라 -2로 널 제외 길이 사용 가능)
    *out_wstr  = wbuf;
    *out_bytes = (DWORD)(wlen * sizeof(WCHAR));
    return 1;
}

// UTF-16LE 대문자화 (NTLM은 User를 대문자 변환하여 사용, 로캘 비의존적으로)
static int ucs2_upper_invariant(WCHAR *wstr) {
    if (!wstr) return 0;
    int len = (int)wcslen(wstr);
    if (len == 0) return 1;
    // LOCALE_INVARIANT 사용
    int outLen = LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, wstr, len, NULL, 0);
    if (outLen <= 0) return 0;
    WCHAR *tmp = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, (outLen + 1) * sizeof(WCHAR));
    if (!tmp) return 0;
    if (!LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, wstr, len, tmp, outLen)) {
        HeapFree(GetProcessHeap(), 0, tmp);
        return 0;
    }
    tmp[outLen] = L'\0';
    // 결과를 원본 버퍼에 다시 복사 (원본 버퍼가 충분하다고 가정: 여기선 MultiByteToWideChar로 생성했으니 충분)
    wcscpy(wstr, tmp);
    HeapFree(GetProcessHeap(), 0, tmp);
    return 1;
}

// Windows FILETIME (1601-01-01 기준 100ns 틱)
static uint64_t filetime_now_100ns() {
    FILETIME ft;
    // 고정밀이 가능하면 사용
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (hKernel) {
        typedef VOID (WINAPI *PFN)(LPFILETIME);
        PFN pGetSystemTimePreciseAsFileTime = (PFN)GetProcAddress(hKernel, "GetSystemTimePreciseAsFileTime");
        if (pGetSystemTimePreciseAsFileTime) {
            pGetSystemTimePreciseAsFileTime(&ft);
        } else {
            GetSystemTimeAsFileTime(&ft);
        }
    } else {
        GetSystemTimeAsFileTime(&ft);
    }
    ULARGE_INTEGER uli;
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart; // 이미 100ns 단위
}

// 안전 난수
static int rnd_bytes(uint8_t *buf, ULONG len) {
    NTSTATUS st = BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0);
}

// ------------------ CNG 해시/맥 ------------------
static int md4_hash(const uint8_t *data, ULONG len, uint8_t out16[16]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD objLen=0, cb=0;
    PUCHAR obj = NULL;
    int ok = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD4_ALGORITHM, NULL, 0)) goto cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0)) goto cleanup;

    obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, objLen);
    if (!obj) goto cleanup;

    if (BCryptCreateHash(hAlg, &hHash, obj, objLen, NULL, 0, 0)) goto cleanup;
    if (BCryptHashData(hHash, (PUCHAR)data, len, 0)) goto cleanup;
    if (BCryptFinishHash(hHash, out16, 16, 0)) goto cleanup;

    ok = 1;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (obj) HeapFree(GetProcessHeap(), 0, obj);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static int hmac_md5(const uint8_t *key, ULONG keylen,
                    const uint8_t *data, ULONG datalen,
                    uint8_t out16[16]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD objLen=0, cb=0;
    PUCHAR obj = NULL;
    int ok = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)) goto cleanup;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0)) goto cleanup;

    obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, objLen);
    if (!obj) goto cleanup;

    if (BCryptCreateHash(hAlg, &hHash, obj, objLen, (PUCHAR)key, keylen, 0)) goto cleanup;
    if (BCryptHashData(hHash, (PUCHAR)data, datalen, 0)) goto cleanup;
    if (BCryptFinishHash(hHash, out16, 16, 0)) goto cleanup;

    ok = 1;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (obj) HeapFree(GetProcessHeap(), 0, obj);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// ------------------ NTLMv2 핵심 ------------------
// NT hash = MD4( password in UTF-16LE )
static int nt_hash_from_password_utf8(const char *password, uint8_t out16[16]) {
    WCHAR *w = NULL; DWORD wbytes = 0;
    if (!utf8_to_utf16le(password, &w, &wbytes)) return 0;
    // wbytes는 널 포함. MD4 입력은 널 제외
    if (!md4_hash((const uint8_t*)w, wbytes - sizeof(WCHAR), out16)) {
        HeapFree(GetProcessHeap(), 0, w);
        return 0;
    }
    HeapFree(GetProcessHeap(), 0, w);
    return 1;
}

// NTLMv2 Hash = HMAC-MD5( NT-Hash(password), Upper(User) + Domain ) where both are UTF-16LE
static int ntlmv2_hash_from_up_utf8_dom_utf8(const char *user_utf8,
                                             const char *domain_utf8,
                                             const char *password_utf8,
                                             uint8_t out16[16]) {
    uint8_t nthash[16];
    if (!nt_hash_from_password_utf8(password_utf8, nthash)) return 0;

    // User (UTF-8 → UTF-16LE) & Upper
    WCHAR *u = NULL; DWORD ubytes = 0;
    if (!utf8_to_utf16le(user_utf8, &u, &ubytes)) return 0;
    if (!ucs2_upper_invariant(u)) { HeapFree(GetProcessHeap(), 0, u); return 0; }

    // Domain (UTF-8 → UTF-16LE)
    WCHAR *d = NULL; DWORD dbytes = 0;
    if (!utf8_to_utf16le(domain_utf8, &d, &dbytes)) { HeapFree(GetProcessHeap(), 0, u); return 0; }

    // 널 제거
    DWORD ubytes_nz = ubytes >= sizeof(WCHAR) ? (ubytes - sizeof(WCHAR)) : 0;
    DWORD dbytes_nz = dbytes >= sizeof(WCHAR) ? (dbytes - sizeof(WCHAR)) : 0;

    // Upper(User) || Domain
    DWORD msglen = ubytes_nz + dbytes_nz;
    uint8_t *msg = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, msglen);
    if (!msg) { HeapFree(GetProcessHeap(), 0, u); HeapFree(GetProcessHeap(), 0, d); return 0; }
    memcpy(msg, (uint8_t*)u, ubytes_nz);
    memcpy(msg + ubytes_nz, (uint8_t*)d, dbytes_nz);

    int ok = hmac_md5(nthash, 16, msg, msglen, out16);

    HeapFree(GetProcessHeap(), 0, msg);
    HeapFree(GetProcessHeap(), 0, u);
    HeapFree(GetProcessHeap(), 0, d);
    return ok;
}

// NTLMSSP AV_PAIR IDs
#define NTLMSSP_AV_EOL            0x0000
#define NTLMSSP_AV_NB_COMPUTER    0x0001
#define NTLMSSP_AV_NB_DOMAIN      0x0002
#define NTLMSSP_AV_DNS_COMPUTER   0x0003
#define NTLMSSP_AV_DNS_DOMAIN     0x0004
#define NTLMSSP_AV_DNS_TREE       0x0005
#define NTLMSSP_AV_TARGET_NAME    0x0009
#define NTLMSSP_AV_FLAGS          0x0006
#define NTLMSSP_AV_TIMESTAMP      0x0007

#pragma pack(push,1)
typedef struct {
    uint16_t AvId;
    uint16_t AvLen;
    // followed by AvLen bytes of Value
} AV_PAIR;
#pragma pack(pop)

// SPN AV_PAIR 생성
static int make_spn_avpair(
    const char *service_utf8,
    const char *dnsHostname_utf8,
    BYTE **out_buf,            // AV_PAIR 바이트 결과
    DWORD *out_len_bytes       // 전체 길이(헤더+값)
) {
    if (!service_utf8 || !dnsHostname_utf8 || !out_buf || !out_len_bytes) return 0;

    WCHAR *svc_w = NULL, *host_w = NULL;
    DWORD svc_bytes_with_null = 0, host_bytes_with_null = 0;

    if (!utf8_to_utf16le(service_utf8, &svc_w, &svc_bytes_with_null)) return 0;
    if (!utf8_to_utf16le(dnsHostname_utf8, &host_w, &host_bytes_with_null)) {
        HeapFree(GetProcessHeap(), 0, svc_w);
        return 0;
    }

    // 널 제외 길이로 환산
    DWORD svc_bytes = (svc_bytes_with_null >= 2) ? (svc_bytes_with_null - 2) : 0;
    DWORD host_bytes = (host_bytes_with_null >= 2) ? (host_bytes_with_null - 2) : 0;

    // 슬래시(UTF-16LE) 2바이트
    const WCHAR slash_w = L'/';
    const DWORD slash_bytes = sizeof(WCHAR);

    // value = "service/hostname" (UTF-16LE, 널 없이 연속)
    DWORD value_bytes = svc_bytes + slash_bytes + host_bytes;

    // AV_PAIR 헤더 + value
    DWORD total = sizeof(AV_PAIR) + value_bytes;
    BYTE *buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
    if (!buf) {
        HeapFree(GetProcessHeap(), 0, svc_w);
        HeapFree(GetProcessHeap(), 0, host_w);
        return 0;
    }

    AV_PAIR *hdr = (AV_PAIR*)buf;
    hdr->AvId  = NTLMSSP_AV_TARGET_NAME;
    hdr->AvLen = (uint16_t)value_bytes;

    BYTE *p = buf + sizeof(AV_PAIR);
    memcpy(p, svc_w, svc_bytes);                     p += svc_bytes;
    memcpy(p, &slash_w, slash_bytes);                p += slash_bytes;
    memcpy(p, host_w, host_bytes);                   p += host_bytes;

    *out_buf = buf;
    *out_len_bytes = total;

    HeapFree(GetProcessHeap(), 0, svc_w);
    HeapFree(GetProcessHeap(), 0, host_w);
    return 1;
}

// NTLMv2 Blob 구성
//  0x01010000 | 0x00000000 | Timestamp(8) | ClientChallenge(8) | 0x00000000 | TargetInfo | 0x00000000
#define NTLMV2_BLOB_HDR 0x00000101u

static uint8_t* build_ntlmv2_blob(const uint8_t clientChallenge[8],
                                  const uint8_t *targetInfo, size_t targetInfoLen,
                                  size_t *outLen, uint64_t ts_100ns /*0이면 now*/) {
    if (!outLen) return NULL;
    if (!ts_100ns) ts_100ns = filetime_now_100ns();

    size_t blobLen = 4 + 4 + 8 + 8 + 4 + targetInfoLen + 4;
    uint8_t *blob = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, blobLen);
    if (!blob) return NULL;

    uint8_t *p = blob;
    write_u32le(p, NTLMV2_BLOB_HDR); p += 4;
    write_u32le(p, 0x00000000u);     p += 4;
    write_u64le(p, ts_100ns);        p += 8;
    memcpy(p, clientChallenge, 8);   p += 8;
    write_u32le(p, 0x00000000u);     p += 4;
    size_t except_last_four_bytes = targetInfoLen-4;
    if (targetInfoLen) { memcpy(p, targetInfo, except_last_four_bytes); p += except_last_four_bytes; }
    write_u32le(p, 0x00000000u);     p += 4;

    *outLen = blobLen;
    return blob;
}

// Public API:
// - user/domain/password: UTF-8 문자열
// - serverChallenge: 8바이트(Type 2에서 받은 값)
// - targetInfo/targetInfoLen: Type 2의 AV_PAIR 원본 바이트열
// - clientChallenge_in: 8바이트(선택), NULL이면 내부에서 랜덤 생성
// - ts_100ns: 0이면 현재 시간 사용 (FILETIME 100ns 단위)
// Output:
//   outLMv2[24] = HMAC(v2hash, SC||CC)(16) || CC(8)
//   outNTv2 = NTProof(16) || Blob(var)
//   *outNTv2_len: 길이
//   *outSessionBaseKey(선택): HMAC(v2hash, NTProof)
int ntlmv2_make_responses_bcrypt(const char *user, const char *domain, const char *password,
                                 const uint8_t serverChallenge[8],
                                 const uint8_t *targetInfo, size_t targetInfoLen,
                                 const uint8_t *clientChallenge_in, /*optional*/
                                 uint64_t ts_100ns,                /*0 = now*/
                                 uint8_t outLMv2[24],
                                 uint8_t **outNTv2, size_t *outNTv2_len,
                                 uint8_t outSessionBaseKey[16] /*optional, can be NULL*/) {
    if (!user || !domain || !password || !serverChallenge || !outLMv2 || !outNTv2 || !outNTv2_len)
        return 0;

    uint8_t v2hash[16];
    if (!ntlmv2_hash_from_up_utf8_dom_utf8(user, domain, password, v2hash)) {
        fprintf(stderr, "ntlmv2_hash failed\n");
        return 0;
    }

    // Client challenge
    uint8_t clientChallenge[8];
    if (clientChallenge_in) memcpy(clientChallenge, clientChallenge_in, 8);
    else if (!rnd_bytes(clientChallenge, 8)) {
        fprintf(stderr, "BCryptGenRandom failed\n");
        return 0;
    }

    // LMv2 response = HMAC(v2hash, SC||CC) || CC
    uint8_t lm_input[16];
    memcpy(lm_input, serverChallenge, 8);
    memcpy(lm_input + 8, clientChallenge, 8);
    if (!hmac_md5(v2hash, 16, lm_input, sizeof(lm_input), outLMv2)) {
        fprintf(stderr, "HMAC(MD5) for LMv2 failed\n");
        return 0;
    }
    memcpy(outLMv2 + 16, clientChallenge, 8);

    // NTLMv2 blob
    size_t blobLen = 0;
    uint8_t *blob = build_ntlmv2_blob(clientChallenge, targetInfo, targetInfoLen, &blobLen, ts_100ns);
    if (!blob) {
        fprintf(stderr, "build_ntlmv2_blob failed\n");
        return 0;
    }

    // NTProof = HMAC(v2hash, SC || blob)
    uint8_t *nt_input = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, 8 + blobLen);
    if (!nt_input) { HeapFree(GetProcessHeap(), 0, blob); return 0; }
    memcpy(nt_input, serverChallenge, 8);
    memcpy(nt_input + 8, blob, blobLen);

    uint8_t nt_proof[16];
    if (!hmac_md5(v2hash, 16, nt_input, (ULONG)(8 + blobLen), nt_proof)) {
        fprintf(stderr, "HMAC(MD5) for NTProof failed\n");
        HeapFree(GetProcessHeap(), 0, blob);
        HeapFree(GetProcessHeap(), 0, nt_input);
        return 0;
    }

    // NTv2 response = NTProof || Blob
    *outNTv2_len = 16 + blobLen;
    *outNTv2 = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, *outNTv2_len);
    if (!*outNTv2) {
        HeapFree(GetProcessHeap(), 0, blob);
        HeapFree(GetProcessHeap(), 0, nt_input);
        return 0;
    }
    memcpy(*outNTv2, nt_proof, 16);
    memcpy(*outNTv2 + 16, blob, blobLen);

    // SessionBaseKey = HMAC(v2hash, NTProof)  (Type3 이후 MIC/Sealing에 사용)
    if (outSessionBaseKey) {
        if (!hmac_md5(v2hash, 16, nt_proof, 16, outSessionBaseKey)) {
            fprintf(stderr, "HMAC(MD5) for SessionBaseKey failed (non-fatal)\n");
            // 실패해도 응답 자체는 반환
            memset(outSessionBaseKey, 0, 16);
        }
    }

    HeapFree(GetProcessHeap(), 0, blob);
    HeapFree(GetProcessHeap(), 0, nt_input);
    return 1;
}

// type2-extract code
static int is_smb2(const SMB2_HDR* h){
    return h && h->Proto[0]==0xFE && h->Proto[1]=='S' && h->Proto[2]=='M' && h->Proto[3]=='B';
}

static uint32_t nbss_len(const NBSS_HDR* n){
    const uint8_t* p = (const uint8_t*)n;
    return ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | p[3];
}

/* 응답 패킷에서 SecurityBuffer(=SPNEGO 전체) 위치/길이 얻기 */
static int get_secbuf_from_smb2_resp(const uint8_t* pkt, uint32_t pkt_len,
                                     const uint8_t** sec_out, uint16_t* sec_len_out)
{
    if(pkt_len < 4 + sizeof(SMB2_HDR) + sizeof(SMB2_SESSSETUP_RESP)) return -1;

    const NBSS_HDR* nb = (const NBSS_HDR*)pkt;
    if(nb->MsgType != 0x00) return -2;                  // NBSS Session Message만 허용
    uint32_t nlen = nbss_len(nb);
    if(4 + nlen > pkt_len) return -3;                   // 선언 길이 초과

    const SMB2_HDR* h = (const SMB2_HDR*)(pkt + 4);
    if(!is_smb2(h)) return -4;

    const uint8_t* p = (const uint8_t*)h + 64;          // SMB2 header(64B) 뒤
    const SMB2_SESSSETUP_RESP* r = (const SMB2_SESSSETUP_RESP*)p;

    uint16_t off = r->SecurityBufferOffset;             // 오프셋 기준: SMB2 header 시작
    uint16_t len = r->SecurityBufferLength;
    const uint8_t* sec = (const uint8_t*)h + off;

    if(sec < (const uint8_t*)h || (sec + len) > (pkt + 4 + nlen)) return -5;

    *sec_out = sec; *sec_len_out = len;
    return 0;
}

/* SecurityBuffer 안에서 NTLM Type-2 블록 찾기 */
static int find_ntlm_type2(const uint8_t* sec, uint32_t sec_len,
                           const NTLM_TYPE2** t2_out, uint32_t* avail_from_t2)
{
    static const uint8_t sig[8] = {'N','T','L','M','S','S','P',0};
    for(uint32_t i=0; i + 12 <= sec_len; ++i){
        if(memcmp(sec + i, sig, 8)==0){
            uint32_t t;
            memcpy(&t, sec + i + 8, 4); // little-endian 환경 가정
            if(t == 2){
                const NTLM_TYPE2* t2 = (const NTLM_TYPE2*)(sec + i);
                // 최소 헤더 크기 보장
                if(i + sizeof(NTLM_TYPE2) > sec_len) return -2;
                *t2_out = t2;
                if(avail_from_t2) *avail_from_t2 = sec_len - i;
                return 0;
            }
        }
    }
    return -1; // Type-2 못 찾음
}

/* 공개 API:
   - resp/pkt_len: NBSS+SMB2 SessionSetup Response 전체 버퍼
   - chal_out[8]: ServerChallenge 8바이트가 복사되어 나감
   - (옵션) targetInfo_ptr/len: Type-2의 TargetInfo 원본 바이트/길이 반환
*/
int extract_ntlm_challenge_from_response(const uint8_t* resp, uint32_t pkt_len,
                                         uint8_t chal_out[8],
                                         const uint8_t** targetInfo_ptr, uint16_t* targetInfo_len)
{
    const uint8_t* sec=NULL; uint16_t sec_len=0;
    int rc = get_secbuf_from_smb2_resp(resp, pkt_len, &sec, &sec_len);
    if(rc!=0) return rc;                         // -1~-5

    const NTLM_TYPE2* t2=NULL; uint32_t avail=0;
    rc = find_ntlm_type2(sec, sec_len, &t2, &avail);
    if(rc!=0) return -10;                        // NTLM Type-2 없음

    // ServerChallenge 추출 (오프셋은 구조체에 정의됨)
    memcpy(chal_out, t2->ServerChallenge, 8);

    // TargetInfo(있을 때만)
    if(targetInfo_ptr && targetInfo_len){
        *targetInfo_ptr = NULL; *targetInfo_len = 0;
        // Type-2 시작을 기준으로 TargetInfoOffset 해석
        const uint8_t* t2_base = (const uint8_t*)t2;
        if(t2->TargetInfoOffset && t2->TargetInfoLen){
            const uint8_t* ti = t2_base + t2->TargetInfoOffset;
            // 범위 체크: t2부터 avail 범위 내에 있어야 함
            if(ti >= t2_base && (ti + t2->TargetInfoLen) <= (t2_base + avail)){
                *targetInfo_ptr = ti;
                *targetInfo_len = t2->TargetInfoLen;
            }
        }
    }
    return 0;
}

// ===== 간단한 헬퍼: 응답 버퍼가 Type-2인지 검사 (이미 있으니 참고용) =====
int is_ntlm_challenge(const void* resp_pkt, uint32_t resp_len)
{
    const uint8_t* sec = NULL; 
    uint16_t sec_len = 0;
    if (get_secbuf_from_smb2_resp((const uint8_t*)resp_pkt, resp_len, &sec, &sec_len) != 0)
        return 0; // SecurityBuffer 자체를 못 찾음

    const NTLM_TYPE2* t2 = NULL; 
    uint32_t avail = 0;
    if (find_ntlm_type2(sec, sec_len, &t2, &avail) == 0)
        return 1; // NTLMSSP Type-2 발견

    return 0; // NTLMSSP Type-2 없음
}
// int is_ntlm_challenge_nbss_smb2(const char *buf, int len){
//     SECLOC s;
//     hprintf("[+] is ntlm challenge nbss smb2 start\n"); 
//     int n = get_secbuf_from_smb2_nbss((const uint8_t*)buf,(uint32_t)len,0,&s); 
//     if(n!=0) {
//       hprintf("[-] there is no secbuf exist error:%d\n", n);
//       return 0;
//     }
//     const uint8_t *p=NULL; 
//     uint32_t L=0,t=0; 
//     if(find_ntlmssp(s.sec,s.sec_len,&p,&L,&t)!=0){
//       hprintf("[-] not challenge\n");
//       return 0;
//     } 
//     return (t==2);
// }

int is_find_request(const uint8_t* data, uint32_t size)
{
    hprintf("[*] is_find_request check start\n");
    if (!data || size < 66) return 0;
    hprintf("[*] is_find_request check step1\n");
    if (data[16] != 0x0E || data[17] != 0x00) return 0;
    hprintf("[*] is_find_request check step2\n");

    if (data[68] != 0x21 || data[69] != 0x00) return 0;
    hprintf("[*] is_find_request check step3\n");
    return 1; // "find" 요청으로 간주
}

int main(int argc, char** argv)
{
    hprintf("[+] msFuzz: loader is executed\n");

    is_smb_service_running();
    wait_for_smb_service_running(2000);
    is_smb_service_running();

    kAFL_custom* payload_buffer = (kAFL_custom*)VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_READWRITE);

    memset(payload_buffer, 0x0, PAYLOAD_MAX_SIZE);

    /* open vulnerable driver */

    HANDLE kafl_vuln_handle = NULL;
    int i;
    int count=0;
    
    // [loop]: Get driver device handler
    // while(1)
    // {
    //     kafl_vuln_handle = CreateFile((LPCSTR)"\\\\?\\GLOBALROOT\\Device\\AFD",
    //         GENERIC_READ | GENERIC_WRITE,
    //         FILE_SHARE_READ | FILE_SHARE_WRITE,
    //         NULL,
    //         OPEN_EXISTING,
    //         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
    //         NULL
    //     );

    //     count++;

    //     if (kafl_vuln_handle != INVALID_HANDLE_VALUE)
    //         break;

    //     if (count % LOG_UPDATE_FREQ == 0)
    //         hprintf("[-] CreateFile failed: Attempt #%d, Error code: 0x%X\n", count, GetLastError());

    //     if (count > MAX_ATTEMPT) {
    //         hprintf("[-] Too many retries. Aborting...\n");
    //         habort("Exceeded max retry count\n");
    //     }

    // }
    
    // if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
    //     hprintf("[-] KAFL test: Cannot get device handle: 0x%X\n", GetLastError());
    //     habort("Cannot get device handle\n");
    // } else {
    //     hprintf("[+] msFuzz: Entering fuzzing loop\n");
    // }


    init_agent_handshake();

    //init_panic_handlers();

    /* this hypercall submits the current CR3 value */ 
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    /* submit the guest virtual address of the payload buffer */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);
    
    // Submit PT ranges
    set_ip_range();
    char* outbuff = (CHAR*)malloc(0x10000);
    DWORD dwRet = 0;
    
    

    wchar_t cmd1[512], cmd2[512], cmd3[512];
    int e1, e2, e3;

    const wchar_t* TARGET_MAC_tap = L"52:54:00:12:34:56";   // 예시 MAC
    const wchar_t* IP_tap         = L"192.168.100.50";
    const wchar_t* MASK_tap       = L"255.255.255.0";
    const wchar_t* GW_tap         = L"192.168.100.1";
    const wchar_t* DNS1_tap       = L"8.8.8.8";
    const wchar_t* DNS2_tap       = L"1.1.1.1";

    wchar_t iface[256];
    if (!find_iface_name_by_mac(TARGET_MAC_tap, iface, 256)) {
        hprintf("failed to find interface by MAC\n");
        return 1;
    }
    hprintf("found interface: %ls\n", iface);

    // NIC 초기화 기다림(부팅 직후 안정화용)
    sleep_ms(5000);

    // IPv4 주소 고정
    swprintf(cmd1, 512,
      L"/C netsh interface ipv4 set address name=\"%s\" static %s %s %s",
      iface, IP_tap, MASK_tap, GW_tap);

    // DNS 설정(기본)
    swprintf(cmd2, 512,
      L"/C netsh interface ipv4 set dnsservers name=\"%s\" static %s primary",
      iface, DNS1_tap);

    // 보조 DNS 추가(선택)
    swprintf(cmd3, 512,
      L"/C netsh interface ipv4 add dnsservers name=\"%s\" %s index=2",
      iface, DNS2_tap);

    e1 = run(cmd1);
    e2 = run(cmd2);
    e3 = run(cmd3);

    hprintf("results: set addr=%d, set dns=%d, add dns2=%d\n", e1, e2, e3);

    sleep_ms(10000);
    
    // for Seed create using sub-process @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    // Python 인터프리터 (환경에 맞게 절대 경로나 python.exe로 설정)
    const wchar_t *python = L"C:\\Python311\\python.exe";

    // 실행할 스크립트와 인자를 C 코드 안에서 직접 지정
    const wchar_t *script = L"C:\\bin\\py\\smbd.py";
    const wchar_t *host   = L"192.168.100.1";
    const wchar_t *port   = L"--port 445";
    const wchar_t *share  = L"--share Shared";
    // const wchar_t *path   = L"--path \\ansible_created.txt";
    const wchar_t *path   = L"--path *";

    // 전체 명령줄 만들기
    wchar_t cmdline[4096];
    swprintf(cmdline, 4096, L"%s %s %s %s %s %s",
             python, script, host, port, share, path);

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE }; // 핸들 상속 가능
    HANDLE out_read = NULL, out_write = NULL;
    if (!CreatePipe(&out_read, &out_write, &sa, 0)) {
        fwprintf(stderr, L"CreatePipe failed (%lu)\n", GetLastError());
        return 1;
    }
    // 부모쪽 read 핸들은 상속 금지 (자식이 잡고 있으면 파이프 EOF가 안 옴)
    SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = out_write;
    si.hStdError  = out_write;

    hprintf("[parent] Executing: %s\n", cmdline);

    // 자식 프로세스 실행
    if (!CreateProcessW(
            NULL,      // 애플리케이션 이름(NULL이면 cmdline 첫 토큰 사용)
            cmdline,   // 명령줄
            NULL,
            NULL,
            TRUE,      // 표준 입출력 상속
            0,
            NULL,
            NULL,
            &si,
            &pi))
    {
        DWORD err = GetLastError();
        hprintf("CreateProcess failed (%lu)\n", err);
        CloseHandle(out_read);
        CloseHandle(out_write);
        return 1;
    }

    // 부모는 write 끝을 바로 닫아야 읽기 쪽에서 EOF를 받을 수 있음
    CloseHandle(out_write);

    // (5) 파이프에서 출력 읽어서 부모 표준출력으로 그대로 뿌리기
    // 바이너리 모드로 바꿔 인코딩 깨짐/개행 변환 최소화
    _setmode(_fileno(stdout), _O_BINARY);

    BYTE buf[4096];
    DWORD readBytes = 0;
    for (;;) {
        BOOL ok = ReadFile(out_read, buf, sizeof(buf), &readBytes, NULL);
        if (!ok || readBytes == 0) break; // 파이프 EOF
        buf[readBytes] = '\0'; // 문자열 끝 표시
        hprintf("%s\n", buf);
        fflush(stdout);
    }

    // 자식 종료 대기
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    hprintf("[parent] child exited with code %lu\n", exitCode);
    return;

    // Create a TCP/UDP socket
    int n;
    WSADATA wsaData;
    SOCKET sockfd;
    struct sockaddr_in serv_addr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        hprintf("WSAStartup failed\n");
        return 1;
    }
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);//IPPROTO_TCP
    if (sockfd == INVALID_SOCKET) {
        hprintf("Invalid socket: %ld\n", WSAGetLastError());
        return 1;
    }
    
    // tcp://127.0.0.1/445
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(445);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    // serv_addr.sin_addr.s_addr = inet_addr("192.168.100.1");

    // printf("[** 1049, send_over_network] Connecting to %s:%d\n", net_ip, net_port);
    hprintf("try connection\n");
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        int err_code = WSAGetLastError();
        hprintf("Connect failed in first try. WSA error code: %d\n", err_code);
        //If it cannot connect to the server under test
        //try it again as the server initial startup time is varied
        for (n=0; n < 1000; n++) {
            hprintf("connection trying......\n");            
            if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;                        
            hprintf("connection failed, WSA error code: %d, sleep and retrying...\n", err_code);
            Sleep(1); // Sleep for 1 ms
        }
        if (n== 1000) {
            closesocket(sockfd);
            hprintf("connection timeout\n");
            return 1;
        }
    }
    hprintf("socket connection done before snapshot\n");
    
    int result = send(sockfd, smb1_negotiate, sizeof(smb1_negotiate), 0);
    if (result == SOCKET_ERROR) {
        hprintf("Send failed\n");
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }
    hprintf("Sent %d bytes\n", result);

    char temppp;
    int peek = recv(sockfd, &temppp, 1, MSG_PEEK);
    hprintf("Peek result: %d\n", peek);
    
    char recvbuf[1024];
    result = recv(sockfd, recvbuf, sizeof(recvbuf), 0);
    if (result > 0) {
        hprintf("Received %d bytes from SMB server\n", result);
    } else {
        hprintf("No response or recv failed\n");
    }   

    // unsigned char payload_example[] =
    // "\x00\x00\x00\x66\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x00\x01\x00\x00\x00\x40\x00\x00\x00\x42\x6b\x64\x79\x50\x4d\x63\x65\x69\x51\x63\x79\x61\x47\x78\x69\x00\x00\x00\x00\x00\x00\x00\x00\x10\x02\x00\x00\x00\x9a\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00"
    // "\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x60\x40\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x36\x30\x34\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x22\x04\x20\x4e\x54\x4c\x4d\x53\x53\x50\x00"
    // "\x01\x00\x00\x00\x05\x02\x88\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x49\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1\x47\x30\x45"
    // "\xa2\x43\x04\x41\x4e\x54\x4c\x4d\x53\x53\x50\x00\x03\x00\x00\x00\x01\x00\x01\x00\x40\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x41\x00\x00\x00\x05\x02\x88\xa0\x00\x00\x00\x00\x9a\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x01\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    // "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x60\x40\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x36\x30\x34\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x22\x04\x20\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x05\x02\x88\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x8c\xfe\x53\x4d\x42\x40\x00\x01\x00\x00"
    // "\x00\x00\x00\x01\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\xa1\x82\x01\x30\x30\x82\x01\x2c\xa2\x82\x01\x28\x04\x82\x01\x24\x4e\x54\x4c\x4d\x53\x53\x50\x00\x03\x00\x00\x00\x18\x00\x18\x00\x4a\x00\x00\x00\xc2\x00\xc2\x00\x62"
    // "\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x0a\x00\x0a\x00\x40\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\x00\x00\x24\x01\x00\x00\x05\x02\x88\xa0\x47\x00\x75\x00\x65\x00\x73\x00\x74\x00\x0f\x6c\xd7\x69\xe5\xce\x3e\xb8\x50\x75\xa1\xf0\x85\x19\xb3\x36\x72\x36\x65\x31\x75\x6b\x43\x56\x4a\x4e\x93\xf1\x15\xda\x4a\x61\x04\xbf\x7f\x5d\xcd\x99\x82\x10\x01\x01\x00\x00\x00\x00\x00\x00\x62\xfb\x05\x13\xde\x1c\xdc\x01\x72\x36\x65\x31\x75\x6b\x43\x56\x00\x00\x00\x00\x02\x00\x14"
    // "\x00\x56\x00\x41\x00\x47\x00\x52\x00\x41\x00\x4e\x00\x54\x00\x2d\x00\x31\x00\x30\x00\x01\x00\x14\x00\x56\x00\x41\x00\x47\x00\x52\x00\x41\x00\x4e\x00\x54\x00\x2d\x00\x31\x00\x30\x00\x04\x00\x14\x00\x76\x00\x61\x00\x67\x00\x72\x00\x61\x00\x6e\x00\x74\x00\x2d\x00\x31\x00\x30\x00\x03\x00\x14\x00\x76\x00\x61\x00\x67\x00\x72\x00\x61\x00\x6e\x00\x74\x00\x2d\x00\x31\x00\x30\x00\x07\x00\x08\x00\x62\xfb\x05\x13\xde\x1c\xdc\x01\x09\x00\x1e\x00\x63\x00\x69\x00\x66\x00\x73\x00\x2f\x00\x56"
    // "\x00\x41\x00\x47\x00\x52\x00\x41\x00\x4e\x00\x54\x00\x2d\x00\x31\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x03\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x48\x00\x2c\x00\x5c\x00\x5c\x00\x31\x00\x39\x00\x32\x00\x2e\x00\x31\x00\x36\x00\x38"
    // "\x00\x2e\x00\x31\x00\x30\x00\x30\x00\x2e\x00\x31\x00\x5c\x00\x53\x00\x68\x00\x61\x00\x72\x00\x65\x00\x64\x00\x00\x00\x01\x68\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x05\x00\x20\x00\x00\x00\x00\x00\xa0\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x39\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81"
    // "\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00\x60\x00\x00\x00\x78\x00\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x61\x00\x6e\x00\x73\x00\x69\x00\x62\x00\x6c\x00\x65\x00\x5f\x00\x63\x00\x72\x00\x65\x00\x61\x00\x74\x00\x65\x00\x64\x00\x2e\x00\x74\x00\x78\x00\x74\x00\x00\x00\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x10\x00\x20\x00\x04\x00\x00\x00\x70\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x0c\x00\x00\x00"
    // "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x00\x01\x05\xff\xff\x00\x00\x68\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x06\x00\x20\x00\x04\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    // "\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x02\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x44\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00\x02"
    // "\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00"
    // ;
    
    // klist_t(lms) *kl_messages;
    // DWORD timeout_ms = 1000;

    // region_t *regions;
    // unsigned int region_count = 0;

    // uint32_t buffer_length = 1744;
    // unsigned char* pbuffer = payload_example;
    
    // hprintf("region_count = %d\n", region_count);
    // hprintf("buffer_length: -u %u\n", buffer_length);
    // hprintf("buffer_length: -x %x\n", buffer_length);
    // hprintf("%x %x %x %x %x %x\n", pbuffer[0],pbuffer[1],pbuffer[2],pbuffer[3],pbuffer[4],pbuffer[5]);
    
    // uint32_t* flag_sequence = NULL;
    // extract_requests_SMB(pbuffer, buffer_length, &regions, &flag_sequence, &region_count);
    // kl_messages = construct_kl_messages(pbuffer, regions, region_count);
    
    // hprintf("region_count = %d\n", region_count);
    // hprintf("build region and kl_messages done\n\n");

    // kliter_t(lms) *it;
    // uint32_t messages_sent = 0;
    // uint32_t poll_wait_msecs = 500;
    // int response_bytes_size = 0;
    // uint32_t *response_bytes = NULL;
    // int response_buf_size = 0;
    // char *response_buf = NULL;

    // int sent_ntlm_auth = 0;
    // int each_response_size = 0;
    // u32 prev_buf_size = 0;
    // int ntlm_count = 0;
    // int find_count = 0;

    // // sleep_ms(20000);
    // uint8_t likely_buggy = 0;
    
    // for (it = kl_begin(kl_messages); it != kl_end(kl_messages); it = kl_next(it)) {
    //     hprintf("\n");
    //     hprintf("mdata: %x %x %x %x %x %x %x, msize: %u\n", kl_val(it)->mdata[0],kl_val(it)->mdata[1],kl_val(it)->mdata[2],kl_val(it)->mdata[3],kl_val(it)->mdata[4],kl_val(it)->mdata[5],kl_val(it)->mdata[6],kl_val(it)->msize);
    //     each_response_size = response_buf_size - prev_buf_size;

    //     if(it!=kl_begin(kl_messages) && sent_ntlm_auth == 0 && is_ntlm_challenge(response_buf+prev_buf_size, each_response_size)){
    //     //   hprintf("[+] NTLM Challenge detected, sending NTLM_AUTH instead!\n");
    //       uint8_t chal[8];
    //       const uint8_t* ti; uint16_t ti_len;
    //       int r = extract_ntlm_challenge_from_response(response_buf+prev_buf_size, each_response_size, chal, &ti, &ti_len);
    //       if(r==0){
    //         ;
    //           // chal[]에 8바이트 도전 값, ti/ti_len은 TargetInfo(옵션)
    //         // hprintf("[+] challenge: %x %x %x %x %x %x %x %x, targetinfo_length: %d\n", chal[0],chal[1],chal[2],chal[3],chal[4],chal[5],chal[6],chal[7],ti_len);
    //       }
    //       const char* service = "cifs";
    //       const char* dnsHost = "vagrant-10";

    //       uint32_t av_len;
    //       uint8_t* avpair;
    //       if(!make_spn_avpair(service, dnsHost, &avpair, &av_len)){
    //         hprintf("[-] fail to make spn avpair\n");
    //         return;
    //       }
          
    //       // modify targetinfo
    //       uint32_t mti_len = ti_len + av_len;
    //       uint8_t* mti = (uint8_t*)malloc(mti_len); 

    //       memcpy(mti, ti, ti_len-4);          
    //       memcpy(mti+ti_len-4, avpair, av_len);      
    //       memset(mti+ti_len-4+av_len, 0, 4);

    //       if (ntlm_count == 0){
    //         n = net_send(sockfd, timeout_ms, kl_val(it)->mdata, kl_val(it)->msize);  
    //         ntlm_count +=1;
    //         goto ANONYMOUS_HANDLE;
    //       }
    //       uint8_t lm[24];
    //       uint8_t *nt = NULL;
    //       size_t nt_len = 0;
    //       uint8_t sessionBaseKey[16];
    
    //       if (!ntlmv2_make_responses_bcrypt("Guest", "", "",
    //                                         chal,
    //                                         mti, mti_len,
    //                                         NULL, /* client challenge auto */
    //                                         0,    /* timestamp now */
    //                                         lm,
    //                                         &nt, &nt_len,
    //                                         sessionBaseKey)) {
    //           hprintf("[-] NTLMv2 response generation failed\n");
    //           return 1;
    //       }
    //     //   hprintf("[+] ntlmv2_response_length: %d\n", nt_len);
    //       // hprintf("");
    //       // modi_data = modify_type3_packet();
    //       uint8_t* modi_data = kl_val(it)->mdata;
    //       memcpy(modi_data+68+24+16+64+10, lm, 24);
    //       // hprintf("[+] nt last value: %2x %2x %2x %2x\n", nt[nt_len-4],nt[nt_len-3],nt[nt_len-2],nt[nt_len-1]);
    //       memcpy(modi_data+68+24+16+64+10+24, nt, nt_len);

    //       n = net_send(sockfd, timeout_ms, modi_data, kl_val(it)->msize);
    //       sent_ntlm_auth = 1;
    //     }
    //     // temparily way
    //     else if(find_count==0 &&it!=kl_begin(kl_messages) && is_find_request(kl_val(it)->mdata, kl_val(it)->msize)){
    //         hprintf("[+] Find request detected, modifying it to avoid server crash!\n");
    //         uint8_t* modi_data = kl_val(it)->mdata;
    //         memset(modi_data+4+64+3, 0x01, 1);
    //         n = net_send(sockfd, timeout_ms, kl_val(it)->mdata, kl_val(it)->msize);
    //         find_count +=1;
    //     }
    //     else{
    //       n = net_send(sockfd, timeout_ms, kl_val(it)->mdata, kl_val(it)->msize);  
    //     }
    //     ANONYMOUS_HANDLE:
    //     messages_sent++;
    //     hprintf("message sent: %d\n", messages_sent);

    //     //Allocate memory to store new accumulated response buffer size
    //     response_bytes = (u32 *) ck_realloc(response_bytes, messages_sent * sizeof(u32));

    //     //Jump out if something wrong leading to incomplete message sent
    //     if (n != kl_val(it)->msize) {
    //         hprintf("something wrong leading to incomplete message sent\n");
    //         // goto HANDLE_RESPONSES;
    //     }
    //     hprintf("message sent is successfully done\n");
    //     //retrieve server response
    //     prev_buf_size = response_buf_size;
    //     if (net_recv(sockfd, timeout_ms, poll_wait_msecs, &response_buf, &response_buf_size)) {
    //         hprintf("[**vuln_test] recv fail\n");
    //         hprintf("[**vuln_test] response_buf_size is %d\n", response_buf_size);
    //         // goto HANDLE_RESPONSES;
    //     }
    //     hprintf("response received: %d bytes\n", response_buf_size);
    //     // buf_size is accumulate and response is accumulate@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    //     //Update accumulated response buffer size
    //     response_bytes[messages_sent - 1] = response_buf_size;
    //     response_bytes_size += response_buf_size;
    //     // for debugging purpose
    //     if(messages_sent==10){
    //         break;
    //     }
        
    //     //set likely_buggy flag if AFLNet does not receive any feedback from the server
    //     //it could be a signal of a potentiall server crash, like the case of CVE-2019-7314
    //     if (prev_buf_size == response_buf_size) likely_buggy = 1;
    //     else likely_buggy = 0;
    // }
    
    // socket close
    closesocket(sockfd);
    WSACleanup();
    
    // Snapshot here
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    /* request new payload (*blocking*) */
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 
    
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        hprintf("WSAStartup failed\n");
        return 1;
    }
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);//IPPROTO_TCP
    if (sockfd == INVALID_SOCKET) {
        hprintf("Invalid socket: %ld\n", WSAGetLastError());
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(445);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    // serv_addr.sin_addr.s_addr = inet_addr("192.168.100.1");

    hprintf("try connection\n");
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        int err_code = WSAGetLastError();
        hprintf("Connect failed in first try. WSA error code: %d\n", err_code);
        //If it cannot connect to the server under test
        //try it again as the server initial startup time is varied
        for (n=0; n < 1000; n++) {
            hprintf("connection trying......\n");            
            if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;                        
            hprintf("connection failed, WSA error code: %d, sleep and retrying...\n", err_code);
            Sleep(1); // Sleep for 1 ms
        }
        if (n== 1000) {
            closesocket(sockfd);
            hprintf("connection timeout\n");
            return 1;
        }
    }
    
    klist_t(lms) *kl_messages;
    DWORD timeout_ms = 1000;

    region_t *regions;
    unsigned int region_count = 0;

    uint32_t buffer_length = payload_buffer->payload_length;
    unsigned char* pbuffer = payload_buffer->payload;
    
    hprintf("region_count = %d\n", region_count);
    hprintf("buffer_length: -u %u\n", buffer_length);
    hprintf("buffer_length: -x %x\n", buffer_length);
    hprintf("%x %x %x %x %x %x\n", pbuffer[0],pbuffer[1],pbuffer[2],pbuffer[3],pbuffer[4],pbuffer[5]);
    
    uint32_t* flag_sequence = NULL;
    extract_requests_SMB(pbuffer, buffer_length, &regions, &flag_sequence, &region_count);
    kl_messages = construct_kl_messages(pbuffer, regions, region_count);
    
    hprintf("region_count = %d\n", region_count);
    hprintf("build region and kl_messages done\n\n");

    kliter_t(lms) *it;
    uint32_t messages_sent = 0;
    uint32_t poll_wait_msecs = 500;
    int response_bytes_size = 0;
    uint32_t *response_bytes = NULL;
    int response_buf_size = 0;
    char *response_buf = NULL;

    int sent_ntlm_auth = 0;
    int each_response_size = 0;
    u32 prev_buf_size = 0;
    int ntlm_count = 0;
    int find_count = 0;
    uint8_t* find_data = NULL;

    // sleep_ms(20000);
    uint8_t likely_buggy = 0;
    
    for (it = kl_begin(kl_messages); it != kl_end(kl_messages); it = kl_next(it)) {
        hprintf("\n");
        hprintf("mdata: %x %x %x %x %x %x %x, msize: %u\n", kl_val(it)->mdata[0],kl_val(it)->mdata[1],kl_val(it)->mdata[2],kl_val(it)->mdata[3],kl_val(it)->mdata[4],kl_val(it)->mdata[5],kl_val(it)->mdata[6],kl_val(it)->msize);
        each_response_size = response_buf_size - prev_buf_size;

        if(it!=kl_begin(kl_messages) && sent_ntlm_auth == 0 && is_ntlm_challenge(response_buf+prev_buf_size, each_response_size)){
        //   hprintf("[+] NTLM Challenge detected, sending NTLM_AUTH instead!\n");
          uint8_t chal[8];
          const uint8_t* ti; uint16_t ti_len;
          int r = extract_ntlm_challenge_from_response(response_buf+prev_buf_size, each_response_size, chal, &ti, &ti_len);
          if(r==0){
            ;
              // chal[]에 8바이트 도전 값, ti/ti_len은 TargetInfo(옵션)
            // hprintf("[+] challenge: %x %x %x %x %x %x %x %x, targetinfo_length: %d\n", chal[0],chal[1],chal[2],chal[3],chal[4],chal[5],chal[6],chal[7],ti_len);
          }
          const char* service = "cifs";
          const char* dnsHost = "vagrant-10";

          uint32_t av_len;
          uint8_t* avpair;
          if(!make_spn_avpair(service, dnsHost, &avpair, &av_len)){
            hprintf("[-] fail to make spn avpair\n");
            return;
          }
          
          // modify targetinfo
          uint32_t mti_len = ti_len + av_len;
          uint8_t* mti = (uint8_t*)malloc(mti_len); 

          memcpy(mti, ti, ti_len-4);          
          memcpy(mti+ti_len-4, avpair, av_len);      
          memset(mti+ti_len-4+av_len, 0, 4);

          if (ntlm_count == 0){
            n = net_send(sockfd, timeout_ms, kl_val(it)->mdata, kl_val(it)->msize);  
            ntlm_count +=1;
            goto ANONYMOUS_HANDLE;
          }
          uint8_t lm[24];
          uint8_t *nt = NULL;
          size_t nt_len = 0;
          uint8_t sessionBaseKey[16];
    
          if (!ntlmv2_make_responses_bcrypt("Guest", "", "",
                                            chal,
                                            mti, mti_len,
                                            NULL, /* client challenge auto */
                                            0,    /* timestamp now */
                                            lm,
                                            &nt, &nt_len,
                                            sessionBaseKey)) {
              hprintf("[-] NTLMv2 response generation failed\n");
              return 1;
          }
        //   hprintf("[+] ntlmv2_response_length: %d\n", nt_len);
          // hprintf("");
          // modi_data = modify_type3_packet();
          uint8_t* modi_data = kl_val(it)->mdata;
          memcpy(modi_data+68+24+16+64+10, lm, 24);
          // hprintf("[+] nt last value: %2x %2x %2x %2x\n", nt[nt_len-4],nt[nt_len-3],nt[nt_len-2],nt[nt_len-1]);
          memcpy(modi_data+68+24+16+64+10+24, nt, nt_len);

          n = net_send(sockfd, timeout_ms, modi_data, kl_val(it)->msize);
          sent_ntlm_auth = 1;
        }
        // temparily way
        else if(find_count==0 &&it!=kl_begin(kl_messages) && is_find_request(kl_val(it)->mdata, kl_val(it)->msize)){
            hprintf("[+] Find request detected, modifying it to avoid server crash!\n");
            uint8_t* modi_data = kl_val(it)->mdata;
            memset(modi_data+4+64+3, 0x01, 1);

            uint8_t* find_data = response_buf+prev_buf_size + 132;
            hprintf("find_data %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", find_data[0],find_data[1],find_data[2],find_data[3],find_data[4],find_data[5],find_data[6],find_data[7],find_data[8],find_data[9],find_data[10],find_data[11],find_data[12],find_data[13],find_data[14],find_data[15]);
            hprintf("modi_data %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", modi_data[72],modi_data[73],modi_data[74],modi_data[75],modi_data[76],modi_data[77],modi_data[78],modi_data[79],modi_data[80],modi_data[81],modi_data[82],modi_data[83],modi_data[84],modi_data[85],modi_data[86],modi_data[87]);
            memcpy(modi_data+4+64+8, find_data, 16);
            n = net_send(sockfd, timeout_ms, kl_val(it)->mdata, kl_val(it)->msize);
            find_count +=1;
        }
        else{
          n = net_send(sockfd, timeout_ms, kl_val(it)->mdata, kl_val(it)->msize);  
        }
        ANONYMOUS_HANDLE:
        messages_sent++;
        hprintf("message sent: %d\n", messages_sent);

        //Allocate memory to store new accumulated response buffer size
        response_bytes = (u32 *) ck_realloc(response_bytes, messages_sent * sizeof(u32));

        //Jump out if something wrong leading to incomplete message sent
        if (n != kl_val(it)->msize) {
            hprintf("something wrong leading to incomplete message sent\n");
            goto HANDLE_RESPONSES;
        }
        hprintf("message sent is successfully done\n");
        //retrieve server response
        prev_buf_size = response_buf_size;
        if (net_recv(sockfd, timeout_ms, poll_wait_msecs, &response_buf, &response_buf_size)) {
            //hprintf("[**vuln_test] recv fail\n");
            //hprintf("[**vuln_test] response_buf_size is %d\n", response_buf_size);
            goto HANDLE_RESPONSES;
        }
        hprintf("response received: %d bytes\n", response_buf_size);
        // buf_size is accumulate and response is accumulate@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        //Update accumulated response buffer size
        response_bytes[messages_sent - 1] = response_buf_size;
        response_bytes_size += response_buf_size;
        // for debugging purpose    
        // if(messages_sent==10){
        //     break;
        // }
        
        //set likely_buggy flag if AFLNet does not receive any feedback from the server
        //it could be a signal of a potentiall server crash, like the case of CVE-2019-7314
        if (prev_buf_size == response_buf_size) likely_buggy = 1;
        else likely_buggy = 0;
    }
    HANDLE_RESPONSES:
    hprintf("response done\n");
    net_recv(sockfd, timeout_ms, poll_wait_msecs, &response_buf, &response_buf_size);
    hprintf("response received: %d bytes\n", response_buf_size);
    // // EXP_ST u8 session_virgin_bits[MAP_SIZE];
    if (messages_sent > 0 && response_bytes != NULL) {
        response_bytes[messages_sent - 1] = response_buf_size;
    }
    if (likely_buggy || messages_sent < region_count){
        // some panic hypercall is needed.
        kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
        hprintf("likely buggy or stop early detected\n");
    }
    closesocket(sockfd);
    WSACleanup();
    
    init_message_code_map();
    int messages_recv = 0;
    unsigned int* state_sequence = extract_response_codes_SMB(response_buf, response_buf_size, &messages_recv);

    // //give the server a bit more time to gracefully terminate
    // while(1) {
    //     nt status = kill(child_pid, 0);
    //     if ((status != 0) && (errno == ESRCH)) break;
    // }
    

    // for(i=0; i< MAX_IRP_COUNT; i++)
    // {
    //     function_code = header[0];
    //     IoControlCode = header[1];
    //     InBufferLength = header[2];
    //     OutBufferLength = header[3];
    //     inbuffer = header+4;
    // //maybe net_send is locate
    // if(function_code != IOCTL)
    //     break; // End of IRP sequence

    //     DeviceIoControl(kafl_vuln_handle,
    //         IoControlCode,
    //         (LPVOID)inbuffer,
    //         InBufferLength,
    //         outbuff,
    //         OutBufferLength,
    //         NULL,
    //         NULL
    //     );

    // header = inbuffer + InBufferLength;

    // }
    
    /* inform fuzzer about finished fuzzing iteration */
    // Will reset back to start of snapshot here
    hprintf("[+]Before aux2 hypercall test\n");
    // for hypercall test
    // static const uint32_t  seq[] = {0, 1, 2, 3};
    // static const uint8_t flg[] = {1, 1, 1, 1};
    // int rc = aux2_publish(state_sequence, (uint32_t)(messages_recv), flag_sequence, (uint32_t)(messages_sent));
    // hprintf("T_IMG_base: %llx, T_IMG_size: %llx\n", T_IMG_base, T_IMG_size);
    int rc = aux2_publish(state_sequence, (uint32_t)(messages_recv), flag_sequence, (uint32_t)(messages_sent), T_IMG_base, T_IMG_size);
    // hprintf("flag sequence length: %d entry length: %d\n", (uint32_t)(sizeof(flag_sequence)), (uint32_t)(sizeof(flag_sequence[0])));
    // hprintf("[aux2] publish rc=%d, seq_count=%u, flags_count=%u\n", rc, messages_sent, messages_sent);
    destroy_message_code_map();
    hprintf("[+]Before call \"HYPERCALL_KAFL_RELEASE\"\n");
    // return 0;
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);  
    
    return 0;
}