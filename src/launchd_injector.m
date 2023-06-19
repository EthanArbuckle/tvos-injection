#include <Foundation/Foundation.h>
#include <mach/mach.h>
#include <xpc.h>
#include <dlfcn.h>

/*
 This utility bootstraps code injection by coercing a remote dlopen() invocation inside launchd. The dylib mapped into launchd handles inserting
 relevant dylibs into subsequently spawned processes.
 
 A partial userspace reboot is performed after launchd's dlopen() to ensure tweaks are injected into processes even if they were spawned before this utility runs.
 Additionally, custom LaunchDaemons (originating from tweaks) are kicked-off from here.
 */

#define LAUNCH_DAEMONS_DIRECTORY @"/fs/jb/Library/LaunchDaemons"

extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
extern void partial_userspace_reboot(void);

void load_daemon(const char *daemon_plist) {
    
    xpc_object_t dict = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(dict, "subsystem", 3);
    xpc_dictionary_set_uint64(dict, "handle", 0);
    xpc_dictionary_set_bool(dict, "legacy-load", 1);
    xpc_dictionary_set_uint64(dict, "type", 1);
    xpc_dictionary_set_bool(dict, "enable", 1);
    xpc_dictionary_set_uint64(dict, "routine", 800);
    
    xpc_object_t paths = xpc_array_create_empty();
    xpc_array_set_string(paths, XPC_ARRAY_APPEND, daemon_plist);
    xpc_dictionary_set_value(dict, "paths", paths);
    
    struct xpc_global_data *xpc_gd = (struct xpc_global_data *)_os_alloc_once_table[1].ptr;
    xpc_object_t reply = NULL;

    if (xpc_pipe_routine(xpc_gd->xpc_bootstrap_pipe, dict, &reply) != KERN_SUCCESS) {
        printf("failed to start %s\n", daemon_plist);
    }
}

int main(int argc, char *argv[]) {

    task_t launchd_task;
    pid_t launchd_pid = 1;
    if (task_for_pid(mach_task_self(), launchd_pid, &launchd_task) != KERN_SUCCESS) {
        printf("tfp0 failed\n");
        return -1;
    }
    
    const char *launchd_hook_dylib_path = "/fs/jb/usr/libexec/libhooker/launchd_hooks.dylib";
    
    mach_vm_size_t stack_size = 0x4000;
    mach_port_insert_right(mach_task_self(), launchd_task, launchd_task, MACH_MSG_TYPE_COPY_SEND);
    
    mach_vm_address_t remote_stack;
    mach_vm_allocate(launchd_task, &remote_stack, stack_size, VM_FLAGS_ANYWHERE);
    mach_vm_protect(launchd_task, remote_stack, stack_size, 1, VM_PROT_READ | VM_PROT_WRITE);
    
    mach_vm_address_t remote_dylib_path_str;
    mach_vm_allocate(launchd_task, &remote_dylib_path_str, 0x100 + strlen(launchd_hook_dylib_path) + 1, VM_FLAGS_ANYWHERE);
    mach_vm_write(launchd_task, 0x100 + remote_dylib_path_str, (vm_offset_t)launchd_hook_dylib_path, (mach_msg_type_number_t)strlen(launchd_hook_dylib_path) + 1);
    
    uint64_t *stack = malloc(stack_size);
    size_t sp = (stack_size / 8) - 2;
    
    mach_vm_write(launchd_task, remote_stack, (vm_offset_t)stack, (mach_msg_type_number_t)stack_size);
    
    arm_thread_state64_t state = {};
    bzero(&state, sizeof(arm_thread_state64_t));
    
    state.__x[0] = (uint64_t)remote_stack;
    state.__x[2] = (uint64_t)dlsym(RTLD_NEXT, "dlopen");
    state.__x[3] = (uint64_t)(remote_dylib_path_str + 0x100);
    __darwin_arm_thread_state64_set_lr_fptr(state, (void *)0x7171717171717171);
    __darwin_arm_thread_state64_set_pc_fptr(state, dlsym(RTLD_NEXT, "pthread_create_from_mach_thread"));
    __darwin_arm_thread_state64_set_sp(state, (void *)(remote_stack + (sp * sizeof(uint64_t))));
    
    mach_port_t exc_handler;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_handler);
    mach_port_insert_right(mach_task_self(), exc_handler, exc_handler, MACH_MSG_TYPE_MAKE_SEND);
    
    mach_port_t remote_thread;
    if (thread_create_running(launchd_task, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT, &remote_thread) != KERN_SUCCESS) {
        free(stack);
        printf("failed to create remote thread\n");
        return -1;
    }
    
    if (thread_set_exception_ports(remote_thread, EXC_MASK_BAD_ACCESS, exc_handler, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64) != KERN_SUCCESS) {
        free(stack);
        printf("failed to set remote exception port\n");
        return -1;
    }
    
    thread_resume(remote_thread);
    
    mach_msg_header_t *msg = malloc(0x4000);
    mach_msg(msg, MACH_RCV_MSG | MACH_RCV_LARGE, 0, 0x4000, exc_handler, 0, MACH_PORT_NULL);
    free(msg);
    
    thread_terminate(remote_thread);
    free(stack);

#if REQUIRE_FULL_USERSPACE_REBOOT

    sleep(1);
    partial_userspace_reboot();
    
    NSArray *daemonPlists = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:LAUNCH_DAEMONS_DIRECTORY error:nil];
    if (daemonPlists) {
        for (NSString *daemonPlistName in daemonPlists) {
            const char *absolute_path = [LAUNCH_DAEMONS_DIRECTORY stringByAppendingPathComponent:daemonPlistName].UTF8String;
            printf("loading LaunchDaemon: %s\n", absolute_path);
            load_daemon(absolute_path);
        }
    }
    
    printf("success!\n");
    
#else
    printf("success! run ldrestart to enable system-wide injection\n");
#endif
    
    return 0;
}
