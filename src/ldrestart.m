#include <xpc.h>
#include <sys/mount.h>

static int kill_process(const char *name) {
    printf("killing process: %s\n", name);
    
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64 (dict, "subsystem", 3);
    xpc_dictionary_set_uint64 (dict, "handle", 0);
    xpc_dictionary_set_uint64(dict, "routine", 0x32e);
    xpc_dictionary_set_uint64 (dict, "type", 1);
    xpc_dictionary_set_string (dict, "name", name);
    
    struct xpc_global_data *xpc_gd = (struct xpc_global_data *)_os_alloc_once_table[1].ptr;
    xpc_object_t reply = NULL;
    
    if (xpc_pipe_routine(xpc_gd->xpc_bootstrap_pipe, dict, &reply) == KERN_SUCCESS) {
        int rc = (int)xpc_dictionary_get_int64(reply, "error");
        if (rc) {
            printf("failed to kill %s: %s\n", name, xpc_strerror(rc));
            return rc;
        }
    }
    
    return KERN_SUCCESS;
}

// The processes to terminate during the "partial userspace reboot"
const char *processes_to_terminate[] = {
    "com.apple.PineBoard",
    "com.apple.backboardd",
    "com.apple.sharingd",
    "com.apple.rapportd",
    NULL
};

void partial_userspace_reboot(void) {
    
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dict, "subsystem", 3);
    xpc_dictionary_set_uint64(dict, "handle", 0);
    xpc_dictionary_set_uint64(dict, "routine", 0x32f);
    xpc_dictionary_set_uint64(dict, "type", 1);
    xpc_dictionary_set_bool(dict, "legacy", 1);
    
    struct xpc_global_data *xpc_gd = (struct xpc_global_data *)_os_alloc_once_table[1].ptr;
    xpc_object_t reply = NULL;
    
    if (xpc_pipe_routine(xpc_gd->xpc_bootstrap_pipe, dict, &reply) == KERN_SUCCESS) {
        if (xpc_dictionary_get_int64(reply, "error") == KERN_SUCCESS) {
            
            xpc_object_t services_dict = xpc_dictionary_get_value(reply, "services");
            if (services_dict == NULL) {
                printf("no services found\n");
                return;
            }
            
            xpc_dictionary_apply(services_dict, ^bool (const char *label, xpc_object_t service) {
                
                const char **process_name = processes_to_terminate;
                while (*process_name) {
                    if (strcmp(*process_name, label) == 0) {
                        int64_t pid = xpc_dictionary_get_int64(service, "pid");
                        if (pid != 0) {
                            kill_process(label);
                            break;
                        }
                    }
                    ++process_name;
                }
               
                return 1;
            });
        }
    }
}

#ifndef BUILDING_FOR_LAUNCHD_INJECTOR

// Full userspace reboot. This removes code injection artifacts from all processes (including launchd)
// This is only performed when `ldrestart` is invoked directly
extern int reboot3(uint64_t flags, ...);
int main(int argc, char *argv[]) {
        
    // Unmount DDI and checkra1n's binpack.
    // If they aren't explicitly unmounted before userspace reboot, they fail
    // to remount afterwards
    unmount("/Developer", MNT_FORCE);
    unmount("/binpack", MNT_FORCE);

    int retval = 0;
    if ((retval = reboot3(0x2000000000000000llu)) != 0) {
        printf("ldrestart failed with errcode: %d\n", retval);
    }
    
    return retval;
}

#endif
