#import <Foundation/Foundation.h>
#import <dyld-interposing.h>
#include <spawn.h>

/*
 xpcproxy is a trampoline spawned by launchd that is responsible for launching xpc services. Launchd ensures that xpcproxy_hooks.dylib is brought into this process.
 
 Similiar to the launchd hook, the hooks applied to this process ensure that the tweakloader is injected into services spawned by xpcproxy.
 */

static int posix_spawn_xpcproxy(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict], void *original_function) {
    
    char *const *envp = __envp;
    
    // CloudKeychainProxy is skipped because: 1 it is spawned very frequently and the logs are annoying, and 2 there is no legit reason for someone to need to inject into this process.
    int should_hook = strstr(path, "CloudKeychainProxy") == NULL;
    if (should_hook) {
        
        size_t envp_size = 0;
        while (__envp[envp_size] != NULL) {
            envp_size++;
        }
        envp_size++;
        
        size_t new_size = envp_size + 1;
        int dylib_already_present = 0;
        char **new_envp = malloc(new_size * sizeof(char *));
        for (size_t i = 0; i < envp_size - 1; i++) {
            
            if (strcmp(__envp[i], "DYLD_INSERT_LIBRARIES=/fs/jb/usr/libexec/libhooker/tweakloader.dylib") == 0) {
                dylib_already_present = 1;
            }

            new_envp[i] = __envp[i];
        }
        
        if (dylib_already_present == 0) {
            new_envp[envp_size - 1] = "DYLD_INSERT_LIBRARIES=/fs/jb/usr/libexec/libhooker/tweakloader.dylib";
            new_envp[new_size - 1] = NULL;
            envp = new_envp;
        }
        else {
            free(new_envp);
        }
    }
    
    return ((int (*)(pid_t * __restrict, const char * __restrict, const posix_spawn_file_actions_t *, const posix_spawnattr_t * __restrict, char *const __argv[__restrict], char *const __envp[__restrict]))original_function)(pid, path, file_actions, attrp, __argv, envp);
}

static int posix_spawn_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
    return posix_spawn_xpcproxy(pid, path, file_actions, attrp, __argv, __envp, posix_spawn);
}

static int posix_spawnp_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
    return posix_spawn_xpcproxy(pid, path, file_actions, attrp, __argv, __envp, posix_spawnp);
}

static void __attribute__((constructor)) init_xpcproxy_hooks(void) {
    DYLD_INTERPOSE(posix_spawn_hook, posix_spawn);
    DYLD_INTERPOSE(posix_spawnp_hook, posix_spawnp);
}
