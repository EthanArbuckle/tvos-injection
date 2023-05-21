#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <spawn.h>

/*
 xpcproxy is a trampoline spawned by launchd that is responsible for launching xpc services. Launchd ensures that xpcproxy_hooks.dylib is brought into this process.
 
 Similiar to the launchd hook, the hooks applied to this process ensure that the tweakloader is injected into services spawned by xpcproxy.
 */

static FILE *logging_fd;

static int posix_spawn_xpcproxy(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict], void *original_function) {
    
    char *const *envp = __envp;
    
    // CloudKeychainProxy is skipped because: 1 it is spawned very frequently and the logs are annoying, and 2 there is no legit reason for someone to need to inject into this process.
    int should_hook = strstr(path, "CloudKeychainProxy") == NULL;
    if (should_hook) {
        
        char *p = "?";
        if (__argv[1]) {
            p = __argv[1];
        }
        fprintf(logging_fd, "[xpcproxy_hooks posix_spawn] caught spawn path: %s, %s\n", path, p);
        
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
            fprintf(logging_fd, "[xpcproxy_hooks posix_spawn] before: %s\n", __envp[i]);
        }
        
        if (dylib_already_present == 0) {
            new_envp[envp_size - 1] = "DYLD_INSERT_LIBRARIES=/fs/jb/usr/libexec/libhooker/tweakloader.dylib";
            new_envp[new_size - 1] = NULL;
            
            for (size_t i = 0; i < new_size; i++) {
                fprintf(logging_fd, "[xpcproxy_hooks posix_spawn] after: %s\n", new_envp[i]);
            }
            
            envp = new_envp;
        }
        else {
            free(new_envp);
        }

        fflush(logging_fd);
    }
    
    return ((int (*)(pid_t * __restrict, const char * __restrict, const posix_spawn_file_actions_t *, const posix_spawnattr_t * __restrict, char *const __argv[__restrict], char *const __envp[__restrict]))original_function)(pid, path, file_actions, attrp, __argv, envp);
}


static void *orig_posix_spawn;
static int posix_spawn_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict])
{
    return posix_spawn_xpcproxy(pid, path, file_actions, attrp, __argv, __envp, orig_posix_spawn);
}

static void *orig_posix_spawnp;
static int posix_spawnp_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict])
{
    return posix_spawn_xpcproxy(pid, path, file_actions, attrp, __argv, __envp, orig_posix_spawnp);
}

static void (*MSHookFunction)(void *symbol, void *replace, void **result);
static void __attribute__((constructor)) init_xpcproxy_hooks(void) {
    
    logging_fd = fopen("/fs/jb/xpcproxy_log.txt", "a");
    
    // TODO: There are performance implications with performing "real" hooks in xpcproxy as it's called so frequently
    // A better approach is to use dyld'd interposing mechanims here to handle hooking the posix_spawn* functions
    void *lhHandle = dlopen("/fs/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", 0);
    MSHookFunction = dlsym(lhHandle, "MSHookFunction");
    
    MSHookFunction((void *)posix_spawn, (void *)posix_spawn_hook, (void **)&orig_posix_spawn);
    MSHookFunction((void *)posix_spawnp, (void *)posix_spawnp_hook, (void **)&orig_posix_spawnp);    
}
