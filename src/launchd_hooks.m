#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <spawn.h>

/*
 launchd is used to bootstrap injection into processes system-wide. launchd spawns both normal processes and XPC services.
 
 When launchd is spawning xpcproxy (which handles spawning services), xpcproxy_hooks.dylib is injected. This brings the tweakloader into xpc services.
 When launchd is spawning normal processes, it adds the tweakloader directly.
 
 The tweakloader is responsible for looking for installed tweaks on the filesystem and dlopen'ing them into the spawned process.
 
 Because launchd starts up and begins spawning processes before injection is established in it, it is necessary to terminate and relaunch all processess
 afterwards to ensure the tweakloader is brought into all relevant processes. This is referred to as a userspace restart.
 
 A "proper" userspace reboot involves killing *every* process including launchd. However this has some unideal side-effects, such as killing active ssh sessions.
 
 While it's technically not a real userspace reboot, an approach that involves enumerating running processes and selectively terminating them gives the granularity of being able to
 skip killing some processes that we don't want to kill, such as ssh/dropbear (and potentially some other stuff).
 */

static int posix_spawn_launchd(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict], void *original_function) {
    
    char *const *envp = __envp;
    
    // Never inject things into launchd via posix_spawn*. The launchd hooks are injected using a standalone executable.
    int should_hook = strcmp(path, "/sbin/launchd");
    if (should_hook) {
        
        // If xpcproxy is being spawned, add xpcproxy_hooks.dylib to it (which handles adding the tweakloader). For everything else, add the tweakloader directly
        int is_xpcproxy = strstr(path, "xpcproxy") != NULL;
        char *dylib_to_inject = is_xpcproxy ? "DYLD_INSERT_LIBRARIES=/fs/jb/usr/libexec/libhooker/xpcproxy_hooks.dylib" : "DYLD_INSERT_LIBRARIES=/fs/jb/usr/libexec/libhooker/tweakloader.dylib";
        
        size_t envp_size = 0;
        while (__envp[envp_size] != NULL) {
            envp_size++;
        }
        envp_size++;
        
        size_t new_size = envp_size + 1;
        char **new_envp = malloc(new_size * sizeof(char *));
        for (size_t i = 0; i < envp_size - 1; i++) {
            new_envp[i] = __envp[i];
        }
        
        new_envp[envp_size - 1] = dylib_to_inject;
        new_envp[new_size - 1] = NULL;
        envp = new_envp;
    }
    
    return ((int (*)(pid_t * __restrict, const char * __restrict, const posix_spawn_file_actions_t *, const posix_spawnattr_t * __restrict, char *const __argv[__restrict], char *const __envp[__restrict]))original_function)(pid, path, file_actions, attrp, __argv, envp);
}


static void *orig_posix_spawn;
static int posix_spawn_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
    return posix_spawn_launchd(pid, path, file_actions, attrp, __argv, __envp, orig_posix_spawn);
    /*
     if (strstr(path, "/bin/sh") != NULL) {
     fprintf(fd, "[launchd posix_spawn hook] redirecting %s to /fs/jb/bin/sh\n\n", path);
     fflush(fd);
     return orig_posix_spawn(pid, "/fs/jb/bin/sh", file_actions, attrp, __argv, __envp);
     }
     */
}

static void *orig_posix_spawnp;
static int posix_spawnp_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
    return posix_spawn_launchd(pid, path, file_actions, attrp, __argv, __envp, orig_posix_spawnp);
}

static void (*_MSHookFunction)(void *symbol, void *replace, void **result);
static void __attribute__((constructor)) init_launchd_hooks(void) {
    
    void *lhHandle = dlopen("/fs/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", 0);
    
    _MSHookFunction = dlsym(lhHandle, "MSHookFunction");
    _MSHookFunction((void *)posix_spawn, (void *)posix_spawn_hook, (void **)&orig_posix_spawn);
    _MSHookFunction((void *)posix_spawnp, (void *)posix_spawnp_hook, (void **)&orig_posix_spawnp);
}
