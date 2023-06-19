#import <Foundation/Foundation.h>
#import <dyld-interposing.h>
#import <sys/stat.h>
#import <spawn.h>
#import "common.h"

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

#define LAUNCH_DAEMONS_DIRECTORY @"/fs/jb/Library/LaunchDaemons"

#if REQUIRE_FULL_USERSPACE_REBOOT
    
#import <sys/mount.h>
#define CHECKRAIN_BINPACK_BLOCKDEV "/dev/disk5"

struct hfs_mount_args {
    char     *fspec;
    uid_t     hfs_uid;
    gid_t     hfs_gid;
    mode_t    hfs_mask;
    u_int32_t hfs_encoding;
    struct    timezone hfs_timezone;
    int       flags;
    int       journal_tbuffer_size;
    int       journal_flags;
    int       journal_disable;
};

extern xpc_object_t xpc_create_from_plist(const void *buf, size_t len);

#else

#import <dlfcn.h>

static void (*_MSHookFunction)(void *symbol, void *replace, void **result);
static void *orig_posix_spawn;
static void *orig_posix_spawnp;

#endif


static int posix_spawn_launchd(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict], void *original_function) {
    
    char *const *envp = __envp;
    
    // Never inject things into launchd via posix_spawn*. The launchd hooks are injected using a standalone executable.
    int should_hook = strcmp(path, "/sbin/launchd");
    if (should_hook) {

        // If xpcproxy is being spawned, add xpcproxy_hooks.dylib to it (which handles adding the tweakloader). For everything else, add the tweakloader directly
        int is_xpcproxy = strstr(path, "xpcproxy") != NULL;
        char *dylib_to_inject = is_xpcproxy ? "DYLD_INSERT_LIBRARIES=/fs/jb/usr/libexec/libhooker/xpcproxy_hooks.dylib" : "DYLD_INSERT_LIBRARIES=/fs/jb/usr/libexec/libhooker/tweakloader.dylib";
        
        if (path && strlen(path) > 2) {
            serial_println("inserting dylib into process %s: %s", path, dylib_to_inject);
        }
        
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

static int posix_spawn_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
#if REQUIRE_FULL_USERSPACE_REBOOT
    return posix_spawn_launchd(pid, path, file_actions, attrp, __argv, __envp, posix_spawn);
#else
    return posix_spawn_launchd(pid, path, file_actions, attrp, __argv, __envp, orig_posix_spawn);
#endif
}

static int posix_spawnp_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
#if REQUIRE_FULL_USERSPACE_REBOOT
    return posix_spawn_launchd(pid, path, file_actions, attrp, __argv, __envp, posix_spawnp);
#else
    return posix_spawn_launchd(pid, path, file_actions, attrp, __argv, __envp, orig_posix_spawnp);
#endif
}

#if REQUIRE_FULL_USERSPACE_REBOOT
xpc_object_t xpc_dictionary_get_value_hook(xpc_object_t xdict, const char *key) {
    
    xpc_object_t xdict_out = xpc_dictionary_get_value(xdict, key);
    if (key == NULL || strlen(key) < 1) {
        return xdict_out;
    }
    
    if (strcmp(key, "LaunchDaemons") == 0) {
        
        serial_println("caught launch daemon creation plist");

        NSArray *daemonPlistNames = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:LAUNCH_DAEMONS_DIRECTORY error:nil];
        for (NSString *plistName in daemonPlistNames) {
            
            const char *plist_path = [LAUNCH_DAEMONS_DIRECTORY stringByAppendingPathComponent:plistName].UTF8String;
            int plist_fd = open(plist_path, O_RDONLY);
            if (plist_fd < 1) {
                continue;
            }
            
            struct stat info;
            if (fstat(plist_fd, &info) != KERN_SUCCESS) {
                close(plist_fd);
                continue;
            }
            
            serial_println("inserting launch daemon plist: %s", plist_path);
            
            void *plist_buff = mmap(NULL, info.st_size, PROT_READ, MAP_PRIVATE | MAP_FILE, plist_fd, 0);
            if (plist_buff != NULL) {
                xpc_object_t xpc_plist = xpc_create_from_plist(plist_buff, info.st_size);
                if (xpc_plist != NULL) {
                    xpc_dictionary_set_value(xdict_out, plist_path, xpc_plist);
                }
            }
            
            close(plist_fd);
        }
    }
    else if (strcmp(key, "Paths") == 0) {
        serial_println("inserting launch daemon path: %s", LAUNCH_DAEMONS_DIRECTORY.UTF8String);
        xpc_array_set_string(xdict_out, XPC_ARRAY_APPEND, LAUNCH_DAEMONS_DIRECTORY.UTF8String);
    }

    return xdict_out;
}

static void remount_checkra1n_binpack(void) {
    
    struct hfs_mount_args args;
    args.fspec = CHECKRAIN_BINPACK_BLOCKDEV;
    args.hfs_uid = 0;
    args.hfs_gid = 0;
    args.hfs_mask = 0;
    args.flags = MNT_RDONLY;

    __unused int ret = mount("hfs", "/binpack", MNT_RDONLY, &args);
    serial_println("checkra1n binpack remount of %s retval: %d", CHECKRAIN_BINPACK_BLOCKDEV, ret);
}

#endif

static void __attribute__((constructor)) init_launchd_hooks(void) {
    
    serial_println("Injected into launchd. Requiring full userspace reboot: %d", REQUIRE_FULL_USERSPACE_REBOOT);
    
#if REQUIRE_FULL_USERSPACE_REBOOT
    char *is_reload = getenv("libhooker-launchd-reload");
    if (is_reload && strcmp(is_reload, "1") == 0) {

        DYLD_INTERPOSE(posix_spawn_hook, posix_spawn);
        DYLD_INTERPOSE(posix_spawnp_hook, posix_spawnp);
        DYLD_INTERPOSE(xpc_dictionary_get_value_hook, xpc_dictionary_get_value);
        
        // Remount checkra1n's binpack
        remount_checkra1n_binpack();
        
        return;
    }

    setenv("DYLD_INSERT_LIBRARIES", "/fs/jb/usr/libexec/libhooker/launchd_hooks.dylib", 1);
    setenv("libhooker-launchd-reload", "1", 1);
#else
    void *lhHandle = dlopen("/fs/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", 0);
    serial_println("libhooker dyld handle: %p", lhHandle);

    if (lhHandle) {
        _MSHookFunction = dlsym(lhHandle, "MSHookFunction");
        _MSHookFunction((void *)posix_spawn, (void *)posix_spawn_hook, (void **)&orig_posix_spawn);
        _MSHookFunction((void *)posix_spawnp, (void *)posix_spawnp_hook, (void **)&orig_posix_spawnp);
        serial_println("succesfully hooked posix_spawn functions");
    }
#endif
}
