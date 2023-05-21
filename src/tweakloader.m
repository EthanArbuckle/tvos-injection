#import <Foundation/Foundation.h>
#include <mach-o/dyld_images.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <sys/stat.h>
#import <syslog.h>
#import <dlfcn.h>

/*
 The tweakloader is a dylib injected into all xpc services and processes. It is responsible for loading user-installed tweaks.
 Hooks in launchd and xpcproxy ensure that tweakloader is brought into all relevant processes.
 */

#define TWEAK_DIRECTORY @"/fs/jb/Library/MobileSubstrate/DynamicLibraries"
#define LIBHOOKER_SAFEMODE_FILE "/tmp/.libhhoker_safemode"
static BOOL isSystemApp = NO;

struct libhooker_image {
    const void *imageHeader;
    uintptr_t slide;
    void *dyldHandle;
};
static void (*_MSHookFunction)(void *symbol, void *replace, void **result);
static bool (*_LHFindSymbols)(struct libhooker_image *libhookerImage, const char **symbolNames, void **searchSyms, size_t searchSymCount);


static void LHLog(NSString *format, ...) {
    
    va_list args;
    va_start(args, format);
    NSString *str = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    syslog(0, "tweakloader: %s", str.UTF8String);
}

const char *last_path_component(const char *path) {
    
    const char *last_path_component = strrchr(path, '/');
    if (last_path_component != NULL) {
        return last_path_component + 1;
    }
    
    return path;
}

static NSArray *locate_dylibs_to_inject(const char *executable_path, CFStringRef bundleId) {
    
    NSArray *dylibDirContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:TWEAK_DIRECTORY error:nil];
    if (!dylibDirContents || [dylibDirContents count] < 1) {
        return nil;
    }
    
    NSArray *tweakFilterPlistNames = [dylibDirContents filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"SELF ENDSWITH %@", @"plist"]];
    if (!tweakFilterPlistNames || [tweakFilterPlistNames count] < 1) {
        return nil;
    }
    
    const char *current_executable_name = last_path_component(executable_path);
    
    NSMutableArray *applicableDylibs = [[NSMutableArray alloc] init];
    for (NSString *plistName in tweakFilterPlistNames) {
        
        NSString *absolutePlistPath = [TWEAK_DIRECTORY stringByAppendingPathComponent:plistName];
        NSDictionary *tweakPlistContents = [NSDictionary dictionaryWithContentsOfFile:absolutePlistPath];
        
        // Bail if the plist could not be read or if its not a dictionary
        if (!tweakPlistContents || ![tweakPlistContents isKindOfClass:[NSDictionary class]]) {
            continue;
        }
        
        // Bail if the plist does not specify a filter or if the filter is not a dictionary
        NSDictionary *tweakFilter = [tweakPlistContents valueForKey:@"Filter"];
        if (!tweakFilter || ![tweakFilter isKindOfClass:[NSDictionary class]]) {
            continue;
        }
        
        // Enforce CoreFoundationVersion
        NSArray *supportedVersions = tweakFilter[@"CoreFoundationVersion"];
        if (supportedVersions && supportedVersions.count >= 1 && supportedVersions.count <= 2) {
            double version0 = [supportedVersions[0] doubleValue];
            double version1 = supportedVersions.count == 2 ? [supportedVersions[1] doubleValue] : version0;
            if (version0 > kCFCoreFoundationVersionNumber || version1 <= kCFCoreFoundationVersionNumber) {
                continue;
            }
        }
        
        // Determine which tweaks should be injected into this process
        BOOL shouldInject = NO;
        
        // Bundle filters
        NSArray *bundleFilters = tweakFilter[@"Bundles"];
        if (bundleFilters && [bundleFilters isKindOfClass:[NSArray class]]) {
            for (NSString *bundleFilter in bundleFilters) {
                // Inject if a bundle with the specified ID is present in this process
                CFBundleRef candidateBundle = CFBundleGetBundleWithIdentifier((CFStringRef)bundleFilter);
                if (candidateBundle && CFBundleIsExecutableLoaded(candidateBundle)) {
                    // The specified bundle exists -- inject the tweak.
                    // No need to keep searching after the first hit
                    shouldInject = YES;
                    break;
                }
            }
        }
        
        // Executable filters
        if (!shouldInject) {
            NSArray *executableFilters = tweakFilter[@"Executables"];
            if (executableFilters && [executableFilters isKindOfClass:[NSArray class]]) {
                for (NSString *executableFilter in executableFilters) {
                    if (strcmp(executableFilter.UTF8String, current_executable_name) == 0) {
                        shouldInject = YES;
                        break;
                    }
                }
            }
        }
        
        if (!shouldInject) {
            NSArray *classFilters = tweakFilter[@"Classes"];
            if (classFilters && [classFilters isKindOfClass:[NSArray class]]) {
                for (NSString *classFilter in classFilters) {
                    if (classFilter && objc_getClass(classFilter.UTF8String) != NULL) {
                        shouldInject = YES;
                        break;
                    }
                }
            }
        }
        
        // If this dylib qualifies for injection, add it to applicableDylibs
        if (shouldInject) {
            [applicableDylibs addObject:[[absolutePlistPath stringByDeletingPathExtension] stringByAppendingString:@".dylib"]];
        }
    }
    
    // For historically reasons, it's expected that tweaks are loading in alphabetical order :(
    [applicableDylibs sortUsingSelector:@selector(caseInsensitiveCompare:)];
    return applicableDylibs;
}

static void signal_handler(int signal, siginfo_t *info, void *uap) {
    
    // Caught an exception signal -- process is dying.
    // If this is PineBoard/backboardd, write the safemode file to disk to disable
    // tweak injection when the process respawns
    if (isSystemApp) {
        FILE *safemode_file = fopen(LIBHOOKER_SAFEMODE_FILE, "w");
        if (safemode_file) {
            fprintf(safemode_file, "who broke something?\n");
            fclose(safemode_file);
        }
    }
    
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    sigaction(signal, &action, NULL);
    raise(signal);
}

static int (*original_open)(const char *path, int oflag, int other);
static int replacement_open(const char *path, int oflag, int other) {
    int result = original_open(path, oflag, other);
    
    // If dyld failed to locate the file, try adding the jailbreak prefix path to it
    if (result < 1) {
        const char *prefix = "/fs/jb";
        char *fixed_path = malloc((strlen(prefix) + strlen(path) + 1) * sizeof(char));
        sprintf(fixed_path, "%s%s", prefix, path);
        result = original_open(fixed_path, oflag, other);
        free(fixed_path);
    }
    
    return result;
}

__attribute__ ((constructor)) static void init_tweakloader(void) {
    
    @autoreleasepool {
        unsetenv("DYLD_INSERT_LIBRARIES");
        
        // Grab this processes bundle id, which may or may not exist (not everything is a bundle)
        CFBundleRef mainBundle = CFBundleGetMainBundle();
        CFStringRef bundleID = NULL;
        if (mainBundle) {
            bundleID = CFBundleGetIdentifier(mainBundle);
        }
        
        // Grab the path to this processes executable, which should always exist
        char current_executable_path[PATH_MAX];
        uint32_t current_executable_path_len = PATH_MAX;
        _NSGetExecutablePath(current_executable_path, &current_executable_path_len);
        
        // SafeMode is automatically enabled when PineBoard or backboardd crash.
        // For other processes, the presence of the _MSSafeMode or _SafeMode environment variables will enable safemode
        BOOL safeModeEnabled = (getenv("_MSSafeMode") != NULL && strcmp(getenv("_MSSafeMode"), "1") == 0) || (getenv("_SafeMode") != NULL && strcmp(getenv("_SafeMode"), "1") == 0);
        isSystemApp = strcmp(current_executable_path, "/Applications/PineBoard.app/PineBoard") == 0 || strcmp(current_executable_path, "/usr/libexec/backboardd") == 0;
        
        if (!safeModeEnabled && isSystemApp) {
            // If safemode is not explicity enabled via environment variables, but this is Pineboard or backboardd, check for the file that indicates one of those processess crashed
            struct stat buffer;
            safeModeEnabled = stat(LIBHOOKER_SAFEMODE_FILE, &buffer) == 0;
        }
        
        // Safe mode is enabled -- do not inject anything into this process
        // TODO: Show some custom UI for safemode / respringing out of safemode
        if (safeModeEnabled) {
            // Delete the file so safemode is disabled on next respring
            unlink(LIBHOOKER_SAFEMODE_FILE);
            LHLog(@"libhooker: safemode enabled for %s. not injecting anything.", current_executable_path);
            return;
        }

        // Setup signal handlers to catch exceptions (so safemode can be enabled)
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_sigaction = &signal_handler;
        action.sa_flags = SA_SIGINFO | SA_RESETHAND;
        sigemptyset(&action.sa_mask);
        
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGILL, &action, NULL);
        sigaction(SIGTRAP, &action, NULL);
        sigaction(SIGABRT, &action, NULL);
        sigaction(SIGEMT, &action, NULL);
        sigaction(SIGFPE, &action, NULL);
        sigaction(SIGBUS, &action, NULL);
        sigaction(SIGSEGV, &action, NULL);
        sigaction(SIGSYS, &action, NULL);
        
        // Gather up the tweaks that should be injected into this process
        NSArray *tweaksToInject = locate_dylibs_to_inject(current_executable_path, bundleID);
        
        if ([tweaksToInject count] > 0) {
            // There are tweaks to inject!
            // However, their load commands may point to libraries (like Substrate/Substitute/Libhooker) expected to be on the System partition.
            // To workaround this without requiring tweaks to be recompiled to binary-patched, hook dyld's `open()` function and, when some file fails to be located, attempt to
            // find it inside the new jailbreak prefix path
            void *lhHandle = dlopen("/fs/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", 0);
            _MSHookFunction = dlsym(lhHandle, "MSHookFunction");
            _LHFindSymbols = dlsym(lhHandle, "LHFindSymbols");
            
            struct task_dyld_info dyldInfo;
            mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
            if (task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count) == KERN_SUCCESS) {
                
                // Only interested in dyld'd `open()`. We don't want to catch invocations this process makes to `open()`.
                // dyld cannot be dlopen()'d, but we can get to its symbol table using its mach_header (from dyld_all_image_infos)
                const struct dyld_all_image_infos *imageInfos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
                struct libhooker_image *lh_image = (struct libhooker_image *)malloc(sizeof(struct libhooker_image));
                lh_image->imageHeader = imageInfos->dyldImageLoadAddress;
                lh_image->slide = -1;
                lh_image->dyldHandle = NULL;
                
                const char *symbol_names[1] = {
                    "_open"
                };
                void *symbol_pointers[1];
                
                int success = _LHFindSymbols(lh_image, symbol_names, symbol_pointers, 1);
                if (success && symbol_pointers[0] != NULL) {
                    _MSHookFunction((void *)symbol_pointers[0], (void *)replacement_open, (void **)&original_open);
                }
                
                free(lh_image);
            }
        }
        
        for (NSString *dylibPath in tweaksToInject) {
            const char *dylib_name = [dylibPath lastPathComponent].UTF8String;
            if (dlopen(dylibPath.UTF8String, RTLD_LAZY | RTLD_GLOBAL) == NULL) {
                LHLog(@"failed to inject %s: %s", dylib_name, dlerror());
            }
            else {
                LHLog(@"successfully injected %s", dylib_name);
            }
        }
    }
}
