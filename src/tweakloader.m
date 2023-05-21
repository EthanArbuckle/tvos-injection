#include <syslog.h>

/*
 The tweakloader is a dylib injected into all xpc services and processes. It is responsible for loading user-installed tweaks.
 Hooks in launchd and xpcproxy ensure that tweakloader is brought into all relevant processes.
 */

void __attribute__((constructor)) init_tweakloader_hooks(void) {
    
    syslog(0, "tweakloader injected");
}
