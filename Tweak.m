// === DIAGNOSTIC VERSION ===
// Step 1: Check if ad-hoc codesign entitlements (root + no-sandbox) are working
// Step 2: If YES → skip kexploit entirely (no PAC panic risk!)
// Step 3: If NO → try kexploit with crash protection
// Step 4: Always log Xcode Console before/after every step

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dirent.h>
#import <unistd.h>
#import <errno.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <objc/message.h>
#import <xpc/xpc.h>
#import <signal.h>

#import "kexploit/kexploit_opa334.h"
#import "kexploit/kutils.h"
#import "sandbox_escape.h"
#import "apfs_own.h"

#pragma mark - Crash Protection

#import signal.h>
static volatile sig_atomic_t g_kexploit_crashed = 0;
static void crash_handler(int sig) {
    g_kexploit_crashed = 1;
    NSLog(@"[Tweak] !!! CRASHED with signal %d (SIGSEGV=%d SIGABRT=%d SIGTRAP=%d)",
          sig, SIGSEGV, SIGABRT, SIGTRAP);
    // Don't really crash — write marker and let app continue without kexploit
    // NOTE: signal handler context is restricted, but NSLog usually works once
}

static void install_crash_handler(void) {
    struct sigaction sa = {0};
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

#pragma mark - Entitlement Check

static BOOL g_kexploit_done = NO;
static BOOL g_entitlements_worked = NO;

static void check_entitlements_first(void) {
    // Check 1: getuid() — should be 0 if com.apple.security.root entitlement works
    uid_t uid = getuid();
    BOOL is_root = (uid == 0);
    NSLog(@"[DIAG] getuid()=%d geteuid()=%d — %s", uid, geteuid(), is_root ? "ROOT!" : "NOT root");
    
    // Check 2: open a known path that requires sandbox bypass
    // /var/mobile/Library/Carrier Bundles should be accessible if no-sandbox works
    int fd = open("/var/mobile/Library/Carrier Bundles", O_RDONLY);
    BOOL can_access_cb = (fd >= 0);
    if (fd >= 0) close(fd);
    NSLog(@"[DIAG] open('Carrier Bundles')=%d errno=%d(%s) — %s",
          fd, errno, strerror(errno), can_access_cb ? "OK!" : "FAIL");
    
    // Check 3: stat root-owned path
    struct stat st;
    int st_ret = stat("/var/root", &st);
    BOOL can_stat_root = (st_ret == 0);
    NSLog(@"[DIAG] stat('/var/root')=%d errno=%d — %s",
          st_ret, errno, can_stat_root ? "OK!" : "FAIL");
    
    g_entitlements_worked = is_root || can_access_cb;
    NSLog(@"[DIAG] === ENTITLEMENT CHECK RESULT: %s ===", g_entitlements_worked ? "WORKED (skip kexploit!)" : "FAILED (need kexploit)");
}

#pragma mark - Hook Installs (unchanged from v6)

static BOOL hook_isRootHelperAvailable(id self, SEL _cmd) { return NO; }
static int hook_spawnRootHelper(id self, SEL _cmd) { return 0; }
static int hook_spawnRootHelperIfNeeds(id self, SEL _cmd) { return 0; }
static int hook_respawnRootHelper(id self, SEL _cmd) { return 0; }
static void hook_tryLoadFilzaHelper(id self, SEL _cmd) {}
static void hook_createHelperConnectionIfNeeds(id self, SEL _cmd) {}
static int hook_spawnRoot_args_pid(id self, SEL _cmd, id path, id args, int *pid) { if (pid) *pid = 0; return -1; }
static id hook_sendObjectWithReplySync(id self, SEL _cmd, id msg) { return (id)xpc_null_create(); }
static id hook_sendObjectWithReplySync_fd(id self, SEL _cmd, id msg, int *fd) { if (fd) *fd = -1; return (id)xpc_null_create(); }
static id hook_sendObjectWithReplySync_fd_logintty(id self, SEL _cmd, id msg, int *fd, BOOL logintty) { if (fd) *fd = -1; return (id)xpc_null_create(); }
static void hook_sendObjectNoReply(id self, SEL _cmd, id msg) {}
static id hook_sendObjectWithReplyAsync(id self, SEL _cmd, id msg, id queue, id completion) { if (completion) { void (^b)(id) = completion; b(nil); } }

static void installHooks(void) {
    Class rfm = NSClassFromString(@"TGRootFileManager");
    if (rfm) {
        Class meta = object_getClass(rfm);
        class_replaceMethod(meta, @selector(isRootHelperAvailable), (IMP)hook_isRootHelperAvailable, "B@:");
        class_replaceMethod(rfm, @selector(spawnRootHelper), (IMP)hook_spawnRootHelper, "i@:");
        class_replaceMethod(rfm, @selector(spawnRootHelperIfNeeds), (IMP)hook_spawnRootHelperIfNeeds, "i@:");
        class_replaceMethod(rfm, @selector(respawnRootHelper), (IMP)hook_respawnRootHelper, "i@:");
        class_replaceMethod(rfm, @selector(tryLoadFilzaHelper), (IMP)hook_tryLoadFilzaHelper, "v@:");
        class_replaceMethod(rfm, @selector(createHelperConnectionIfNeeds), (IMP)hook_createHelperConnectionIfNeeds, "v@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"spawnRoot:args:pid:"), (IMP)hook_spawnRoot_args_pid, "i@:@@^i");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:"), (IMP)hook_sendObjectWithReplySync, "@@:@");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:fileDescriptor:"), (IMP)hook_sendObjectWithReplySync_fd, "@@:@^i");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:fileDescriptor:logintty:"), (IMP)hook_sendObjectWithReplySync_fd_logintty, "@@:@^iB");
        class_replaceMethod(rfm, @selector(sendObjectNoReply:), (IMP)hook_sendObjectNoReply, "v@:@");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplyAsync:queue:completion:"), (IMP)hook_sendObjectWithReplyAsync, "v@:@@?");
    }
    NSLog(@"[DIAG] All hooks installed");
}

#pragma mark - Exploit Runner

static void runExploitSafe(void) {
    NSLog(@"[DIAG] === START EXPLOIT (with crash protection) ===");
    
    if (g_entitlements_worked) {
        NSLog(@"[DIAG] SKIPPING kexploit — entitlements already give us root/no-sandbox");
        // Skip straight to sandbox_elevate — with com.apple.security.root we might still need kernel-side fixes
        // Actually if com.apple.security.root works, getuid() is already 0, but proc structs still need PAC strip
        return;
    }
    
    NSLog(@"[DIAG] Running kexploit_opa334()...");
    sig_atomic_t before_crash = g_kexploit_crashed;
    int kret = -1;
    @try {
        kret = kexploit_opa334();
    } @catch (NSException *e) {
        NSLog(@"[DIAG] kexploit ObjC exception: %@", e);
    }
    
    if (g_kexploit_crashed != before_crash) {
        NSLog(@"[DIAG] !!! kexploit CRASHED !!! (signal handler fired)");
        return;
    }
    
    NSLog(@"[DIAG] kexploit returned %d", kret);
    if (kret != 0) {
        NSLog(@"[DIAG] kexploit failed — skipping sandbox_escape");
        return;
    }
    
    NSLog(@"[DIAG] kexploit OK! Running sandbox_escape...");
    uint64_t self_proc_addr = proc_self();
    NSLog(@"[DIAG] self_proc = 0x%llx", self_proc_addr);
    
    @try {
        int sret = sandbox_escape(self_proc_addr);
        NSLog(@"[DIAG] sandbox_escape = %d", sret);
    } @catch (NSException *e) {
        NSLog(@"[DIAG] sandbox_escape exception: %@", e);
    }
    
    @try {
        int eret = sandbox_elevate_to_root(self_proc_addr);
        NSLog(@"[DIAG] sandbox_elevate_to_root = %d", eret);
    } @catch (NSException *e) {
        NSLog(@"[DIAG] sandbox_elevate exception: %@", e);
    }
    
    NSLog(@"[DIAG] Final: getuid()=%d", getuid());
}

#pragma mark - Entry Point

__attribute__((constructor)) void TweakInit(void) {
    install_crash_handler();
    installHooks();
    NSLog(@"[DIAG] ============ TweakInit DONE ============");
    
    // Delay exploit — wait 5s so user can open Xcode Console
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
        object:nil queue:nil usingBlock:^(NSNotification *note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
                       dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            NSLog(@"[DIAG] 5s delay over, starting checks...");
            check_entitlements_first();
            runExploitSafe();
            NSLog(@"[DIAG] ============ EXPLOIT PHASE DONE ============");
        });
    }];
}
