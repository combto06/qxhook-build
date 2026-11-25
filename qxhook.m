//
// qxhook.m — 通用授权 hook dylib
//
// 原理：不修改主程序（避开完整性校验），运行时替换授权判定方法。
// 参考 Via-STE 破解版的 QXGate / QXLicenseWatcher 做法。
//
// 编译：clang -arch arm64 -miphoneos-version-min=14.0 -dynamiclib \
//         -framework Foundation -framework UIKit \
//         -o qxhook.dylib qxhook.m
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>

static const char *kLogTag = "[QXHook]";
static NSMutableSet *gHookedClasses = nil;

static void qxlog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"%s %@", kLogTag, msg);
}

#pragma mark - 通用方法替换

// 把某个类上的无参方法替换成返回固定值
static BOOL qx_replaceBoolReturn(Class cls, SEL sel, BOOL value) {
    if (!cls || !sel) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;

    IMP block = imp_implementationWithBlock(^BOOL(id _self) {
        qxlog(@"%@ - %@ -> %d", NSStringFromClass([_self class]),
              NSStringFromSelector(sel), value);
        return value;
    });
    method_setImplementation(m, block);
    return YES;
}

static BOOL qx_replaceIntReturn(Class cls, SEL sel, long value) {
    if (!cls || !sel) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    IMP block = imp_implementationWithBlock(^long(id _self) {
        qxlog(@"%@ - %@ -> %ld", NSStringFromClass([_self class]),
              NSStringFromSelector(sel), value);
        return value;
    });
    method_setImplementation(m, block);
    return YES;
}

static BOOL qx_replaceIdReturn(Class cls, SEL sel, id value) {
    if (!cls || !sel) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    IMP block = imp_implementationWithBlock(^id(id _self) {
        qxlog(@"%@ - %@ -> %@", NSStringFromClass([_self class]),
              NSStringFromSelector(sel), value);
        return value;
    });
    method_setImplementation(m, block);
    return YES;
}

#pragma mark - 目标 selector 清单

// 返回 BOOL 的授权判定方法
static const char *kBoolSelectors[] = {
    "isValid", "isAuthorized", "isLicensed", "isActivated", "isBound",
    "isExpired", "hasLicense", "authorized", "licensed", "activated",
    "isPro", "isPremium", "unlocked", "sharesLiveMap",
    "verifyReceipt", "verifyReceiptV2", "verifyReceiptEx", "verifyReceiptStrict",
    "checkLicense", "checkLicenseV2", "checkLicenseEx", "checkLicenseStrict",
    "validateToken", "validateTokenV2", "validateTokenEx", "validateTokenStrict",
    "auditIntegrity", "auditReceipt", "scanReceipt", "inspectReceipt",
    "verifySignature", "verifyLicense", "validateReceipt",
    NULL
};

// 返回枚举/整型的
static const char *kIntSelectors[] = {
    "activationState", "licenseState", "authState", "authorizationStatus",
    NULL
};

#pragma mark - 全类扫描并替换

static void qx_hook_all_classes(void) {
    int total = objc_getClassList(NULL, 0);
    if (total <= 0) return;

    Class *classes = (Class *)malloc(sizeof(Class) * total);
    if (!classes) return;
    total = objc_getClassList(classes, total);

    int hooked = 0;
    for (int i = 0; i < total; i++) {
        Class cls = classes[i];
        const char *name = class_getName(cls);
        if (!name) continue;

        // 只看与本 App 相关的类（排除系统类）
        NSString *cn = [NSString stringWithUTF8String:name];
        BOOL relevant = NO;
        for (NSString *pre in @[@"QXA", @"_License", @"_LV_", @"_SE_", @"_Keystore",
                                @"_KG_", @"_BM_", @"_BX_", @"_AntiTamper", @"_Binary",
                                @"_Certificate", @"_QBL", @"QX", @"_AC_"]) {
            if ([cn hasPrefix:pre]) { relevant = YES; break; }
        }
        if (!relevant) continue;

        // BOOL 方法
        for (int k = 0; kBoolSelectors[k]; k++) {
            SEL sel = sel_registerName(kBoolSelectors[k]);
            if (class_getInstanceMethod(cls, sel)) {
                // isExpired / isBound 之类的语义相反的，返回 NO
                BOOL val = YES;
                NSString *sn = [NSString stringWithUTF8String:kBoolSelectors[k]];
                if ([sn containsString:@"xpired"] || [sn containsString:@"ivergenc"] ||
                    [sn containsString:@"nvalid"] || [sn containsString:@"amper"]) {
                    val = NO;
                }
                if (qx_replaceBoolReturn(cls, sel, val)) {
                    hooked++;
                }
            }
        }

        // 整型状态
        for (int k = 0; kIntSelectors[k]; k++) {
            SEL sel = sel_registerName(kIntSelectors[k]);
            if (class_getInstanceMethod(cls, sel)) {
                if (qx_replaceIntReturn(cls, sel, 1)) hooked++;
            }
        }
    }

    free(classes);
    qxlog(@"扫描 %d 个类，替换 %d 个方法", total, hooked);
}

#pragma mark - NSUserDefaults / Keychain 兜底

static void qx_hook_userdefaults(void) {
    Class UD = objc_getClass("NSUserDefaults");
    if (!UD) return;

    // 拦截读授权字段
    SEL sel = sel_registerName("objectForKey:");
    Method m = class_getInstanceMethod(UD, sel);
    if (!m) return;
    IMP orig = method_getImplementation(m);

    IMP repl = imp_implementationWithBlock(^id(id _self, NSString *key) {
        if (key && [key isKindOfClass:[NSString class]]) {
            NSString *low = [key lowercaseString];
            if ([low containsString:@"license"] || [low containsString:@"expire"] ||
                [low containsString:@"activ"] || [low containsString:@"bound"]) {
                qxlog(@"UserDefaults 读 %@ -> 伪造", key);
                // 授权相关的布尔/时间字段
                if ([low containsString:@"expire"] || [low containsString:@"end"]) {
                    return @(9999999999.0);   // 到期时间：2286 年
                }
                return @YES;
            }
        }
        id (*fn)(id, SEL, NSString *) = (void *)orig;
        return fn(_self, sel, key);
    });
    method_setImplementation(m, repl);
    qxlog(@"NSUserDefaults objectForKey: 已挂");
}

#pragma mark - 入口

__attribute__((constructor))
static void qx_init(void) {
    qxlog(@"===== QXHook 加载 =====");

    @autoreleasepool {
        // 延迟执行，等主程序类都注册完
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool {
                qx_hook_userdefaults();
                qx_hook_all_classes();
                qxlog(@"===== QXHook 完成 =====");
            }
        });
    }
}
