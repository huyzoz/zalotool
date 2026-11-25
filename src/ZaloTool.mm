// ZaloTool.dylib — Zalo iOS 26.11.02.1 (build 261102804) mod.
// Hooks 4 mods, all toggled from inside Zalo's own Settings screen:
//   "Tài khoản và Bảo mật" (AccountSettingUI40ViewController) -> "Tool" row
//   at the top -> settings page with 4 UISwitch toggles (all ON by default).
//
// Mod A: hide seen / typing / delivered (swallow, never call orig).
// Mod B: confirm before call (VoipFlowManager choke point, alert -> orig).
// Mod C: confirm before sending image (willSendMedia: choke point, alert -> orig).
// Mod D: anti-recall (swallow, never call orig).
//
// Safety rules (see HANDOFF.md):
// - Init via __attribute__((constructor)); modern ld64 on arm64 emits this
//   as __TEXT,__init_offsets (S_INIT_FUNC_OFFSETS), NOT __mod_init_func.
//   No +load anywhere.
// - FIRST thing in init: bundle-ID guard (vn.com.vng.zingalo only).
// - Every hook is nil/missing-method safe; a missing class/method never crashes.
// - MSHookMessageEx is resolved at runtime with dlopen + dlsym (NOT linked):
//   the shipped CydiaSubstrate.framework binary carries
//   LC_ID_DYLIB /usr/local/lib/libellekit.dylib, so a link-time -framework
//   reference would record a path that does not exist on device.
// - NO network calls, NO file writes, NO save/asset modification, NO IAP
//   strings, NO ad code, NO timers, NO render-loop hooks, NO per-frame work.
// - No main-binary patching: injection happens through BackupProtoLib only
//   (see scripts/inject_backupprotolib.py).
//
// Method type encodings below were read off the real 26.11.02.1 binary
// (see HANDOFF.md §2); replacement signatures match them exactly.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

// ---------------------------------------------------------------------------
// MSHookMessageEx (ElleKit / CydiaSubstrate) — resolved at runtime.
// ---------------------------------------------------------------------------
typedef void (*MSHookMessageExFn)(Class _class, SEL message, IMP hook, IMP *old);
static MSHookMessageExFn g_MSHookMessageEx = NULL;

// ---------------------------------------------------------------------------
// Mods + persisted toggles (NSUserDefaults, all ON by default).
// Every hook reads its toggle at fire time; turning a toggle OFF restores
// stock Zalo behaviour for that mod immediately (no restart needed).
// ---------------------------------------------------------------------------
typedef NS_ENUM(NSInteger, ZMMod) {
    ZMModHideSeen = 0,   // Mod A
    ZMModConfirmCall,    // Mod B
    ZMModConfirmSend,    // Mod C
    ZMModAntiRecall      // Mod D
};

static NSString *const kZMKeyHideSeen    = @"ZaloTool.HideSeen";
static NSString *const kZMKeyConfirmCall = @"ZaloTool.ConfirmCall";
static NSString *const kZMKeyConfirmSend = @"ZaloTool.ConfirmSend";
static NSString *const kZMKeyAntiRecall  = @"ZaloTool.AntiRecall";

static NSString *ZMKeyForMod(ZMMod mod) {
    switch (mod) {
        case ZMModHideSeen:    return kZMKeyHideSeen;
        case ZMModConfirmCall: return kZMKeyConfirmCall;
        case ZMModConfirmSend: return kZMKeyConfirmSend;
        case ZMModAntiRecall:  return kZMKeyAntiRecall;
    }
    return nil;
}

static BOOL ZMModEnabled(ZMMod mod) {
    NSString *key = ZMKeyForMod(mod);
    if (!key) return YES;
    return [[NSUserDefaults standardUserDefaults] boolForKey:key];
}

static void ZMRegisterDefaults(void) {
    [[NSUserDefaults standardUserDefaults] registerDefaults:@{
        kZMKeyHideSeen:    @YES,
        kZMKeyConfirmCall: @YES,
        kZMKeyConfirmSend: @YES,
        kZMKeyAntiRecall:  @YES,
    }];
}

// ---------------------------------------------------------------------------
// Orig-IMP store for the 28 RE-verified hooks, keyed by selector name.
// Selector names are unique across mods A/B/D, so one entry per selector is
// enough; Mod C (same selector on 3 classes) keeps per-class static IMPs
// below instead. Subclass instances (e.g. ChatTableViewController calling
// a BaseChatTVC hook) resolve by selector too, which is exactly right.
// ---------------------------------------------------------------------------
static NSMutableDictionary<NSString *, NSValue *> *g_origIMPs = nil;

static void ZMStoreOrig(SEL sel, IMP orig) {
    if (!sel || !orig || !g_origIMPs) return;
    g_origIMPs[NSStringFromSelector(sel)] = [NSValue valueWithPointer:orig];
}

static IMP ZMOrigForSel(SEL sel) {
    if (!sel || !g_origIMPs) return NULL;
    NSValue *v = g_origIMPs[NSStringFromSelector(sel)];
    return v ? (IMP)[v pointerValue] : NULL;
}

// ---------------------------------------------------------------------------
// Hook spec table — mirrors hook_table_verified.json (28 hooks).
// sig selects the replacement function; mod selects the toggle.
// ---------------------------------------------------------------------------
typedef NS_ENUM(NSInteger, ZMSig) {
    ZMSigSwallowVoid0 = 0,  // () -> void
    ZMSigSwallowObj1,       // (id) -> void
    ZMSigSwallowObjLong,    // (id, long) -> void
    ZMSigSwallowLong1,      // (long) -> void
    ZMSigSwallowObj3,       // (id, id, id) -> void
    ZMSigSwallowObjBoolLong,// (id, BOOL, long) -> void
    ZMSigSwallowTyping,     // (long, id, long, BOOL) -> BOOL
    ZMSigCallUserId,        // Mod B: (id, long, long) -> void
    ZMSigCallUserIdParams,  // Mod B: (id, long, long, id) -> void
    ZMSigCallGroup,         // Mod B: (id, id, long, long) -> void
    ZMSigCallGroupParams,   // Mod B: (id, id, long, long, id) -> void
    ZMSigCallPhone,         // Mod B: (id, BOOL, long) -> void
    ZMSigSendMedia          // Mod C: (id, id, long) -> void
};

typedef struct {
    const char *cls;
    const char *sel;
    BOOL meta;      // YES = class method (hook the metaclass)
    ZMMod mod;
    ZMSig sig;
} ZMHookSpec;

// clang-format off
static const ZMHookSpec kZMHookSpecs[] = {
    // Mod A — hide seen / typing / delivered (15)
    {"ChatSendSeenDataManager", "sendSeenWithChatEntity:", NO, ZMModHideSeen, ZMSigSwallowObj1},
    {"ChatSendSeenDataManager", "addChatSeenWithLastChatEntity:", NO, ZMModHideSeen, ZMSigSwallowObj1},
    {"ChatSendSeenDataManager", "sendSeenServerPeriodicallyIfNeeded", NO, ZMModHideSeen, ZMSigSwallowVoid0},
    {"ChatSendSeenDataManager", "sendAllFailedSeenMessage", NO, ZMModHideSeen, ZMSigSwallowVoid0},
    {"ChatSendSeenDataManager", "sendSeenLastMessageWithThreadIds:withMessageType:", NO, ZMModHideSeen, ZMSigSwallowObjLong},
    {"ChatSendSeenDataManager", "sendSeenServer", NO, ZMModHideSeen, ZMSigSwallowVoid0},
    {"ChatSendSeenDataManager", "forceSendSeenServer", NO, ZMModHideSeen, ZMSigSwallowVoid0},
    {"ChatSendSeenDataManager", "_sendSeenMessageWithSeenData:messageType:", NO, ZMModHideSeen, ZMSigSwallowObjLong},
    {"BaseChatTVC", "sendSeenInfoInboxEntity:", NO, ZMModHideSeen, ZMSigSwallowObj1},
    {"BaseChatTVC", "sendSeenForLastReadMessage", NO, ZMModHideSeen, ZMSigSwallowVoid0},
    {"BaseChatTVC", "sendSeenMessageWithTalkTableItem:", NO, ZMModHideSeen, ZMSigSwallowObj1},
    {"BaseChatTVC", "sendSeenMessageWithChatEntity:", NO, ZMModHideSeen, ZMSigSwallowObj1},
    {"BaseChatProcessor", "sendSeenMessages:messageDict:incomingData:", NO, ZMModHideSeen, ZMSigSwallowObj3},
    {"ChatDataManager", "sendTypingWithType:toUserId:messageType:isE2eeChat:", NO, ZMModHideSeen, ZMSigSwallowTyping},
    // NOTE: the 2-param sendChatDeliveredMessages:isSeen: does NOT exist in
    // this build (verified absent) — only the 3-param form is hooked.
    {"ChatSocketCmdHelper", "sendChatDeliveredMessages:isSeen:commandType:", YES, ZMModHideSeen, ZMSigSwallowObjBoolLong},
    // Mod B — confirm before call (6)
    {"VoipFlowManager", "callWithUserId:withCallType:withSource:", NO, ZMModConfirmCall, ZMSigCallUserId},
    {"VoipFlowManager", "callWithUserId:withCallType:withSource:withParams:", NO, ZMModConfirmCall, ZMSigCallUserIdParams},
    {"VoipFlowManager", "_callWithUserId:withCallType:withSource:withParams:", NO, ZMModConfirmCall, ZMSigCallUserIdParams},
    {"VoipFlowManager", "callWithGroupId:withPartners:withCallType:withSource:", NO, ZMModConfirmCall, ZMSigCallGroup},
    {"VoipFlowManager", "callWithGroupId:withPartners:withCallType:withSource:withParams:", NO, ZMModConfirmCall, ZMSigCallGroupParams},
    {"VoipFlowManager", "callWithPhoneNumber:hasVideo:withSource:", NO, ZMModConfirmCall, ZMSigCallPhone},
    // Mod C — confirm before sending image (3)
    {"UXChatFilePhotoActionSheetController", "mediaEditorViewController:willSendMedia:quality:", NO, ZMModConfirmSend, ZMSigSendMedia},
    {"UXChatFilePageController", "mediaEditorViewController:willSendMedia:quality:", NO, ZMModConfirmSend, ZMSigSendMedia},
    {"UXChatPhotoActionSheetController", "mediaEditorViewController:willSendMedia:quality:", NO, ZMModConfirmSend, ZMSigSendMedia},
    // Mod D — anti-recall (4)
    {"MSDataCoordinator", "handleRecallMessageNotification:", NO, ZMModAntiRecall, ZMSigSwallowObj1},
    {"MSDataCoordinator", "_handleRecallWithData:", NO, ZMModAntiRecall, ZMSigSwallowObj1},
    {"ChatEntity", "set_originTextRecallMsg:", NO, ZMModAntiRecall, ZMSigSwallowObj1},
    {"ChatEntity", "set_recallTime:", NO, ZMModAntiRecall, ZMSigSwallowLong1},
};
static const size_t kZMHookSpecCount = sizeof(kZMHookSpecs) / sizeof(kZMHookSpecs[0]);
// clang-format on

static ZMMod ZMModForSel(SEL sel) {
    if (!sel) return ZMModHideSeen;
    const char *name = sel_getName(sel);
    for (size_t i = 0; i < kZMHookSpecCount; i++) {
        if (strcmp(kZMHookSpecs[i].sel, name) == 0) return kZMHookSpecs[i].mod;
    }
    return ZMModHideSeen;
}

// ---------------------------------------------------------------------------
// Swallow replacements (Mods A + D). When the toggle is OFF the original
// implementation is called; when ON the call is dropped. All return the
// "nothing happened" value (nil / NO / 0) so a caller that reads the
// return value sees a safe zero instead of garbage.
// ---------------------------------------------------------------------------
static id ZMSwallowVoid0(id self, SEL _cmd) {
    (void)self;
    if (!ZMModEnabled(ZMModForSel(_cmd))) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) return ((id (*)(id, SEL))orig)(self, _cmd);
    }
    return nil;
}

static id ZMSwallowObj1(id self, SEL _cmd, id a1) {
    if (!ZMModEnabled(ZMModForSel(_cmd))) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) return ((id (*)(id, SEL, id))orig)(self, _cmd, a1);
    }
    return nil;
}

static id ZMSwallowObjLong(id self, SEL _cmd, id a1, long a2) {
    if (!ZMModEnabled(ZMModForSel(_cmd))) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) return ((id (*)(id, SEL, id, long))orig)(self, _cmd, a1, a2);
    }
    return nil;
}

static id ZMSwallowLong1(id self, SEL _cmd, long a1) {
    if (!ZMModEnabled(ZMModForSel(_cmd))) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) return ((id (*)(id, SEL, long))orig)(self, _cmd, a1);
    }
    return nil;
}

static id ZMSwallowObj3(id self, SEL _cmd, id a1, id a2, id a3) {
    if (!ZMModEnabled(ZMModForSel(_cmd))) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) return ((id (*)(id, SEL, id, id, id))orig)(self, _cmd, a1, a2, a3);
    }
    return nil;
}

static id ZMSwallowObjBoolLong(id self, SEL _cmd, id a1, BOOL a2, long a3) {
    if (!ZMModEnabled(ZMModForSel(_cmd))) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) return ((id (*)(id, SEL, id, BOOL, long))orig)(self, _cmd, a1, a2, a3);
    }
    return nil;
}

// sendTyping... returns BOOL (encoding B44...). When hidden, report NO
// (typing not sent); when the toggle is OFF, return the real result.
static BOOL ZMSwallowTyping(id self, SEL _cmd, long a1, id a2, long a3, BOOL a4) {
    if (!ZMModEnabled(ZMModForSel(_cmd))) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) return ((BOOL (*)(id, SEL, long, id, long, BOOL))orig)(self, _cmd, a1, a2, a3, a4);
    }
    return NO;
}

// ---------------------------------------------------------------------------
// Confirm dialog (Mods B + C). Presents on the main thread from the topmost
// view controller. Fail-safe: if no view controller can present, the
// confirm block never runs, so orig is NEVER called blindly.
// ---------------------------------------------------------------------------
static UIViewController *ZMTopViewController(void) {
    UIWindow *window = nil;
    @try {
        UIApplication *app = [UIApplication sharedApplication];
        for (UIScene *scene in app.connectedScenes) {
            if (scene.activationState != UISceneActivationStateForegroundActive) continue;
            if (![scene isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                if (w.isKeyWindow) { window = w; break; }
            }
            if (window) break;
        }
        if (!window) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            window = app.keyWindow;
#pragma clang diagnostic pop
        }
    } @catch (...) {
        return nil;
    }
    if (!window) return nil;
    UIViewController *vc = window.rootViewController;
    if (!vc) return nil;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    if ([vc isKindOfClass:[UINavigationController class]]) {
        UIViewController *top = ((UINavigationController *)vc).topViewController;
        if (top) vc = top;
    } else if ([vc isKindOfClass:[UITabBarController class]]) {
        UIViewController *sel = ((UITabBarController *)vc).selectedViewController;
        if (sel) vc = sel;
    }
    return vc;
}

static void ZMPresentConfirm(NSString *title, NSString *message,
                              NSString *confirmTitle, void (^onConfirm)(void)) {
    // Copy the inputs now; the alert is presented async on the main queue.
    NSString *t = [title copy];
    NSString *m = [message copy];
    NSString *c = [confirmTitle copy];
    void (^confirmBlock)(void) = [onConfirm copy];
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIViewController *vc = ZMTopViewController();
            if (!vc) return;  // fail safe: no presenter -> never call orig
            UIAlertController *alert =
                [UIAlertController alertControllerWithTitle:t
                                                    message:m
                                             preferredStyle:UIAlertControllerStyleAlert];
            UIAlertAction *ok = [UIAlertAction actionWithTitle:c
                                                         style:UIAlertActionStyleDefault
                                                       handler:^(__unused UIAlertAction *a) {
                                                           if (confirmBlock) confirmBlock();
                                                       }];
            UIAlertAction *cancel = [UIAlertAction actionWithTitle:@"Hủy"
                                                             style:UIAlertActionStyleCancel
                                                           handler:nil];
            [alert addAction:cancel];
            [alert addAction:ok];
            [vc presentViewController:alert animated:YES completion:nil];
        } @catch (...) {
            // Never let a presentation failure place the call / send the image.
        }
    });
}

static NSString *ZMDisplayName(id value) {
    if ([value isKindOfClass:[NSString class]] && ((NSString *)value).length > 0) {
        return (NSString *)value;
    }
    return nil;
}

// ---------------------------------------------------------------------------
// Mod B — confirm before call (VoipFlowManager only; never hook the call
// buttons as well — that would double-prompt).
// Type encodings (verified off the binary):
//   callWithUserId:withCallType:withSource:            v40@0:8@16q24q32
//   callWithUserId:withCallType:withSource:withParams: v48@0:8@16q24q32@40
//   callWithGroupId:withPartners:withCallType:...      v48@0:8@16@24q32q40
//   callWithPhoneNumber:hasVideo:withSource:           v36@0:8@16B24q28
// ---------------------------------------------------------------------------
static void ZMCallUserId(id self, SEL _cmd, id userId, long callType, long source) {
    if (!ZMModEnabled(ZMModConfirmCall)) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) ((void (*)(id, SEL, id, long, long))orig)(self, _cmd, userId, callType, source);
        return;
    }
    NSString *name = ZMDisplayName(userId);
    NSString *msg = name ? [NSString stringWithFormat:@"Gọi cho %@?", name]
                         : @"Bạn có chắc muốn thực hiện cuộc gọi này?";
    IMP orig = ZMOrigForSel(_cmd);
    id sSelf = self, sUserId = userId;
    ZMPresentConfirm(@"Xác nhận gọi", msg, @"Gọi", ^{
        if (orig) ((void (*)(id, SEL, id, long, long))orig)(sSelf, _cmd, sUserId, callType, source);
    });
}

static void ZMCallUserIdParams(id self, SEL _cmd, id userId, long callType, long source, id params) {
    if (!ZMModEnabled(ZMModConfirmCall)) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) ((void (*)(id, SEL, id, long, long, id))orig)(self, _cmd, userId, callType, source, params);
        return;
    }
    NSString *name = ZMDisplayName(userId);
    NSString *msg = name ? [NSString stringWithFormat:@"Gọi cho %@?", name]
                         : @"Bạn có chắc muốn thực hiện cuộc gọi này?";
    IMP orig = ZMOrigForSel(_cmd);
    id sSelf = self, sUserId = userId, sParams = params;
    ZMPresentConfirm(@"Xác nhận gọi", msg, @"Gọi", ^{
        if (orig) ((void (*)(id, SEL, id, long, long, id))orig)(sSelf, _cmd, sUserId, callType, source, sParams);
    });
}

static void ZMCallGroup(id self, SEL _cmd, id groupId, id partners, long callType, long source) {
    if (!ZMModEnabled(ZMModConfirmCall)) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) ((void (*)(id, SEL, id, id, long, long))orig)(self, _cmd, groupId, partners, callType, source);
        return;
    }
    NSString *name = ZMDisplayName(groupId);
    NSString *msg = name ? [NSString stringWithFormat:@"Gọi nhóm %@?", name]
                         : @"Bạn có chắc muốn thực hiện cuộc gọi nhóm này?";
    IMP orig = ZMOrigForSel(_cmd);
    id sSelf = self, sGroupId = groupId, sPartners = partners;
    ZMPresentConfirm(@"Xác nhận gọi", msg, @"Gọi", ^{
        if (orig) ((void (*)(id, SEL, id, id, long, long))orig)(sSelf, _cmd, sGroupId, sPartners, callType, source);
    });
}

static void ZMCallGroupParams(id self, SEL _cmd, id groupId, id partners, long callType, long source, id params) {
    if (!ZMModEnabled(ZMModConfirmCall)) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) ((void (*)(id, SEL, id, id, long, long, id))orig)(self, _cmd, groupId, partners, callType, source, params);
        return;
    }
    NSString *name = ZMDisplayName(groupId);
    NSString *msg = name ? [NSString stringWithFormat:@"Gọi nhóm %@?", name]
                         : @"Bạn có chắc muốn thực hiện cuộc gọi nhóm này?";
    IMP orig = ZMOrigForSel(_cmd);
    id sSelf = self, sGroupId = groupId, sPartners = partners, sParams = params;
    ZMPresentConfirm(@"Xác nhận gọi", msg, @"Gọi", ^{
        if (orig) ((void (*)(id, SEL, id, id, long, long, id))orig)(sSelf, _cmd, sGroupId, sPartners, callType, source, sParams);
    });
}

static void ZMCallPhone(id self, SEL _cmd, id phoneNumber, BOOL hasVideo, long source) {
    if (!ZMModEnabled(ZMModConfirmCall)) {
        IMP orig = ZMOrigForSel(_cmd);
        if (orig) ((void (*)(id, SEL, id, BOOL, long))orig)(self, _cmd, phoneNumber, hasVideo, source);
        return;
    }
    NSString *name = ZMDisplayName(phoneNumber);
    NSString *msg = name ? [NSString stringWithFormat:@"Gọi tới số %@?", name]
                         : @"Bạn có chắc muốn thực hiện cuộc gọi này?";
    IMP orig = ZMOrigForSel(_cmd);
    id sSelf = self, sPhone = phoneNumber;
    ZMPresentConfirm(@"Xác nhận gọi", msg, @"Gọi", ^{
        if (orig) ((void (*)(id, SEL, id, BOOL, long))orig)(sSelf, _cmd, sPhone, hasVideo, source);
    });
}

// ---------------------------------------------------------------------------
// Mod C — confirm before sending image.
// mediaEditorViewController:willSendMedia:quality:  v40@0:8@16@24q32
// Same selector on 3 classes, so each class keeps its own orig IMP (a
// selector-keyed lookup would collide). One shared body, 3 thin wrappers.
// Only these 3 classes are hooked — NOT the BaseChatTVC fallback, so
// quick-send paths that bypass the editor will NOT prompt (see HANDOFF §5).
// ---------------------------------------------------------------------------
static IMP g_origWillSendMedia_FilePhoto = NULL;
static IMP g_origWillSendMedia_FilePage = NULL;
static IMP g_origWillSendMedia_PhotoSheet = NULL;

static void ZMSendMediaCommon(id self, SEL _cmd, id editor, id media, long quality, IMP orig) {
    if (!ZMModEnabled(ZMModConfirmSend)) {
        if (orig) ((void (*)(id, SEL, id, id, long))orig)(self, _cmd, editor, media, quality);
        return;
    }
    id sSelf = self, sEditor = editor, sMedia = media;
    ZMPresentConfirm(@"Xác nhận gửi", @"Bạn có chắc muốn gửi ảnh/video này?", @"Gửi", ^{
        if (orig) ((void (*)(id, SEL, id, id, long))orig)(sSelf, _cmd, sEditor, sMedia, quality);
    });
}

static void ZMSendMedia_FilePhoto(id self, SEL _cmd, id editor, id media, long quality) {
    ZMSendMediaCommon(self, _cmd, editor, media, quality, g_origWillSendMedia_FilePhoto);
}
static void ZMSendMedia_FilePage(id self, SEL _cmd, id editor, id media, long quality) {
    ZMSendMediaCommon(self, _cmd, editor, media, quality, g_origWillSendMedia_FilePage);
}
static void ZMSendMedia_PhotoSheet(id self, SEL _cmd, id editor, id media, long quality) {
    ZMSendMediaCommon(self, _cmd, editor, media, quality, g_origWillSendMedia_PhotoSheet);
}

// ---------------------------------------------------------------------------
// Settings UI — the "Tool" page (plain UITableViewController, 4 switches).
// Opened from the "Tool" row injected at the top of the Account & Privacy
// screen (see the row-injection hooks below).
// ---------------------------------------------------------------------------
@interface ZMSettingsViewController : UITableViewController
@end

@implementation ZMSettingsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Tool";
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    (void)tableView;
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    (void)tableView; (void)section;
    return 4;
}

- (NSString *)zm_titleForRow:(NSInteger)row {
    switch (row) {
        case 0: return @"Ẩn đã xem / đang gõ / đã nhận";
        case 1: return @"Hỏi trước khi gọi";
        case 2: return @"Hỏi trước khi gửi ảnh";
        case 3: return @"Chống thu hồi";
        default: return @"";
    }
}

- (NSString *)zm_detailForRow:(NSInteger)row {
    switch (row) {
        case 0: return @"Người khác không thấy bạn đã xem, đang gõ hay đã nhận tin nhắn";
        case 1: return @"Hiện xác nhận trước khi thực hiện cuộc gọi";
        case 2: return @"Hiện xác nhận trước khi gửi ảnh/video trong trình sửa";
        case 3: return @"Tin nhắn bị thu hồi vẫn hiển thị như bình thường";
        default: return @"";
    }
}

- (NSString *)zm_keyForRow:(NSInteger)row {
    switch (row) {
        case 0: return kZMKeyHideSeen;
        case 1: return kZMKeyConfirmCall;
        case 2: return kZMKeyConfirmSend;
        case 3: return kZMKeyAntiRecall;
        default: return nil;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *const kReuseId = @"ZaloToolSettingCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:kReuseId];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:kReuseId];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    }
    NSInteger row = indexPath.row;
    cell.textLabel.text = [self zm_titleForRow:row];
    cell.detailTextLabel.text = [self zm_detailForRow:row];
    cell.detailTextLabel.numberOfLines = 0;
    // Fresh switch every time (a reused cell's old switch would otherwise
    // accumulate duplicate targets).
    UISwitch *sw = [[UISwitch alloc] init];
    sw.tag = row;
    sw.on = [[NSUserDefaults standardUserDefaults] boolForKey:[self zm_keyForRow:row]];
    [sw addTarget:self action:@selector(zm_switchChanged:) forControlEvents:UIControlEventValueChanged];
    cell.accessoryView = sw;
    return cell;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    (void)tableView; (void)section;
    return @"Thay đổi có hiệu lực ngay, không cần khởi động lại Zalo. "
           @"Tắt một mục để trở về hành vi gốc của Zalo cho mục đó.";
}

- (void)zm_switchChanged:(UISwitch *)sender {
    NSString *key = [self zm_keyForRow:sender.tag];
    if (!key) return;
    [[NSUserDefaults standardUserDefaults] setBool:sender.on forKey:key];
}

@end

// ---------------------------------------------------------------------------
// "Tool" row injection — top of the Account & Privacy screen.
//
// Target (verified statically on 26.11.02.1, see HANDOFF.md §3):
//   AccountSettingUI40ViewController : BasicSettingUI40TableViewController
//                                    : BasicSettingTableViewController
// The table-view data source methods live ONLY in BasicSettingTableViewController
// (AccountSettingUI40ViewController and BasicSettingUI40TableViewController
// do not override any of them), so hooking the base class hooks the real
// implementation. The replacements activate ONLY when self is an
// AccountSettingUI40ViewController instance, so every other settings screen
// that shares the base class is untouched.
// Injection: section 0, row 0. All other rows in section 0 are shifted by
// one when forwarded to orig. heightForRowAtIndexPath: is deliberately NOT
// hooked — orig answers for the displayed row 0, which is the real first
// row's height and suits our standard settings row.
// ---------------------------------------------------------------------------
static Class g_accountSettingsClass = Nil;

static BOOL ZMIsAccountSettingsVC(id self) {
    if (!self || g_accountSettingsClass == Nil) return NO;
    return [self isKindOfClass:g_accountSettingsClass];
}

static IMP g_origNumRows = NULL;
static IMP g_origCellForRow = NULL;
static IMP g_origDidSelectRow = NULL;
static IMP g_origWillDisplayCell = NULL;

static UITableViewCell *ZMToolRowCell(UITableView *tableView) {
    static NSString *const kReuseId = @"ZaloToolRow";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:kReuseId];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:kReuseId];
    }
    cell.textLabel.text = @"Tool";
    cell.detailTextLabel.text = @"Ẩn đã xem • Hỏi trước khi gọi/gửi • Chống thu hồi";
    cell.detailTextLabel.numberOfLines = 0;
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return cell;
}

static void ZMPushSettingsVC(UIViewController *fromVC) {
    ZMSettingsViewController *vc =
        [[ZMSettingsViewController alloc] initWithStyle:UITableViewStyleGrouped];
    @try {
        if (fromVC.navigationController) {
            [fromVC.navigationController pushViewController:vc animated:YES];
        } else {
            UINavigationController *nav =
                [[UINavigationController alloc] initWithRootViewController:vc];
            [fromVC presentViewController:nav animated:YES completion:nil];
        }
    } @catch (...) {
        // Never crash the settings screen if navigation is unavailable.
    }
}

static NSInteger ZMNumberOfRows(id self, SEL _cmd, UITableView *tv, NSInteger section) {
    typedef NSInteger (*Fn)(id, SEL, id, NSInteger);
    NSInteger count = g_origNumRows ? ((Fn)g_origNumRows)(self, _cmd, tv, section) : 0;
    if (section == 0 && ZMIsAccountSettingsVC(self)) return count + 1;
    return count;
}

static UITableViewCell *ZMCellForRow(id self, SEL _cmd, UITableView *tv, NSIndexPath *ip) {
    typedef UITableViewCell *(*Fn)(id, SEL, id, id);
    if (ZMIsAccountSettingsVC(self) && ip.section == 0 && ip.row == 0) {
        return ZMToolRowCell(tv);
    }
    NSIndexPath *real = ip;
    if (ZMIsAccountSettingsVC(self) && ip.section == 0) {
        real = [NSIndexPath indexPathForRow:ip.row - 1 inSection:0];
    }
    if (!g_origCellForRow) return [[UITableViewCell alloc] init];  // degraded blank row, never a duplicate Tool row
    return ((Fn)g_origCellForRow)(self, _cmd, tv, real);
}

static void ZMDidSelectRow(id self, SEL _cmd, UITableView *tv, NSIndexPath *ip) {
    typedef void (*Fn)(id, SEL, id, id);
    if (ZMIsAccountSettingsVC(self) && ip.section == 0 && ip.row == 0) {
        [tv deselectRowAtIndexPath:ip animated:YES];
        ZMPushSettingsVC((UIViewController *)self);
        return;
    }
    NSIndexPath *real = ip;
    if (ZMIsAccountSettingsVC(self) && ip.section == 0) {
        real = [NSIndexPath indexPathForRow:ip.row - 1 inSection:0];
    }
    if (g_origDidSelectRow) ((Fn)g_origDidSelectRow)(self, _cmd, tv, real);
}

static void ZMWillDisplayCell(id self, SEL _cmd, UITableView *tv, UITableViewCell *cell, NSIndexPath *ip) {
    typedef void (*Fn)(id, SEL, id, id, id);
    // Our row: skip orig highlight/separator logic (it would look up the
    // wrong row object for index 0).
    if (ZMIsAccountSettingsVC(self) && ip.section == 0 && ip.row == 0) return;
    NSIndexPath *real = ip;
    if (ZMIsAccountSettingsVC(self) && ip.section == 0) {
        real = [NSIndexPath indexPathForRow:ip.row - 1 inSection:0];
    }
    if (g_origWillDisplayCell) ((Fn)g_origWillDisplayCell)(self, _cmd, tv, cell, real);
}

static void ZMInstallSettingsHooks(void) {
    if (!g_MSHookMessageEx) return;
    Class base = objc_getClass("BasicSettingTableViewController");
    g_accountSettingsClass = objc_getClass("AccountSettingUI40ViewController");
    if (!base || g_accountSettingsClass == Nil) return;  // no UI, mods stay all-on
    SEL selRows = sel_getUid("tableView:numberOfRowsInSection:");
    SEL selCell = sel_getUid("tableView:cellForRowAtIndexPath:");
    SEL selSelect = sel_getUid("tableView:didSelectRowAtIndexPath:");
    SEL selDisplay = sel_getUid("tableView:willDisplayCell:forRowAtIndexPath:");
    // All three core methods must exist, or the row shift would be
    // inconsistent — install nothing in that case.
    if (!class_getInstanceMethod(base, selRows)) return;
    if (!class_getInstanceMethod(base, selCell)) return;
    if (!class_getInstanceMethod(base, selSelect)) return;
    IMP orig = NULL;
    g_MSHookMessageEx(base, selRows, (IMP)ZMNumberOfRows, &orig);
    if (orig) g_origNumRows = orig;
    orig = NULL;
    g_MSHookMessageEx(base, selCell, (IMP)ZMCellForRow, &orig);
    if (orig) g_origCellForRow = orig;
    orig = NULL;
    g_MSHookMessageEx(base, selSelect, (IMP)ZMDidSelectRow, &orig);
    if (orig) g_origDidSelectRow = orig;
    // willDisplayCell is optional (cosmetic only).
    if (class_getInstanceMethod(base, selDisplay)) {
        orig = NULL;
        g_MSHookMessageEx(base, selDisplay, (IMP)ZMWillDisplayCell, &orig);
        if (orig) g_origWillDisplayCell = orig;
    }
}

// ---------------------------------------------------------------------------
// Install the 28 RE-verified hooks.
// ---------------------------------------------------------------------------
static IMP ZMReplacementForSig(ZMSig sig, const char *cls, const char *sel) {
    switch (sig) {
        case ZMSigSwallowVoid0:      return (IMP)ZMSwallowVoid0;
        case ZMSigSwallowObj1:       return (IMP)ZMSwallowObj1;
        case ZMSigSwallowObjLong:    return (IMP)ZMSwallowObjLong;
        case ZMSigSwallowLong1:      return (IMP)ZMSwallowLong1;
        case ZMSigSwallowObj3:       return (IMP)ZMSwallowObj3;
        case ZMSigSwallowObjBoolLong:return (IMP)ZMSwallowObjBoolLong;
        case ZMSigSwallowTyping:     return (IMP)ZMSwallowTyping;
        case ZMSigCallUserId:        return (IMP)ZMCallUserId;
        case ZMSigCallUserIdParams:  return (IMP)ZMCallUserIdParams;
        case ZMSigCallGroup:         return (IMP)ZMCallGroup;
        case ZMSigCallGroupParams:   return (IMP)ZMCallGroupParams;
        case ZMSigCallPhone:         return (IMP)ZMCallPhone;
        case ZMSigSendMedia:
            // One wrapper per class — the selector is shared, the origs differ.
            if (strcmp(cls, "UXChatFilePhotoActionSheetController") == 0) return (IMP)ZMSendMedia_FilePhoto;
            if (strcmp(cls, "UXChatFilePageController") == 0) return (IMP)ZMSendMedia_FilePage;
            return (IMP)ZMSendMedia_PhotoSheet;
    }
    (void)sel;
    return NULL;
}

static void ZMInstallModHooks(void) {
    if (!g_MSHookMessageEx) return;
    for (size_t i = 0; i < kZMHookSpecCount; i++) {
        const ZMHookSpec *spec = &kZMHookSpecs[i];
        Class cls = objc_getClass(spec->cls);
        if (!cls) continue;  // missing class: skip, never crash
        SEL sel = sel_getUid(spec->sel);
        if (!sel) continue;
        Method m = NULL;
        Class target = cls;
        if (spec->meta) {
            m = class_getClassMethod(cls, sel);
            target = object_getClass((id)cls);  // metaclass
        } else {
            m = class_getInstanceMethod(cls, sel);
        }
        if (!m) continue;  // missing method: skip, never crash
        IMP repl = ZMReplacementForSig(spec->sig, spec->cls, spec->sel);
        if (!repl) continue;
        IMP orig = NULL;
        g_MSHookMessageEx(target, sel, repl, &orig);
        if (!orig) continue;  // store orig only when non-null
        if (spec->sig == ZMSigSendMedia) {
            // Per-class orig (selector is shared across 3 classes).
            if (strcmp(spec->cls, "UXChatFilePhotoActionSheetController") == 0) {
                g_origWillSendMedia_FilePhoto = orig;
            } else if (strcmp(spec->cls, "UXChatFilePageController") == 0) {
                g_origWillSendMedia_FilePage = orig;
            } else {
                g_origWillSendMedia_PhotoSheet = orig;
            }
        } else {
            ZMStoreOrig(sel, orig);
        }
    }
}

// ---------------------------------------------------------------------------
// Init — constructor (NOT +load, NOT __mod_init_func).
// ---------------------------------------------------------------------------
__attribute__((constructor, used))
static void ZaloToolInit(void) {
    @try {
        // FIRST: bundle-ID guard. Only hook inside the real Zalo app; if
        // this dylib is ever loaded into an extension or another process,
        // do nothing at all.
        if (![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"vn.com.vng.zingalo"]) {
            return;
        }
        ZMRegisterDefaults();
        g_origIMPs = [NSMutableDictionary dictionary];
        // Resolve MSHookMessageEx at runtime. The framework binary's
        // LC_ID_DYLIB is /usr/local/lib/libellekit.dylib, so linking
        // against it would record a nonexistent load path; dlopen by
        // @executable_path works because the framework lives in
        // Zalo.app/Frameworks/.
        void *handle = dlopen("@executable_path/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
                              RTLD_NOW);
        if (!handle) return;
        g_MSHookMessageEx = (MSHookMessageExFn)dlsym(handle, "MSHookMessageEx");
        if (!g_MSHookMessageEx) return;
        ZMInstallModHooks();
        ZMInstallSettingsHooks();
    } @catch (...) {
        // A failure this early must never take the app down with it.
    }
}
