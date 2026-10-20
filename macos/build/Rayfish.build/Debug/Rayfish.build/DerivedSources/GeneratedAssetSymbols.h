#import <Foundation/Foundation.h>

#if __has_attribute(swift_private)
#define AC_SWIFT_PRIVATE __attribute__((swift_private))
#else
#define AC_SWIFT_PRIVATE
#endif

/// The "Logo" asset catalog image resource.
static NSString * const ACImageNameLogo AC_SWIFT_PRIVATE = @"Logo";

/// The "MenuBarIcon" asset catalog image resource.
static NSString * const ACImageNameMenuBarIcon AC_SWIFT_PRIVATE = @"MenuBarIcon";

#undef AC_SWIFT_PRIVATE
