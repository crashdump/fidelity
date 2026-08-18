/* The CLEAN control for a desktop web view, and the measurement that gave the
 * host its guidance.
 *
 * It splits the web-view cost into three phases, because the three answer
 * different product questions: does creating the view add code, does the first
 * navigation add code, and does a later navigation add code. Measured on
 * macOS 26 and ARM64 on 2026-08-09: four regions, none, and none.
 *
 * The cost therefore lands once, when the host creates the view. A host that
 * creates its view before it calls `start()` reports nothing afterwards.
 *
 *   clang -o phases phases.m -framework Cocoa -framework WebKit
 */
#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#include "regions.h"

static int step(const char *label, int prev) {
    unsigned long long b; int n = exec_regions(&b);
    printf("%-28s : %d regions (%+d), %llu bytes\n", label, n, n - prev, b);
    return n;
}
static void spin(double seconds) {
    NSDate *end = [NSDate dateWithTimeIntervalSinceNow:seconds];
    while ([end timeIntervalSinceNow] > 0)
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
}
static NSString *page(int seed) {
    return [NSString stringWithFormat:
        @"<html><body><script>function w(n){var s=0;for(var i=0;i<n;i++){s+=Math.sqrt(i+%d)|0;}return s;}"
         "var t=0;for(var k=0;k<40;k++){t+=w(400000);}document.title='p%d '+t;</script></body></html>",
        seed, seed];
}

int main(void) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        int n = step("baseline", 0);
        int start = n;
        WKWebView *v = [[WKWebView alloc] initWithFrame:NSMakeRect(0,0,400,300)];
        n = step("WKWebView created, no load", n);
        [v loadHTMLString:page(1) baseURL:nil]; spin(10);
        n = step("first navigation + JS", n);
        for (int i = 2; i <= 4; i++) {
            [v loadHTMLString:page(i) baseURL:nil]; spin(8);
            char label[64]; snprintf(label, sizeof label, "navigation %d + JS", i);
            n = step(label, n);
        }
        printf("\ntotal added since baseline   : %+d regions\n", n - start);
    }
    return 0;
}
