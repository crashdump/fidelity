// The iOS image-identity control.
//
// It reads the entitlements of the running image with no Security framework,
// which is the mechanism that iOS needs: checked against the iOS 26 SDK on
// 2026-08-10, that SDK declares neither SecCode nor SecTask, so the macOS
// route does not exist. The probe does the same walk in Rust, in
// `sys/image.rs`, and this control checks the walk without the library.
//
// The entitlements come from a plist that the signature carries. Write one
// that a local build may run:
//
//     printf '%s' '<plist version="1.0"><dict>
//     <key>com.apple.security.get-task-allow</key><true/>
//     </dict></plist>' > benign.plist
//
// Build and run, on macOS:
//
//     clang -o entitle entitle.c
//     codesign --force --sign - --entitlements benign.plist entitle && ./entitle
//
// On the iOS simulator, add the SDK and spawn it:
//
//     SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
//     clang -arch arm64 -isysroot "$SDK" -mios-simulator-version-min=18.0 \
//         -o entitle-sim entitle.c
//     codesign --force --sign - --entitlements benign.plist entitle-sim
//     xcrun simctl spawn "$FIDELITY_IOS_SIM" "$PWD/entitle-sim"
//
// Measured on 2026-08-10, on macOS 26 and on the iOS 26 simulator: the walk
// finds the signature and prints the plist on both, with the same layout.
//
// A team entitlement needs a provisioned build. An ad-hoc signature that
// carries `application-identifier` or `com.apple.developer.team-identifier`
// is refused at launch with SIGKILL, on both systems. That is why every iOS
// control runs against an image that names no team.
//
// The two recorded signatures that `fidelity-formats` tests against came from
// this control. Sign a small binary with and without the team entitlement,
// then cut the SuperBlob out at the length that its own header declares:
// `otool -l` gives the dataoff, and bytes 4 to 8 of the blob give the length.
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0u
#define CSMAGIC_EMBEDDED_ENTITLEMENTS 0xfade7171u
#define CSSLOT_ENTITLEMENTS 5u

static uint32_t be32(uint32_t v) { return __builtin_bswap32(v); }

int main(void) {
    const struct mach_header_64 *header = NULL;
    intptr_t slide = 0;

    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header_64 *h =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (h && h->filetype == MH_EXECUTE) {
            header = h;
            slide = _dyld_get_image_vmaddr_slide(i);
            printf("main image  : index %u, slide 0x%lx\n", i, (unsigned long)slide);
            break;
        }
    }
    if (!header) { printf("no main image\n"); return 1; }

    // Walk the load commands for __LINKEDIT and LC_CODE_SIGNATURE.
    uint64_t linkedit_vmaddr = 0, linkedit_fileoff = 0;
    uint32_t sig_off = 0, sig_size = 0;
    const uint8_t *p = (const uint8_t *)header + sizeof(*header);

    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const void *)lc;
            if (strcmp(seg->segname, SEG_LINKEDIT) == 0) {
                linkedit_vmaddr = seg->vmaddr;
                linkedit_fileoff = seg->fileoff;
            }
        } else if (lc->cmd == LC_CODE_SIGNATURE) {
            const struct linkedit_data_command *cs = (const void *)lc;
            sig_off = cs->dataoff;
            sig_size = cs->datasize;
        }
        p += lc->cmdsize;
    }
    printf("__LINKEDIT  : vmaddr 0x%llx fileoff 0x%llx\n", linkedit_vmaddr, linkedit_fileoff);
    printf("signature   : dataoff 0x%x size %u\n", sig_off, sig_size);
    if (!sig_off || !linkedit_vmaddr) { printf("no signature in this image\n"); return 1; }

    // A file offset becomes an address through the __LINKEDIT mapping.
    const uint8_t *blob =
        (const uint8_t *)(linkedit_vmaddr + (uint64_t)slide - linkedit_fileoff + sig_off);

    uint32_t magic = be32(*(const uint32_t *)blob);
    uint32_t count = be32(*(const uint32_t *)(blob + 8));
    printf("superblob   : magic 0x%08x, %u slots\n", magic, count);
    if (magic != CSMAGIC_EMBEDDED_SIGNATURE) { printf("not a superblob\n"); return 1; }

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *entry = blob + 12 + (i * 8);
        uint32_t type = be32(*(const uint32_t *)entry);
        uint32_t offset = be32(*(const uint32_t *)(entry + 4));
        printf("  slot %u    : type %u offset 0x%x\n", i, type, offset);
        if (type != CSSLOT_ENTITLEMENTS) continue;

        const uint8_t *ent = blob + offset;
        uint32_t ent_magic = be32(*(const uint32_t *)ent);
        uint32_t ent_len = be32(*(const uint32_t *)(ent + 4));
        printf("entitlements: magic 0x%08x, %u bytes\n", ent_magic, ent_len);
        if (ent_magic != CSMAGIC_EMBEDDED_ENTITLEMENTS) continue;
        printf("---- plist ----\n%.*s\n---------------\n", (int)(ent_len - 8), ent + 8);
    }
    return 0;
}
