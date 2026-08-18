/* Counts the top-level executable regions of this task.
 *
 * The same walk that `fidelity-probe-apple/src/sys/regions.rs` makes, in C, so
 * a control can measure a region count without linking the library. It does not
 * descend into a submap, for the reason that module records.
 */
#ifndef FIDELITY_PLATFORM_REGIONS_H
#define FIDELITY_PLATFORM_REGIONS_H

#include <mach/mach.h>
#include <mach/mach_vm.h>

static int exec_regions(unsigned long long *bytes) {
    mach_vm_address_t addr = 0;
    int n = 0;
    unsigned long long total = 0;
    for (;;) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = 0;
        kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &size,
            VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
        if (kr != KERN_SUCCESS || size == 0) break;
        if (info.protection & VM_PROT_EXECUTE) { n++; total += size; }
        addr += size;
    }
    if (bytes) *bytes = total;
    return n;
}

#endif
