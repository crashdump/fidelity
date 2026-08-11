/* The measurement that chose the Apple worker's quality of service.
 *
 * Two threads wake every 5 s while every core is busy, one at utility and one
 * at background. The drift is what a detector would pay, because a scan the
 * scheduler defers extends the time a host stays exposed.
 *
 * Measured on macOS 26 and ARM64 on 2026-08-09: utility drifts 0.007 s mean and
 * 0.014 s worst, background drifts 0.973 s mean and 2.102 s worst. That is why
 * `sys/qos.rs` takes utility, and it records the same table.
 *
 *   clang -O2 -o qos-drift qos-drift.c && ./qos-drift
 */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/qos.h>

static double now(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
                         return t.tv_sec + t.tv_nsec/1e9; }
static void *cycle(void *arg){
    qos_class_t c = (qos_class_t)(long)arg;
    pthread_set_qos_class_self_np(c, 0);
    double worst = 0, total = 0;
    for (int i=0;i<5;i++){ double a=now(); sleep(5); double d=now()-a-5.0;
                           total+=d; if(d>worst) worst=d; }
    printf("  class 0x%02x : mean drift %.3f s, worst %.3f s\n", c, total/5, worst);
    return 0;
}
static void *burn(void *u){ (void)u; volatile double x=0;
    double end=now()+27; while(now()<end){ for(int i=0;i<2000000;i++) x+=i*0.5; } return 0; }

int main(void){
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    printf("loading %ld cores for 27 s, then two workers wake every 5 s\n", cores);
    pthread_t l[32]; for(long i=0;i<cores && i<32;i++) pthread_create(&l[i],0,burn,0);
    pthread_t a,b;
    pthread_create(&a,0,cycle,(void*)(long)QOS_CLASS_UTILITY);
    pthread_create(&b,0,cycle,(void*)(long)QOS_CLASS_BACKGROUND);
    pthread_join(a,0); pthread_join(b,0);
    return 0;
}
