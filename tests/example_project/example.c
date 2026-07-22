/*
 * Example C program for DecBench testing.
 * Based on code from the SAILR evaluation.
 *
 * This program has multiple functions with various control flow structures
 * to test CFG extraction and GED computation.
 */

#include <stdio.h>

int EXTRA_RUN = 3;
int EARLY_EXIT = 4;

int next_job(void) {
    puts("next_job");
    return 1;
}

int refresh_jobs(void) {
    puts("refresh_jobs");
    return 2;
}

int fast_unlock(void) {
    puts("fast_unlock");
    return 4;
}

int complete_job(void) {
    puts("checking...");
    return 0;
}

void log_workers(void) {
    puts("log_workers");
}

int job_status(int stats) {
    puts("job_status");
    return stats;
}

/* Main test function with complex control flow */
int schedule_job(int needs_next, int fast_job, int mode)
{
    if (needs_next && fast_job) {
        complete_job();
        if (mode == EARLY_EXIT)
            goto cleanup;

        next_job();
    }

    refresh_jobs();
    if (fast_job)
        fast_unlock();

cleanup:
    complete_job();
    log_workers();
    return job_status(fast_job);
}

/* Simple loop function */
int count_to_n(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += i;
    }
    return sum;
}

/* Nested conditionals */
int classify_number(int x) {
    if (x < 0) {
        return -1;
    } else if (x == 0) {
        return 0;
    } else if (x < 10) {
        return 1;
    } else if (x < 100) {
        return 2;
    } else {
        return 3;
    }
}

int main(int argc, char** argv)
{
    if (argc < 4)
        return 1;
    return schedule_job(argv[1][0], argv[2][0], argv[3][0]);
}
