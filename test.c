#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

void timer_handler(int signum) {
	// printf("hello world\n");
}

void test_write() {
	int dev_null = open("/dev/null", O_WRONLY);
	char text[] = "hel\x6co\0\x04\t\n\x7f\b";
	write(dev_null, text, sizeof(text) - 1);
}

void test_write_escapes() {
	int dev_null = open("/dev/null", O_WRONLY);
	char text[] = "\0 \x1b \x7f \x80";
	write(dev_null, text, sizeof(text) - 1);
}

void test_sleep() {
	sleep(20);
}

void test_read() {
	int dev_null = open("/dev/null", O_WRONLY);

	char text[64];
	ssize_t n = read(STDIN_FILENO, text, sizeof(text) - 1);
	text[n] = '\0';

	dprintf(dev_null, "text: \"%s\"\n", text);
}

void test_timer() {
	signal(SIGUSR1, &timer_handler);
	timer_t timer_id;
	struct sigevent sigevent;
	sigevent.sigev_signo = SIGUSR1;
	sigevent.sigev_notify = SIGEV_SIGNAL;
	sigevent.sigev_value.sival_ptr = &timer_id;

	timer_create(CLOCK_REALTIME, &sigevent, &timer_id);

    struct itimerspec its;
	its.it_value.tv_sec = 2;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 2;
	its.it_interval.tv_nsec = 0;

	timer_settime(timer_id, 0, &its, NULL);

	while (1) {}
}

void test_read_with_timer() {
	signal(SIGUSR1, &timer_handler);
	timer_t timer_id;
	struct sigevent sigevent;
	sigevent.sigev_signo = SIGUSR1;
	sigevent.sigev_notify = SIGEV_SIGNAL;
	sigevent.sigev_value.sival_ptr = &timer_id;

	timer_create(CLOCK_REALTIME, &sigevent, &timer_id);

    struct itimerspec its;
	its.it_value.tv_sec = 2;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 2;
	its.it_interval.tv_nsec = 0;

	timer_settime(timer_id, 0, &its, NULL);

	char text[64];
	ssize_t n = read(STDIN_FILENO, text, sizeof(text) - 1);
	text[n] = '\0';
}

void test_sleep_with_timer() {
	int dev_null = open("/dev/null", O_WRONLY);

	signal(SIGUSR1, &timer_handler);
	timer_t timer_id;
	struct sigevent sigevent;
	sigevent.sigev_signo = SIGUSR1;
	sigevent.sigev_notify = SIGEV_SIGNAL;
	sigevent.sigev_value.sival_ptr = &timer_id;

	timer_create(CLOCK_REALTIME, &sigevent, &timer_id);

    struct itimerspec its;
	its.it_value.tv_sec = 2;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 2;
	its.it_interval.tv_nsec = 0;

	timer_settime(timer_id, 0, &its, NULL);

	time_t t = time(NULL);
	sleep(20);
	time_t e = time(NULL);

	dprintf(dev_null, "slept for %lu seconds\n", e - t);
}

void print_help(char *cmd_name) {
	printf(
		"Usage: %s <test_case>\n"
		"\t1 - test_write\n"
		"\t2 - test_write\n"
		"\t3 - test_sleep\n"
		"\t4 - test_read\n"
		"\t5 - test_timer\n"
		"\t6 - test_read_with_timer\n"
		"\t7 - test_sleep_with_timer\n",
			cmd_name ? cmd_name : "./test"
	);
}

int main(int argc, char **argv) {
	printf("\n\nPID: %u\n\n", getpid());

	long test_num = 0;
	if (argc == 2) {
		test_num = strtol(argv[1], NULL, 0);
	}

	switch (test_num) {
		case 1:
			test_write();
			break;
		case 2:
			test_write_escapes();
			break;
		case 3:
			test_sleep();
			break;
		case 4:
			test_read();
			break;
		case 5:
			test_timer();
			break;
		case 6:
			test_read_with_timer();
			break;
		case 7:
			test_sleep_with_timer();
			break;
		default:
			fprintf(stderr, "Not a valid test case\n");
			print_help(argv[0]);
			return EXIT_FAILURE;
	}

	return 0;
}
