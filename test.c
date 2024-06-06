#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
void handler(int signum) {
	printf("hello world\n");
}
int main(void) {
	signal(SIGUSR1, &handler);
	printf("PID: %u\n\n", getpid());
	// write(STDOUT_FILENO, "\n\n\n\n\n\n", 6);
	// int fd = open("/dev/null", O_WRONLY|O_CREAT);
	// struct stat stat_buf;
	// int s = stat("/dev/null", &stat_buf);
	char text[] = "hel\x6co\0\x04\t\n\x7f\b";
	// write(fd, text, sizeof(text) - 1);
	// char text2[128];
	// for (size_t i = 0; i < sizeof(text2); ++i) {
	// 	text2[i] = (i + '\1') % sizeof(text2);
	// }
	// write(fd, text2, sizeof(text2));
	// printf("PID: %u\n\n", getpid());
	// // sleep(20);
	// read(STDIN_FILENO, text, sizeof(text) - 1);
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
	// timer_settime(timer_id, 0, &its, NULL);
	// read(STDIN_FILENO, text, sizeof(text) - 1);
	// sleep(5);
	return 0;
}
