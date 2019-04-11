#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define MAX_ARGV_LEN 64

void parse_filename(const char *file_name, char *argv[],int *argc);
void construct_ESP(char *argv[], const int argc, void **esp);
tid_t process_execute (const char *cmd_line);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
