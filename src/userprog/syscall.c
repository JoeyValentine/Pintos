#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "process.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "../threads/thread.h"
#include "../filesys/filesys.h"
#include "../filesys/file.h"
#include "../threads/malloc.h"
#include "exception.h"

static void syscall_handler (struct intr_frame *);
static struct lock file_lock;

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  const uint32_t get_argc[15] =
    {
      0,    //  SYS_HALT
      1,    //  SYS_EXIT
      1,    //  SYS_EXEC
      1,    //  SYS_WAIT
      2,    //  SYS_CREATE
      1,    //  SYS_REMOVE
      1,    //  SYS_OPEN
      1,    //  SYS_FILESIZE
      3,    //  SYS_READ
      3,    //  SYS_WRITE
      2,    //  SYS_SEEK
      1,    //  SYS_TELL
      1,    //  SYS_CLOSE
      1,    //  SYS_FIBO
      4	    //  SYS_4SUM
    };
  void *cur_eps_pos = f->esp;
  void *argv[4] ={0};
  uint32_t sys_num;
  int argc, i;

  sys_num = *(uint32_t *)cur_eps_pos;
  cur_eps_pos += sizeof(uint32_t *);

  argc = get_argc[sys_num];

  for(i=0; i<argc; ++i)
    {
      argv[i] = cur_eps_pos;
      if( !is_valid_ptr( argv[i]) )
	syscall_exit(-1);
      cur_eps_pos += sizeof(uint32_t *);
    }

  switch(sys_num)
  {
    case SYS_HALT:  /* Halt the operating system. */
      syscall_halt();
      break;
    case SYS_EXIT:  /* Terminate this process. */
      syscall_exit(*(int *)argv[0]);
      break;
    case SYS_EXEC:  /* Start another process. */
      f->eax = syscall_exec(*(const char **)argv[0]);
      break;
    case SYS_WAIT:  /* Wait for a child process to die. */
      f->eax = syscall_wait(*(pid_t *)argv[0]);
      break;
    case SYS_CREATE:
      f->eax = syscall_create(*(const char**)argv[0],
			      *(unsigned*)argv[1]);
      break;
    case SYS_REMOVE:
      f->eax = syscall_remove(*(const char**)argv[0]);
      break;
    case SYS_OPEN:
      f->eax = syscall_open(*(const char**)argv[0]);
      break;
    case SYS_FILESIZE:
      f->eax = syscall_filesize(*(int*)argv[0]);
      break;
    case SYS_READ:  /* Read from a file. */
      f->eax = syscall_read( *(int*)argv[0], 
			     *(void **)argv[1], 
			     *(unsigned *)argv[2]);
      break;
    case SYS_WRITE: /* Write to a file. */
      f->eax = syscall_write( *(int *)argv[0], 
			      *(void **)argv[1], 
			      *(unsigned *)argv[2] );
      break;
    case SYS_SEEK:
      syscall_seek(*(int*)argv[0], *(unsigned*)argv[1]);
      break;
    case SYS_TELL:
      f->eax = syscall_tell(*(int*)argv[0]);
      break;
    case SYS_CLOSE:
      syscall_close(*(int*)argv[0]);
      break;
    case SYS_FIBO:
      f->eax = syscall_fibonacci(*(int*)argv[0]);
      break;
    case SYS_4SUM:
      f->eax = syscall_sum_of_four_integers(
	*(int *)argv[0], *(int *)argv[1], 
	*(int *)argv[2], *(int *)argv[3]);
      break;
    default:
      syscall_exit(-1);
  }
}


struct file*
get_file(int fd)
{
  bool find_flag = false;
  struct thread *t = thread_current();
  struct list_elem *e;
  struct fd_elem *cur_elem;

  for(e = list_begin(&t->fd_list); 
      e != list_end(&t->fd_list);
      e = list_next(e))
    {
      cur_elem = list_entry(e, struct fd_elem, fd_elem);
      if( cur_elem->fd == fd )
	{
	  find_flag = true;
	  break;
	}
    }

  if( !find_flag )
    return NULL;

  return cur_elem->file;
}

void 
syscall_halt(void)
{
  shutdown_power_off();
  NOT_REACHED();
}

void 
syscall_exit(int status)
{
  struct thread *t = thread_current();
  struct list_elem *e;
  char *process_name, *save_ptr;

  process_name = strtok_r(t->name, " ", &save_ptr);
  printf("%s: exit(%d)\n", process_name, status);

  for(e = list_begin(&t->fd_list); 
      e != list_end(&t->fd_list); 
      )
    {
      struct fd_elem *cur_fd_elem = list_entry(e, struct fd_elem, fd_elem);
      struct list_elem *next = list_next(e);
      list_remove(&cur_fd_elem->fd_elem);
//      lock_acquire(&file_lock);
      file_close(cur_fd_elem->file);
//      lock_release(&file_lock);
      free(cur_fd_elem);
      e = next;
    }

  //lock_acquire(&file_lock);
  file_close(t->cur_exe_file); 
 // lock_release(&file_lock);

  for(e = list_begin(&t->parent->child_list); 
      e != list_end(&t->parent->child_list); 
      e = list_next(e))
    {
      struct thread *child = list_entry(e, struct thread, child_elem);
      if( child->tid == t->tid )
	{
	  list_remove(&child->child_elem);
	  break;
	}
    }

  t->parent->child_exit_status = status;
  sema_up(&(t->parent->sema_wait));
  thread_exit();
}

pid_t 
syscall_exec(const char *cmd_line)
{
  if( !is_valid_ptr(cmd_line) )
    syscall_exit(-1);
  return process_execute(cmd_line);
}


int 
syscall_wait(pid_t pid)
{
  return process_wait(pid);
}

bool
syscall_create(const char *file, unsigned initial_size)
{
  bool ret;
  if( !is_valid_ptr(file) )
    syscall_exit(-1);
  lock_acquire(&file_lock);
  ret = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return ret;
}

bool
syscall_remove(const char *file)
{
  bool ret;
  if( !is_valid_ptr(file) )
    syscall_exit(-1);
  lock_acquire(&file_lock);
  ret = filesys_remove(file);
  lock_release(&file_lock);
  return ret;
}

int
syscall_open(const char *file)
{
  if( !is_valid_ptr(file) )
    syscall_exit(-1);
  lock_acquire(&file_lock);
  struct file *new_file = filesys_open(file);
  lock_release(&file_lock);

  if( new_file == NULL )
    return -1;

  struct thread *t = thread_current();

  if( t->cur_avail_fd > MAX_FILE_NUM )
    return -1;

  struct fd_elem *new_fd_elem = 
   (struct fd_elem *)calloc(1, sizeof(struct fd_elem));

  if( !new_fd_elem )
    return -1;

  new_fd_elem->file = new_file;
  new_fd_elem->fd = t->cur_avail_fd++;
  
  list_push_back(&t->fd_list, &new_fd_elem->fd_elem);

  return new_fd_elem->fd;
}

int
syscall_filesize(int fd)
{
  int ret;
  struct file *file = get_file(fd);
  if( file == NULL )
    return -1;
  lock_acquire(&file_lock);
  ret = file_length(file);
  lock_release(&file_lock);
  return ret;
}

int 
syscall_read(int fd, void *buffer, unsigned size)
{
  int ret = -1;

  if( !is_valid_ptr(buffer) )
    syscall_exit(-1);

  if( fd == STDIN )
    {
      uint8_t input, i;
      for(i=0; i<size; ++i)
	{
	  input = input_getc();
	  memset((uint8_t*)buffer + i, input, sizeof(uint8_t));
	  if( input != '\0' )
	    break;
	}
      ret = i;
    }
  else
    {
      struct file *file = get_file(fd);
      if( file == NULL ) 
	return -1;
      lock_acquire(&file_lock);
      ret = file_read(file, buffer, size);
      lock_release(&file_lock);
    }

  return ret;

}

int
syscall_write(int fd, const void *buffer, unsigned size)
{
  int ret = -1;

  if( !is_valid_ptr(buffer) )
    syscall_exit(-1);

  if( fd == STDOUT )
    {
      unsigned i;
      for(i=0; i<size && *((char*)buffer + i); ++i);
      putbuf(buffer, i);
      ret = i;
    }
  else
    {
      struct file *file = get_file(fd);
      if( file == NULL )
	return -1;
      lock_acquire(&file_lock);
      ret = file_write(file, buffer, size);
      lock_release(&file_lock);
    }

  return ret;
}

void
syscall_seek(int fd, unsigned position)
{
  struct file *file = get_file(fd);
  if( file == NULL )
    return;
  lock_acquire(&file_lock);
  file_seek(file, position);
  lock_release(&file_lock);
}

unsigned
syscall_tell(int fd)
{
  unsigned ret;
  struct file *file = get_file(fd);
  if( file == NULL )
    return -1;
  lock_acquire(&file_lock);
  ret = file_tell(file);
  lock_release(&file_lock);
  return ret;
}

// i need to change it
void
syscall_close(int fd)
{
  bool find_flag = false;
  struct list_elem *e;
  struct fd_elem *cur_elem;
  struct thread *t = thread_current();

  for(e = list_begin(&t->fd_list); 
      e != list_end(&t->fd_list);
      e = list_next(e))
    {
      cur_elem = list_entry(e, struct fd_elem, fd_elem);
      if( cur_elem->fd == fd )
	{
	  find_flag = true;
	  break;
	}
    }

  if( !find_flag )
    return;

  e = list_rbegin(&t->fd_list);

  if( e != &(cur_elem->fd_elem) && e != list_rend(&t->fd_list) )
    {
      list_insert(&cur_elem->fd_elem, e);
      cur_elem->fd = fd;
    }

  list_remove(&cur_elem->fd_elem);
  free(cur_elem);
  --(t->cur_avail_fd);
}

int 
syscall_fibonacci(int n)
{
  int fibo = 0, fibo_1 = 1, fibo_2 = 1, i = 0;

  if( n == 1 ) return 1;
  else if( n == 2 ) return 1;

  for(i=0; i<n-2; ++i)
    {
      fibo = fibo_1 + fibo_2;
      fibo_2 = fibo_1;
      fibo_1 = fibo;
    }

  return fibo;
}

int 
syscall_sum_of_four_integers(int a, int b, int c, int d)
{
  return a + b + c + d;
}

