/* Copied, Pasted and summarized from ps' source code.
   You can use sysctl to get other process' argv.
   Thanks: https://gist.github.com/nonowarn/770696
 */

#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proc_argv.h"

#define pid_of(pproc) pproc->kp_proc.p_pid

// Example
// int
// main(int argc, char** argv) {
//   if (argc != 2) {
//     fprintf(stderr, "Usage: %s pid\n", argv[0]);
//     exit(1);
//   }
//   print_argv_of_pid(atoi(argv[1]));
//   return 0;
// }
 
void print_argv_of_pid(int pid) {
  int    mib[3], argmax, nargs, c = 0;
  size_t    size;
  char    *procargs, *sp, *np, *cp;
  int show_args = 1;
 
  fprintf(stderr, "Getting argv of PID %d\n", pid);
 
  mib[0] = CTL_KERN;
  mib[1] = KERN_ARGMAX;
 
  size = sizeof(argmax);
  if (sysctl(mib, 2, &argmax, &size, NULL, 0) == -1) {
    goto ERROR_A;
  }
 
  /* Allocate space for the arguments. */
  procargs = (char *)malloc(argmax);
  if (procargs == NULL) {
    goto ERROR_A;
  }
 
 
  /*
   * Make a sysctl() call to get the raw argument space of the process.
   * The layout is documented in start.s, which is part of the Csu
   * project.  In summary, it looks like:
   *
   * /---------------\ 0x00000000
   * :               :
   * :               :
   * |---------------|
   * | argc          |
   * |---------------|
   * | arg[0]        |
   * |---------------|
   * :               :
   * :               :
   * |---------------|
   * | arg[argc - 1] |
   * |---------------|
   * | 0             |
   * |---------------|
   * | env[0]        |
   * |---------------|
   * :               :
   * :               :
   * |---------------|
   * | env[n]        |
   * |---------------|
   * | 0             |
   * |---------------| <-- Beginning of data returned by sysctl() is here.
   * | argc          |
   * |---------------|
   * | exec_path     |
   * |:::::::::::::::|
   * |               |
   * | String area.  |
   * |               |
   * |---------------| <-- Top of stack.
   * :               :
   * :               :
   * \---------------/ 0xffffffff
   */
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROCARGS2;
  mib[2] = pid;
 
 
  size = (size_t)argmax;
  if (sysctl(mib, 3, procargs, &size, NULL, 0) == -1) {
    goto ERROR_B;
  }
 
  memcpy(&nargs, procargs, sizeof(nargs));
  cp = procargs + sizeof(nargs);
 
  /* Skip the saved exec_path. */
  for (; cp < &procargs[size]; cp++) {
    if (*cp == '\0') {
      /* End of exec_path reached. */
      break;
    }
  }
  if (cp == &procargs[size]) {
    goto ERROR_B;
  }
 
  /* Skip trailing '\0' characters. */
  for (; cp < &procargs[size]; cp++) {
    if (*cp != '\0') {
      /* Beginning of first argument reached. */
      break;
    }
  }
  if (cp == &procargs[size]) {
    goto ERROR_B;
  }
  /* Save where the argv[0] string starts. */
  sp = cp;
 
  /*
   * Iterate through the '\0'-terminated strings and convert '\0' to ' '
   * until a string is found that has a '=' character in it (or there are
   * no more strings in procargs).  There is no way to deterministically
   * know where the command arguments end and the environment strings
   * start, which is why the '=' character is searched for as a heuristic.
   */
  for (np = NULL; c < nargs && cp < &procargs[size]; cp++) {
    if (*cp == '\0') {
      c++;
      if (np != NULL) {
          /* Convert previous '\0'. */
          *np = ' ';
      } else {
          /* *argv0len = cp - sp; */
      }
      /* Note location of current '\0'. */
      np = cp;
 
      if (!show_args) {
          /*
           * Don't convert '\0' characters to ' '.
           * However, we needed to know that the
           * command name was terminated, which we
           * now know.
           */
          break;
      }
    }
  }
 
  /*
   * sp points to the beginning of the arguments/environment string, and
   * np should point to the '\0' terminator for the string.
   */
  if (np == NULL || np == sp) {
    /* Empty or unterminated string. */
    goto ERROR_B;
  }
 
  /* Make a copy of the string. */
  printf("%s\n", sp);
 
  /* Clean up. */
  free(procargs);
  return;
 
  ERROR_B:
  free(procargs);
  ERROR_A:
  fprintf(stderr, "Sorry, failed\n");
  exit(2);
}
