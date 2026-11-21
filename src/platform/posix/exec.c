/* src/platform/posix/exec.c - capture a child process (POSIX). */
#define _POSIX_C_SOURCE 200809L

#include "sliver/proc.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sliver/proto.h"

static void drain(int fd, sliver_buf_t *out) {
  char buf[4096];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    (void)sliver_buf_append(out, buf, (size_t)n);
  }
}

int sliver_proc_exec(const char *path, const char *const *args, size_t argc, int capture,
                     sliver_buf_t *out, sliver_buf_t *err, uint32_t *pid_out,
                     uint32_t *status_out) {
  int out_pipe[2] = {-1, -1};
  int err_pipe[2] = {-1, -1};
  pid_t pid;
  int status = 0;

  if (path == NULL) {
    return -1;
  }
  if (capture && (pipe(out_pipe) != 0 || pipe(err_pipe) != 0)) {
    return -1;
  }
  pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    char *argv_local[64];
    size_t i;
    if (argc + 2 > sizeof(argv_local) / sizeof(argv_local[0])) {
      _exit(127);
    }
    argv_local[0] = (char *)path;
    for (i = 0; i < argc; ++i) {
      argv_local[i + 1] = (char *)(args[i] != NULL ? args[i] : "");
    }
    argv_local[argc + 1] = NULL;
    if (capture) {
      (void)dup2(out_pipe[1], STDOUT_FILENO);
      (void)dup2(err_pipe[1], STDERR_FILENO);
      (void)close(out_pipe[0]);
      (void)close(out_pipe[1]);
      (void)close(err_pipe[0]);
      (void)close(err_pipe[1]);
    }
    execvp(path, argv_local);
    _exit(127);
  }
  if (capture) {
    (void)close(out_pipe[1]);
    (void)close(err_pipe[1]);
    drain(out_pipe[0], out);
    drain(err_pipe[0], err);
    (void)close(out_pipe[0]);
    (void)close(err_pipe[0]);
  }
  (void)waitpid(pid, &status, 0);
  if (pid_out != NULL) {
    *pid_out = (uint32_t)pid;
  }
  if (status_out != NULL) {
    *status_out = WIFEXITED(status) ? (uint32_t)WEXITSTATUS(status) : 1u;
  }
  return 0;
}

/* --- interactive child ------------------------------------------------- */
struct sliver_child {
  int stdin_w;
  int stdout_r;
  pid_t pid;
};

int sliver_child_spawn(const char *path, const char *const *args, size_t argc,
                       sliver_child_t **out, uint32_t *pid_out) {
  int in_pipe[2] = {-1, -1};
  int out_pipe[2] = {-1, -1};
  pid_t pid;
  sliver_child_t *child;

  if (path == NULL || out == NULL) {
    return -1;
  }
  if (pipe(in_pipe) != 0) {
    return -1;
  }
  if (pipe(out_pipe) != 0) {
    (void)close(in_pipe[0]);
    (void)close(in_pipe[1]);
    return -1;
  }
  pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    char *argv_local[64];
    size_t i;
    if (argc + 2 > sizeof(argv_local) / sizeof(argv_local[0])) {
      _exit(127);
    }
    argv_local[0] = (char *)path;
    for (i = 0; i < argc; ++i) {
      argv_local[i + 1] = (char *)(args[i] != NULL ? args[i] : "");
    }
    argv_local[argc + 1] = NULL;
    (void)dup2(in_pipe[0], STDIN_FILENO);
    (void)dup2(out_pipe[1], STDOUT_FILENO);
    (void)dup2(out_pipe[1], STDERR_FILENO);
    (void)close(in_pipe[0]);
    (void)close(in_pipe[1]);
    (void)close(out_pipe[0]);
    (void)close(out_pipe[1]);
    execvp(path, argv_local);
    _exit(127);
  }
  (void)close(in_pipe[0]);
  (void)close(out_pipe[1]);
  child = (sliver_child_t *)calloc(1, sizeof(*child));
  if (child == NULL) {
    (void)kill(pid, SIGKILL);
    return -1;
  }
  child->stdin_w = in_pipe[1];
  child->stdout_r = out_pipe[0];
  child->pid = pid;
  *out = child;
  if (pid_out != NULL) {
    *pid_out = (uint32_t)pid;
  }
  return 0;
}

long sliver_child_write(sliver_child_t *c, const void *buf, size_t len) {
  ssize_t n;
  if (c == NULL || c->stdin_w < 0) {
    return -1;
  }
  n = write(c->stdin_w, buf, len);
  return n < 0 ? -1 : (long)n;
}

long sliver_child_read(sliver_child_t *c, void *buf, size_t len) {
  ssize_t n;
  if (c == NULL || c->stdout_r < 0) {
    return -1;
  }
  n = read(c->stdout_r, buf, len);
  return n < 0 ? -1 : (long)n;
}

void sliver_child_close_stdin(sliver_child_t *c) {
  if (c != NULL && c->stdin_w >= 0) {
    (void)close(c->stdin_w);
    c->stdin_w = -1;
  }
}

int sliver_child_wait(sliver_child_t *c, uint32_t *status_out) {
  int status = 0;
  if (c == NULL) {
    return -1;
  }
  (void)waitpid(c->pid, &status, 0);
  if (status_out != NULL) {
    *status_out = WIFEXITED(status) ? (uint32_t)WEXITSTATUS(status) : 1u;
  }
  return 0;
}

void sliver_child_terminate(sliver_child_t *c) {
  if (c != NULL && c->pid > 0) {
    (void)kill(c->pid, SIGKILL);
  }
}

void sliver_child_free(sliver_child_t *c) {
  if (c == NULL) {
    return;
  }
  sliver_child_close_stdin(c);
  if (c->stdout_r >= 0) {
    (void)close(c->stdout_r);
  }
  free(c);
}
