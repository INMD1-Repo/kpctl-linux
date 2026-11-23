// SPDX-License-Identifier: MIT
// Narrow CVE-2026-46315 regression: reused WAITID requests must return zero
// result fields for WNOHANG when our own child has not exited.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/io_uring.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct ring {
 int fd;
 unsigned *sq_tail, *sq_mask, *sq_array, *cq_head, *cq_tail, *cq_mask;
 struct io_uring_sqe *sqes;
 struct io_uring_cqe *cqes;
};

static void die(const char *msg) { perror(msg); exit(2); }
static void setup(struct ring *r) {
 struct io_uring_params p = {0};
 r->fd = syscall(__NR_io_uring_setup, 8, &p);
 if (r->fd < 0) die("io_uring_setup");
 size_t sqsz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
 size_t cqsz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
 if (p.features & IORING_FEAT_SINGLE_MMAP) sqsz = sqsz > cqsz ? sqsz : cqsz;
 char *sq = mmap(NULL, sqsz, PROT_READ|PROT_WRITE, MAP_SHARED, r->fd, IORING_OFF_SQ_RING);
 if (sq == MAP_FAILED) die("sq mmap");
 char *cq = (p.features & IORING_FEAT_SINGLE_MMAP) ? sq : mmap(NULL, cqsz, PROT_READ|PROT_WRITE, MAP_SHARED, r->fd, IORING_OFF_CQ_RING);
 if (cq == MAP_FAILED) die("cq mmap");
 r->sqes = mmap(NULL, p.sq_entries * sizeof(*r->sqes), PROT_READ|PROT_WRITE, MAP_SHARED, r->fd, IORING_OFF_SQES);
 if (r->sqes == MAP_FAILED) die("sqes mmap");
 r->sq_tail=(void *)(sq+p.sq_off.tail); r->sq_mask=(void *)(sq+p.sq_off.ring_mask); r->sq_array=(void *)(sq+p.sq_off.array);
 r->cq_head=(void *)(cq+p.cq_off.head); r->cq_tail=(void *)(cq+p.cq_off.tail); r->cq_mask=(void *)(cq+p.cq_off.ring_mask); r->cqes=(void *)(cq+p.cq_off.cqes);
}

static int submit_wait(struct ring *r, pid_t pid, int options, siginfo_t *si) {
 unsigned tail=__atomic_load_n(r->sq_tail,__ATOMIC_RELAXED), slot=tail & *r->sq_mask;
 struct io_uring_sqe *q=&r->sqes[slot]; memset(q,0,sizeof(*q));
 q->opcode=IORING_OP_WAITID; q->fd=pid; q->len=P_PID;
 q->file_index=options; q->addr2=(uintptr_t)si; q->user_data=tail+1;
 r->sq_array[slot]=slot; __atomic_store_n(r->sq_tail,tail+1,__ATOMIC_RELEASE);
 int n=syscall(__NR_io_uring_enter,r->fd,1,1,IORING_ENTER_GETEVENTS,NULL,0);
 if(n<0)die("io_uring_enter");
 unsigned head=__atomic_load_n(r->cq_head,__ATOMIC_RELAXED);
 if(head==__atomic_load_n(r->cq_tail,__ATOMIC_ACQUIRE)) { errno=EIO;die("empty completion"); }
 int res=r->cqes[head & *r->cq_mask].res;
 __atomic_store_n(r->cq_head,head+1,__ATOMIC_RELEASE); return res;
}

int main(int argc,char **argv) {
 int rounds=argc>1?atoi(argv[1]):128, stale=0;
 if(rounds<1 || rounds>10000)return 2;
 alarm(60);
 struct ring r;setup(&r);
 pid_t parent=getpid(), held=fork(); if(held<0)die("fork");
 if(!held) { prctl(PR_SET_PDEATHSIG,SIGKILL);if(getppid()!=parent)_exit(1);for(;;)pause(); }
 for(int i=0;i<rounds;i++) {
  pid_t exited=fork();if(exited<0)die("fork");if(!exited)_exit(37);
  siginfo_t si;memset(&si,0xa5,sizeof(si));
  int res=submit_wait(&r,exited,WEXITED,&si);
  if(res || si.si_pid!=exited || si.si_status!=37 || si.si_code!=CLD_EXITED) {
   fprintf(stderr,"normal waitid regression: result=%d\n",res);kill(held,SIGKILL);waitpid(held,NULL,0);return 2;
  }
  memset(&si,0xa5,sizeof(si));res=submit_wait(&r,held,WEXITED|WNOHANG,&si);
  if(res) { fprintf(stderr,"WNOHANG completion=%d\n",res);kill(held,SIGKILL);waitpid(held,NULL,0);return 2; }
  if(si.si_pid || si.si_code || si.si_status || si.si_uid || si.si_signo || si.si_errno)stale++;
 }
 kill(held,SIGKILL);waitpid(held,NULL,0);close(r.fd);
 printf("{\"test\":\"CVE-2026-46315\",\"rounds\":%d,\"stale_noevent_results\":%d,\"normal_child_results\":%d}\n",rounds,stale,rounds);
 return stale?1:0;
}
