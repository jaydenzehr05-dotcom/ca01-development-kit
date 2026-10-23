#define _POSIX_C_SOURCE 200809L
#include "ca01_hmi_ipc.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

size_t ca01_message_bytes(void) { return sizeof(Ca01Message); }
uint32_t ca01_queue_capacity(void) { return CA01_QUEUE_CAPACITY; }
Ca01Result ca01_queue_init(Ca01Queue *q, uint32_t id) {
    if (!q || id != CA01_QUEUE_ID_HMI) return CA01_ERR_ARG;
    memset(q,0,sizeof(*q));
    if (pthread_mutex_init(&q->mutex,NULL)) return CA01_ERR_STATE;
    if (pthread_cond_init(&q->changed,NULL)) {
        pthread_mutex_destroy(&q->mutex); return CA01_ERR_STATE;
    }
    q->queue_id=id; q->capacity=CA01_QUEUE_CAPACITY;
    return CA01_OK;
}
void ca01_queue_destroy(Ca01Queue *q) {
    if (!q || q->queue_id!=CA01_QUEUE_ID_HMI) return;
    pthread_cond_destroy(&q->changed); pthread_mutex_destroy(&q->mutex);
    q->queue_id=0;
}
Ca01Queue *ca01_queue_new(uint32_t capacity) {
    if (!capacity || capacity>CA01_QUEUE_CAPACITY) return NULL;
    Ca01Queue *q=calloc(1,sizeof(*q));
    if (!q) return NULL;
    if (ca01_queue_init(q,CA01_QUEUE_ID_HMI)!=CA01_OK) { free(q); return NULL; }
    q->capacity=capacity; return q;
}
void ca01_queue_delete(Ca01Queue *q) { ca01_queue_destroy(q); free(q); }
uint32_t ca01_queue_count(Ca01Queue *q) {
    if (!q || q->queue_id!=CA01_QUEUE_ID_HMI) return 0;
    pthread_mutex_lock(&q->mutex);
    uint32_t count=q->count;
    pthread_mutex_unlock(&q->mutex); return count;
}
static struct timespec deadline(uint32_t ms) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME,&t);
    t.tv_sec+=ms/1000; t.tv_nsec+=(long)(ms%1000)*1000000;
    if(t.tv_nsec>=1000000000) { ++t.tv_sec; t.tv_nsec-=1000000000; }
    return t;
}
/* pthread condition loops tolerate spurious wakes; deadline is not reset. */
int ca01_queue_send_t(Ca01Queue *q, const Ca01Message *m, uint32_t ms) {
    if (!q || !m || q->queue_id!=CA01_QUEUE_ID_HMI) return -1;
    struct timespec until=deadline(ms);
    pthread_mutex_lock(&q->mutex);
    while(q->count==q->capacity) {
        if (!ms || pthread_cond_timedwait(&q->changed,&q->mutex,&until)) {
            pthread_mutex_unlock(&q->mutex); return -1;
        }
    }
    q->messages[(q->head+q->count)%q->capacity]=*m; ++q->count;
    pthread_cond_broadcast(&q->changed); pthread_mutex_unlock(&q->mutex);
    return 0;
}
int ca01_queue_receive_t(Ca01Queue *q, Ca01Message *out, uint32_t ms) {
    if (!q || !out || q->queue_id!=CA01_QUEUE_ID_HMI) return -1;
    struct timespec until=deadline(ms);
    pthread_mutex_lock(&q->mutex);
    while (!q->count) {
        if (!ms || pthread_cond_timedwait(&q->changed,&q->mutex,&until)) {
            pthread_mutex_unlock(&q->mutex); return -1;
        }
    }
    *out=q->messages[q->head]; q->head=(q->head+1)%q->capacity; --q->count;
    pthread_cond_broadcast(&q->changed); pthread_mutex_unlock(&q->mutex);
    return 0;
}
int ca01_queue_receive_p(Ca01Queue *q, Ca01Message *out) {
    return ca01_queue_receive_t(q,out,0)==0 ? -1 : -2;
}
Ca01Result ca01_queue_send(Ca01Queue *q, uint32_t id, Ca01Message m) {
    if(!q || q->queue_id!=CA01_QUEUE_ID_HMI || id!=q->queue_id) return CA01_ERR_ARG;
    return ca01_queue_send_t(q,&m,0)==0 ? CA01_OK : CA01_ERR_FULL;
}
Ca01Result ca01_queue_receive(Ca01Queue *q, uint32_t id, Ca01Message *out) {
    if(!q || !out || q->queue_id!=CA01_QUEUE_ID_HMI || id!=q->queue_id) return CA01_ERR_ARG;
    return ca01_queue_receive_t(q,out,0)==0 ? CA01_OK : CA01_ERR_EMPTY;
}
Ca01Result ca01_queue_dispatch(Ca01Queue *q, const Ca01Message *m, Ca01Dispatch *out) {
    if (!q || !m || !out || q->queue_id!=CA01_QUEUE_ID_HMI) return CA01_ERR_ARG;
    pthread_mutex_lock(&q->mutex);
    if (m->code==0) { ++q->type_zero_count; *out=CA01_DISPATCH_ZERO; }
    else if(m->code==CA01_EVENT_ALT) { ++q->type_41002_count; *out=CA01_DISPATCH_41002; }
    else { ++q->other_count; *out=CA01_DISPATCH_OTHER; }
    pthread_mutex_unlock(&q->mutex); return CA01_OK;
}
