/* Self-authored research contract, not a vendor ABI replacement. */
#ifndef CA01_HMI_IPC_H
#define CA01_HMI_IPC_H
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
enum {
    CA01_QUEUE_ID_HMI = 0x28,
    CA01_QUEUE_CAPACITY = 64,
    CA01_EVENT_ALT = 0x41002
};
typedef enum {
    CA01_OK = 0,
    CA01_ERR_ARG = -1,
    CA01_ERR_RANGE = -2,
    CA01_ERR_ALLOC = -3,
    CA01_ERR_STATE = -4,
    CA01_ERR_NOT_FOUND = -5,
    CA01_ERR_EMPTY = -6,
    CA01_ERR_FULL = -7
} Ca01Result;

/* Guest payload is an opaque ARM32 token, NEVER a host pointer. */
typedef struct {
    uint32_t code, subcommand, event, payload;
} Ca01Message;
_Static_assert(sizeof(Ca01Message)==16, "CA01 envelope must be 16 bytes");
_Static_assert(offsetof(Ca01Message,payload)==12, "CA01 payload is word 3");

typedef struct {
    uint32_t queue_id, head, count, capacity;
    uint32_t type_zero_count, type_41002_count, other_count;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    Ca01Message messages[CA01_QUEUE_CAPACITY];
} Ca01Queue;
typedef enum {
    CA01_DISPATCH_ZERO = 0,
    CA01_DISPATCH_41002 = 1,
    CA01_DISPATCH_OTHER = 2
} Ca01Dispatch;

Ca01Result ca01_queue_init(Ca01Queue *q, uint32_t queue_id);
void ca01_queue_destroy(Ca01Queue *q); /* No concurrent users allowed at destroy. */
Ca01Queue *ca01_queue_new(uint32_t capacity);
void ca01_queue_delete(Ca01Queue *q);
uint32_t ca01_queue_count(Ca01Queue *q);
size_t ca01_message_bytes(void);
uint32_t ca01_queue_capacity(void);
/* Normalized API used by the GUI fixture; shares the same ring as P/T. */
Ca01Result ca01_queue_send(Ca01Queue *q, uint32_t queue_id, Ca01Message m);
Ca01Result ca01_queue_receive(Ca01Queue *q, uint32_t queue_id, Ca01Message *out);
Ca01Result ca01_queue_dispatch(Ca01Queue *q, const Ca01Message *m, Ca01Dispatch *out);
/* Verified normal-path conventions: P -1 success/-2 empty; T 0/-1 timeout.
 * Timeout/error does not modify out. Send failure retains caller ownership.
 * No enqueue/dequeue operation frees or dereferences payloads.
 * Invalid vendor queue/fatal cleanup paths are deliberately not emulated.
 */
int ca01_queue_receive_p(Ca01Queue *q, Ca01Message *out);
int ca01_queue_receive_t(Ca01Queue *q, Ca01Message *out, uint32_t timeout_ms);
int ca01_queue_send_t(Ca01Queue *q, const Ca01Message *m, uint32_t timeout_ms);
#endif
