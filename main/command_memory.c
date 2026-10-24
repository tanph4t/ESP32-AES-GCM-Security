#include "command_memory.h"
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"

#ifndef CONFIG_HEAP_USE_HOOKS
#error "Command memory measurement requires CONFIG_HEAP_USE_HOOKS=y"
#endif

/* Single producer: the MQTT task. Hooks never allocate, log, take locks or
 * inspect another task's allocations. No measured pointer is handed to a
 * different task during this synchronous scope. ISR allocations are excluded.
 * Fixed tracking storage is instrumentation overhead, not measured heap. */
#define TRACKED_BLOCKS 32
static struct { void *ptr; size_t size; } s_blocks[TRACKED_BLOCKS];
static _Atomic(TaskHandle_t) s_owner;
static command_memory_t s_sample;

/* IRAM placement is inherited from esp_heap_caps.h; do not repeat the
 * section attribute (IRAM_ATTR creates a different section on each use). */
void esp_heap_trace_alloc_hook(void *ptr, size_t size, uint32_t caps) {
    (void)caps;
    TaskHandle_t owner = atomic_load_explicit(&s_owner, memory_order_relaxed);
    if (!owner || !ptr || xPortInIsrContext() || xTaskGetCurrentTaskHandle() != owner) return;
    /* ESP-IDF realloc hooks do not identify the previous pointer. The current
     * GCM/control path uses malloc/calloc/free only. In-place realloc is an
     * unsupported trace; reject it instead of counting the same block twice. */
    for (unsigned i = 0; i < TRACKED_BLOCKS; ++i) {
        if (s_blocks[i].ptr == ptr) { s_sample.valid = false; return; }
    }
    for (unsigned i = 0; i < TRACKED_BLOCKS; ++i) {
        if (!s_blocks[i].ptr) {
            s_blocks[i].ptr = ptr;
            s_blocks[i].size = size;
            s_sample.heap_retained += size;
            s_sample.allocations++;
            if (s_sample.heap_retained > s_sample.heap_peak)
                s_sample.heap_peak = s_sample.heap_retained;
            return;
        }
    }
    s_sample.valid = false; /* Never report an underestimated peak as valid. */
}

void esp_heap_trace_free_hook(void *ptr) {
    TaskHandle_t owner = atomic_load_explicit(&s_owner, memory_order_relaxed);
    if (!owner || !ptr || xPortInIsrContext() || xTaskGetCurrentTaskHandle() != owner) return;
    for (unsigned i = 0; i < TRACKED_BLOCKS; ++i) {
        if (s_blocks[i].ptr == ptr) {
            s_sample.heap_retained -= s_blocks[i].size;
            s_blocks[i].ptr = NULL;
            return;
        }
    }
}

void command_memory_begin(bool aes_enabled, uint32_t context_bytes) {
    atomic_store(&s_owner, NULL);
    memset(s_blocks, 0, sizeof(s_blocks));
    s_sample = (command_memory_t){.valid = true, .aes_enabled = aes_enabled,
        .context_bytes = context_bytes,
        .heap_before = heap_caps_get_free_size(MALLOC_CAP_8BIT)};
    atomic_store(&s_owner, xTaskGetCurrentTaskHandle());
}

command_memory_t command_memory_end(void) {
    TaskHandle_t owner = atomic_load(&s_owner);
    if (!owner || owner != xTaskGetCurrentTaskHandle()) return (command_memory_t){0};
    atomic_store(&s_owner, NULL);
    s_sample.heap_after = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    /* ESP-IDF returns bytes. This is task lifetime high-water information,
     * NOT the peak stack usage of this individual command. */
    s_sample.stack_free_min = uxTaskGetStackHighWaterMark(NULL);
    return s_sample;
}
