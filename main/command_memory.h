#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Protocol 1: synchronous payload processing in the MQTT task, after HEX
 * decode and before hardware queue/ACK. Counts requested heap bytes, not
 * allocator headers, stack, static RAM or allocations from other tasks. */
typedef struct {
    uint32_t heap_before, heap_after;
    uint32_t heap_peak, heap_retained, allocations;
    uint32_t stack_free_min, context_bytes;
    bool valid, aes_enabled;
} command_memory_t;

void command_memory_begin(bool aes_enabled, uint32_t context_bytes);
command_memory_t command_memory_end(void);
