#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Protocol 2: synchronous payload processing in the MQTT task, after HEX
 * decode and before hardware queue/ACK. Heap counters are requested bytes in
 * this task. stack_peak is the stack depth below the entry SP used by this
 * command, measured by repainting the unused stack below that SP. Neither
 * value includes allocator headers, static RAM, other tasks or the ISR stack. */
typedef struct {
    uint32_t heap_before, heap_after;
    uint32_t heap_peak, heap_retained, allocations;
    uint32_t stack_free_min, context_bytes, stack_peak;
    bool valid, aes_enabled;
} command_memory_t;

void command_memory_begin(bool aes_enabled, uint32_t context_bytes);
command_memory_t command_memory_end(void);
