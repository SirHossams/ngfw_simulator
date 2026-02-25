#pragma once

#include "packet.h"
#include "decision.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    int (*init)();

    decision_t (*process_packet)(packet_t* packet);

    void (*cleanup)();

} module_interface_t;


module_info_t* module_get_info();

module_interface_t* module_get_interface();

#ifdef __cplusplus
}
#endif