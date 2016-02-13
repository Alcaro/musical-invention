//Musical Invention, main module
//Author: Alcaro
//Licence: GPL v3.0 or higher

#include "musical-invention.h"

struct musical_rule rules[] = {
{"example.com", 0,0, ~0, 0,65535, NULL, -1},
};
struct musical_config config = { rules, sizeof(rules)/sizeof(*rules), "MUSICAL", "ACCEPT", 0 };
