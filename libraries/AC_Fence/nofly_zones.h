#ifndef NOFLY_ZONES_H
#define NOFLY_ZONES_H

#include <stdint.h>
#include "AP_Math/AP_Math.h"
#include "AP_Common/Location.h"
#include <GCS_MAVLink/GCS.h>


// Define Severity Levels
enum class NFZ_Severity {
    RED = 3,    // Strict No-Fly (Avoid Completely)
    YELLOW = 2, // Restricted Flight (Max 40m Altitude)
    GREEN = 1   // No Restrictions (Uses Default Limits)
};

// Define a structure to hold no-fly zones
struct NoFlyZone {
    int32_t lat;    // Latitude in degrees * 1e7
    int32_t lon;    // Longitude in degrees * 1e7
    float radius;   // Radius in meters
};

// Predefined No-Fly Zones
const NoFlyZone nofly_zones[] = {
    {174837938,787595492,5000} // Near tara UAV drone Academy test place
    
};

extern const uint8_t num_nofly_zones;
extern const uint16_t in_yellow_zone_radius;

// ✅ Declare `get_nofly_zone()`
bool get_nofly_zone(uint8_t index, Vector2f &center_pos_cm, float &radius);
bool in_nofly_zone(const Location& current_location, bool display_failure);
bool in_yellow_zone();
#endif // NOFLY_ZONES_H
