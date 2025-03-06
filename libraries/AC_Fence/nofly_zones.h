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
    // {374200000, -1220840000, 500}, // Example: Lat 37.42, Lon -122.084, Radius 500m
    // {374210000, -1220850000, 300}, // Another No-Fly Zone
    {-353632621, 1491652374, 200},  // Third No-Fly Zone
    {-353603393, 1491596668, 300}  // Third No-Fly Zone
    // {-353632621, 1491652374, 200}  // Third No-Fly Zone
};

extern const uint8_t num_nofly_zones;

// ✅ Declare `get_nofly_zone()`
bool get_nofly_zone(uint8_t index, Vector2f &center_pos_cm, float &radius);
bool in_nofly_zone(const Location& current_location, bool display_failure);
#endif // NOFLY_ZONES_H
