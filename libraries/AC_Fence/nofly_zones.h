#ifndef NOFLY_ZONES_H
#define NOFLY_ZONES_H

#include <stdint.h>
#include "AP_Math/AP_Math.h"
#include "AP_Common/Location.h"
#include <GCS_MAVLink/GCS.h>


// Define a structure to hold no-fly zones
struct NoFlyZone {
    int32_t lat;    // Latitude in degrees * 1e7
    int32_t lon;    // Longitude in degrees * 1e7
    float radius;   // Radius in meters
};

// Predefined No-Fly Zones
const NoFlyZone nofly_zones[] = {
    {174837938,787595492,5000}, // Near tara UAV drone Academy test place
    {172296731,784318854,5000}, // Shamshabad Airport (RGIA)
    {174531500,784688199,5000}, // Begumpet Airport
    {176281299,784054301,5000}, // Dundigal Airport
    {175532699,785217400,5000}, // Hakimpet Airport

};

extern const uint8_t num_nofly_zones;
extern const uint16_t red_zone_radius;
extern const uint16_t yellow_zone_radius;

// ✅ Declare `get_nofly_zone()`
bool get_nofly_zone(uint8_t index, Vector2f &center_pos_cm, float &radius);
bool in_nofly_zone(const Location& current_location, bool display_failure);
bool in_yellow_zone();
uint16_t get_yellow_zone_radius();
uint16_t get_red_zone_radius();
#endif // NOFLY_ZONES_H
