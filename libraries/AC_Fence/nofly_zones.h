#ifndef NOFLY_ZONES_H
#define NOFLY_ZONES_H

#include <stdint.h>

// Define a structure to hold no-fly zones
struct NoFlyZone {
    int32_t lat;    // Latitude in degrees * 1e7
    int32_t lon;    // Longitude in degrees * 1e7
    float radius;   // Radius in meters
};

// Predefined No-Fly Zones
const NoFlyZone nofly_zones[] = {
    {374200000, -1220840000, 500}, // Example: Lat 37.42, Lon -122.084, Radius 500m
    {374210000, -1220850000, 300}, // Another No-Fly Zone
    {374220000, -1220860000, 200},  // Third No-Fly Zone
    {-353603393, 1491596668, 200}  // Third No-Fly Zone
    // {-353632621, 1491652374, 200}  // Third No-Fly Zone
};

const uint8_t num_nofly_zones = sizeof(nofly_zones) / sizeof(NoFlyZone);

#endif // NOFLY_ZONES_H
