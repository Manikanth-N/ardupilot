#include "nofly_zones.h"
#include "AP_Math/AP_Math.h"
#include "AP_Common/Location.h"
#include "AP_AHRS/AP_AHRS.h"

const uint8_t num_nofly_zones = sizeof(nofly_zones) / sizeof(NoFlyZone);

// Function to retrieve No-Fly Zone details by index
bool get_nofly_zone(uint8_t index, Vector2f &center_pos_cm, float &radius) {
    if (index >= num_nofly_zones) {
        return false; // Index out of range
    }

    // Get No-Fly Zone details
    const NoFlyZone &zone = nofly_zones[index];

    // Convert lat/lon to NE offsets using EKF origin
    Location ekf_origin;
    if (!AP::ahrs().get_origin(ekf_origin)) {
        return false;  // No valid EKF origin
    }

    // ✅ FIX: Correctly initialize `Location` for NFZ
    Location nfz_location;
    nfz_location.lat = zone.lat;
    nfz_location.lng = zone.lon;


    // Compute NE offset using ArduPilot's function
    Vector2f ne_offset = ekf_origin.get_distance_NE(nfz_location);

    // Convert to cm (ArduPilot convention)
    center_pos_cm = ne_offset * 100.0f;
    radius = zone.radius * 100.0f;  // Convert meters to cm
    
    return true;
}

NFZ_Severity check_nofly_zone_severity(const Location& loc) {
    NFZ_Severity highest_severity = NFZ_Severity::GREEN;  // Default to GREEN

    for (uint8_t i = 0; i < num_nofly_zones; i++) {
        Vector2f center_pos_cm;
        float radius;

        if (get_nofly_zone(i, center_pos_cm, radius)) {
            // ✅ FIX: Correctly initialize a `Location` object
            Location nfz_location;
            nfz_location.lat = nofly_zones[i].lat;
            nfz_location.lng = nofly_zones[i].lon;

            // ✅ FIX: Call `get_distance_NE()` properly
            Vector2f position_NE = loc.get_distance_NE(nfz_location);
            float distance_cm = position_NE.length();

            if (distance_cm < radius) {
                // Inside No-Fly Zone
                if (nofly_zones[i].level > highest_severity) {
                    highest_severity = nofly_zones[i].level;
                }
            }
        }
    }

    return highest_severity;
}


