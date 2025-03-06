#include "nofly_zones.h"
#include "AP_Math/AP_Math.h"
#include "AP_Common/Location.h"
#include "AP_AHRS/AP_AHRS.h"
#include <GCS_MAVLink/GCS.h>

const uint8_t num_nofly_zones = sizeof(nofly_zones) / sizeof(NoFlyZone);

// ✅ **Ensure function matches the declaration**
bool get_nofly_zone(uint8_t index, Vector2f &center_pos_cm, float &radius) {
    if (index >= num_nofly_zones) {
        return false; // Index out of range
    }

    // Retrieve NFZ details
    const NoFlyZone &zone = nofly_zones[index];

    // ✅ Ensure EKF origin is available
    Location ekf_origin;
    if (!AP::ahrs().get_origin(ekf_origin)) {
        return false;  // No valid EKF origin
    }

    // ✅ Convert NFZ Lat/Lon to NE Frame
    Location nfz_location;
    nfz_location.lat = zone.lat;
    nfz_location.lng = zone.lon;
    Vector2f ne_offset = ekf_origin.get_distance_NE(nfz_location);

    // ✅ Convert to cm (ArduPilot convention)
    center_pos_cm = ne_offset * 100.0f;  // Store center position in cm

    // ✅ Assign default radius (ignored in AC_Avoid.cpp)
    radius = 0.0f;  

    return true;
}


bool in_nofly_zone(const Location& current_location, bool display_failure) {
    // Log the current UAV location in the GCS
    // gcs().send_text(MAV_SEVERITY_DEBUG, "UAV Location = (%d, %d)", current_location.lat, current_location.lng);

    // Define the radii for the red and yellow zones (in meters)
    const float red_zone_radius = 30000.0f;  // Red Zone radius in meters
    const float yellow_zone_radius = 50000.0f;  // Yellow Zone radius in meters
    // const float warning_distance = 40.0f;  // Maximum allowed distance inside the yellow zone

    // Iterate over all no-fly zones
    for (uint8_t i = 0; i < num_nofly_zones; i++) {
        // Create Location for the no-fly zone center
        Location nfz_location;
        nfz_location.lat = nofly_zones[i].lat;
        nfz_location.lng = nofly_zones[i].lon;


        // Get the distance between the current vehicle location and the No Fly Zone center
        Vector2f position_NE = current_location.get_distance_NE(nfz_location);  // Using passed location
        float distance_cm = position_NE.length() * 100.0f;  // Distance in centimeters

        // Check if the vehicle is inside the No Fly Zone
        if (distance_cm < red_zone_radius) {  // Red zone radius in cm (300m = 30000cm)
            // Inside red zone, prevent arming
            if (display_failure) {
                gcs().send_text(MAV_SEVERITY_CRITICAL, "UAV is inside a red no-fly zone. Cannot arm.");
            }
            return true;  // The vehicle is inside the red No Fly Zone, return true (cannot arm)
        } else if (distance_cm < yellow_zone_radius) {  // Yellow zone radius in cm (500m = 50000cm)
            // Inside yellow zone (within 40 meters of the red zone)
            if (display_failure) {
                gcs().send_text(MAV_SEVERITY_WARNING, "Warning: UAV is within %f meters of a red no-fly zone.", yellow_zone_radius - distance_cm / 100.0f);
            }

            // Check if the UAV is too close to the center of the yellow zone (within 40 meters)
            // if (distance_cm > yellow_zone_radius * 100.0f - warning_distance * 100.0f) {
            //     if (display_failure) {
            //         gcs().send_text(MAV_SEVERITY_WARNING, "Warning: UAV is too close to the red no-fly zone. You cannot fly more than 40 meters into the yellow zone.");
            //     }
            //     return true;
            // }
        }
    }

    return false;  // The vehicle is not inside any No Fly Zone
}

