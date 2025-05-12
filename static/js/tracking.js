/**
 * Live tracking functionality for both admin and user interfaces
 */

// Socket.io connection for real-time updates
let socket;

// Initialize tracking map
function initTrackingMap(elementId, centerLat, centerLng, zoom) {
    const map = L.map(elementId).setView([centerLat, centerLng], zoom);
    
    // Add OpenStreetMap tiles
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);
    
    return map;
}

// Create or update truck markers
function updateTruckMarkers(map, markers, data) {
    data.forEach(collector => {
        if (markers[collector.id]) {
            // Update existing marker
            markers[collector.id].setLatLng([collector.lat, collector.lng]);
            markers[collector.id].bindPopup(`
                <strong>${collector.name}</strong><br>
                Vehicle: ${collector.vehicle_id}<br>
                Barangay: ${collector.barangay}<br>
                Last Updated: ${collector.last_updated}
            `);
        } else {
            // Create new marker
            const truckIcon = L.icon({
                iconUrl: '/static/img/truck-icon.png',
                iconSize: [32, 32],
                iconAnchor: [16, 32],
                popupAnchor: [0, -32]
            });
            
            markers[collector.id] = L.marker([collector.lat, collector.lng], {icon: truckIcon}).addTo(map);
            markers[collector.id].bindPopup(`
                <strong>${collector.name}</strong><br>
                Vehicle: ${collector.vehicle_id}<br>
                Barangay: ${collector.barangay}<br>
                Last Updated: ${collector.last_updated}
            `);
        }
    });
}

// Fetch collector locations from API
function fetchCollectorLocations(callback, barangayId = null) {
    let url = '/api/collectors-location';
    if (barangayId) {
        url += `?barangay=${barangayId}`;
    }
    
    fetch(url)
        .then(response => response.json())
        .then(data => callback(data))
        .catch(error => console.error('Error fetching collector locations:', error));
}

// Connect to real-time updates via Socket.io
function connectToRealtimeUpdates(map, markers, barangayId = null) {
    socket = io();
    
    socket.on('location_update', function(data) {
        if (barangayId && data.barangay_id !== barangayId) {
            return; // Skip updates for different barangays if filtering is active
        }
        
        if (markers[data.id]) {
            // Update existing marker
            markers[data.id].setLatLng([data.lat, data.lng]);
            
            // Update popup content
            const popup = markers[data.id].getPopup();
            popup.setContent(`
                <strong>${data.name}</strong><br>
                Vehicle: ${data.vehicle_id}<br>
                Barangay: ${data.barangay}<br>
                Last Updated: ${data.last_updated}
            `);
            
            // If popup is open, update it
            if (popup.isOpen()) {
                popup.update();
            }
        }
    });
}

// Handle location update for collector client
function initCollectorLocationUpdate(vehicleId) {
    // Check if geolocation is available
    if (!navigator.geolocation) {
        alert('Geolocation is not supported by your browser');
        return;
    }
    
    // Watch position and send updates
    const watchId = navigator.geolocation.watchPosition(
        position => {
            const locationData = {
                lat: position.coords.latitude,
                lng: position.coords.longitude,
                vehicle_id: vehicleId,
                timestamp: new Date().toISOString()
            };
            
            // Send location to server
            fetch('/api/update-location', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(locationData)
            })
            .then(response => response.json())
            .then(data => console.log('Location updated:', data))
            .catch(error => console.error('Error updating location:', error));
        },
        error => {
            console.error('Error getting location:', error);
        },
        {
            enableHighAccuracy: true,
            timeout: 5000,
            maximumAge: 0
        }
    );
    
    return watchId;
}

// Stop location tracking
function stopLocationTracking(watchId) {
    navigator.geolocation.clearWatch(watchId);
}
