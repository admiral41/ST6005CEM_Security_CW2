import React, { useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';
import moment from 'moment';

// Define custom icon for markers
const customIcon = new L.Icon({
  iconUrl: 'https://unpkg.com/leaflet@1.7.1/dist/images/marker-icon.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowUrl: 'https://unpkg.com/leaflet@1.7.1/dist/images/marker-shadow.png',
  shadowSize: [41, 41]
});

const Activity = ({ user }) => {
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 3;

  const handleActivityResponse = (index, isMe) => {
    console.log(`Log entry ${index}: ${isMe ? "This is me" : "This is not me"}`);
    // Handle the response (e.g., send to the backend)
  };

  const totalPages = Math.ceil(user.logs.length / itemsPerPage);
  const currentLogs = user.logs.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  return (
    <div>
      <h3 className="text-xl font-bold mb-2">Activity Logs</h3>
      <ul className="space-y-4">
        {currentLogs.map((log, index) => (
          <li
            key={index}
            className="bg-gray-100 dark:bg-gray-700 p-4 rounded-lg shadow-sm"
          >
            <div className="flex items-center space-x-4">
              <div className="text-blue-500 dark:text-blue-400">
                {log.action === "User logged in" ? (
                  <svg
                    className="w-6 h-6"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2"
                      d="M12 11c0-1.654 1.346-3 3-3s3 1.346 3 3-1.346 3-3 3-3-1.346-3-3zM9 8V7a4 4 0 1 1 8 0v1M15 11c0 3-3 5-3 5s-3-2-3-5"
                    />
                  </svg>
                ) : (
                  <svg
                    className="w-6 h-6"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2"
                      d="M5 13l4 4L19 7"
                    />
                  </svg>
                )}
              </div>
              <div>
                <p className="font-bold">{log.action}</p>
                <p className="text-gray-500 dark:text-gray-400 text-sm">
                  {moment(log.timestamp).format('MMMM Do YYYY, h:mm:ss a')} - {log.ip} - {log.location}
                </p>
              </div>
            </div>
            <div className="mt-4">
              <MapContainer
                center={[log.latitude, log.longitude]}
                zoom={2}
                style={{ height: "200px", width: "100%" }}
              >
                <TileLayer
                  url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                />
                <Marker
                  position={[log.latitude, log.longitude]}
                  icon={customIcon}
                >
                  <Popup>
                    <span>{log.action}</span>
                    <br />
                    <span>{moment(log.timestamp).format('MMMM Do YYYY, h:mm:ss a')}</span>
                    <br />
                    <span>{log.ip}</span>
                  </Popup>
                </Marker>
              </MapContainer>
            </div>
            <div className="mt-4 flex space-x-4">
              <button
                className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600"
                onClick={() => handleActivityResponse(index, true)}
              >
                This is me
              </button>
              <button
                className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600"
                onClick={() => handleActivityResponse(index, false)}
              >
                This is not me
              </button>
            </div>
          </li>
        ))}
      </ul>
      <div className="flex justify-between mt-4">
        <button
          className="bg-gray-300 text-gray-700 px-4 py-2 rounded hover:bg-gray-400"
          onClick={() => setCurrentPage(currentPage - 1)}
          disabled={currentPage === 1}
        >
          Previous
        </button>
        <button
          className="bg-gray-300 text-gray-700 px-4 py-2 rounded hover:bg-gray-400"
          onClick={() => setCurrentPage(currentPage + 1)}
          disabled={currentPage === totalPages}
        >
          Next
        </button>
      </div>
    </div>
  );
};

export default Activity;
