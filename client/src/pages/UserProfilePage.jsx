import React, { useState } from "react";
import PageHeader from "../component/PageHeader";
import LogoutModal from '../component/LogoutModal';
import Profile from './Profile';
import Activity from './Activity';
import Files from './Files';

const UserProfilePage = () => {
  const user = JSON.parse(localStorage.getItem("user"));
  const [activeTab, setActiveTab] = useState("profile");
  const [showLogoutModal, setShowLogoutModal] = useState(false);

  if (!user) {
    return (
      <div className="flex justify-center py-2">
        <p>No user data found. Please log in.</p>
      </div>
    );
  }

  const handleLogout = () => {
    localStorage.clear();
    window.location.reload();
  };

  return (
    <>
      <PageHeader title="User Profile Page" path="Home > User Profile Page" />
      <div className="flex">
        <div className="w-1/4 bg-gray-100 dark:bg-gray-800 p-4 rounded-lg shadow-lg">
          <ul className="space-y-4">
            <li>
              <button
                className={`w-full text-left py-2 px-4 text-blue-500 hover:text-blue-800 font-semibold ${
                  activeTab === "profile" ? "border-l-4 border-blue-500 bg-blue-50" : "hover:bg-blue-50"
                }`}
                onClick={() => setActiveTab("profile")}
              >
                Your Profile
              </button>
            </li>
            <li>
              <button
                className={`w-full text-left py-2 px-4 text-blue-500 hover:text-blue-800 font-semibold ${
                  activeTab === "activity" ? "border-l-4 border-blue-500 bg-blue-50" : "hover:bg-blue-50"
                }`}
                onClick={() => setActiveTab("activity")}
              >
                Activity
              </button>
            </li>
            <li>
              <button
                className={`w-full text-left py-2 px-4 text-blue-500 hover:text-blue-800 font-semibold ${
                  activeTab === "files" ? "border-l-4 border-blue-500 bg-blue-50" : "hover:bg-blue-50"
                }`}
                onClick={() => setActiveTab("files")}
              >
                Your Files
              </button>
            </li>
            <li>
              <button
                className="w-full text-left py-2 px-4 text-red-500 hover:text-red-800 font-semibold hover:bg-red-50"
                onClick={() => setShowLogoutModal(true)}
              >
                Logout
              </button>
            </li>
          </ul>
        </div>
        <div className="w-3/4 bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg">
          {activeTab === "profile" && <Profile user={user} />}
          {activeTab === "activity" && <Activity user={user} />}
          {activeTab === "files" && <Files />}
        </div>
      </div>
      {showLogoutModal && (
        <LogoutModal
          closeModal={() => setShowLogoutModal(false)}
          confirmLogout={handleLogout}
        />
      )}
    </>
  );
};

export default UserProfilePage;
