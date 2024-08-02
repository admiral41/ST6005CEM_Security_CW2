import React, { useState } from 'react';
import ChangePasswordModal from '../component/ChangePasswordModal';

const Profile = ({ user }) => {
  const [isModalOpen, setIsModalOpen] = useState(false);

  const handlePasswordChange = () => {
    setIsModalOpen(true);
  };

  return (
    <div className="p-8 bg-white dark:bg-gray-800 rounded-lg shadow-lg">
      <div className="flex items-center space-x-6 mb-6">
        <img
          className="w-28 h-28 rounded-full border-4 border-gray-300 shadow-sm"
          src="https://via.placeholder.com/100" // Placeholder image, replace with actual user image if available
          alt="User Profile"
        />
        <div>
          <h2 className="text-4xl font-bold text-gray-900 dark:text-gray-100">{user.name}</h2>
          <p className="text-lg text-gray-500 dark:text-gray-400">{user.email}</p>
        </div>
      </div>
      <div className="mb-6">
        <h3 className="text-2xl font-semibold text-gray-900 dark:text-gray-200 mb-2">Number of Files:</h3>
        <p className="text-xl text-gray-700 dark:text-gray-300">{user.files ? user.files.length : 0}</p>
      </div>
      <div className="flex space-x-4 mt-4">
        <button className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 focus:outline-none">
          Edit Profile
        </button>
        <button 
          className="px-6 py-3 bg-red-600 text-white font-semibold rounded-lg hover:bg-red-700 focus:outline-none"
          onClick={handlePasswordChange} // Open modal on click
        >
          Change Password
        </button>
      </div>
      {isModalOpen && (
        <ChangePasswordModal
          userId={user.id}  // Pass userId to ChangePasswordModal
          closeModal={() => setIsModalOpen(false)}
        />
      )}
    </div>
  );
};

export default Profile;
