import React from 'react';
import { FaExclamationCircle, FaTimes } from 'react-icons/fa';

const LogoutModal = ({ closeModal, confirmLogout }) => {
    return (
        <div className="fixed top-0 left-0 w-full h-full flex justify-center items-center bg-black bg-opacity-50 z-50">
            <div className="bg-white rounded-lg p-6 max-w-md text-center">
                <div className="flex justify-end">
                    <button onClick={closeModal} className="text-gray-500 hover:text-gray-700 focus:outline-none">
                        <FaTimes />
                    </button>
                </div>
                <div className="mt-6 flex items-center justify-center space-x-4">
                    <FaExclamationCircle className="text-red-500 text-4xl" />
                    <p className="text-lg font-semibold">Are you sure you want to logout?</p>
                </div>
                <div className="mt-8 flex justify-center space-x-4">
                    <button onClick={closeModal} className="px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 focus:outline-none">
                        Cancel
                    </button>
                    <button onClick={confirmLogout} className="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 focus:outline-none">
                        Logout
                    </button>
                </div>
            </div>
        </div>
    );
};

export default LogoutModal;
