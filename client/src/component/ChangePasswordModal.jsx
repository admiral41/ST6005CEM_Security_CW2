import React, { useState } from 'react';
import { changePasswordApi } from '../Apis/Api';
import toast from 'react-hot-toast';

const ChangePasswordModal = ({ userId, closeModal }) => {
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordChecks, setPasswordChecks] = useState({
    minLength: false,
    hasUpperCase: false,
    hasNumber: false,
    hasSpecialChar: false,
    passwordsMatch: false,
  });

  const validatePassword = (password) => {
    const checks = {
      minLength: password.length >= 8,
      hasUpperCase: /[A-Z]/.test(password),
      hasNumber: /[0-9]/.test(password),
      hasSpecialChar: /[\W]/.test(password),
      passwordsMatch: password === confirmPassword,
    };
    setPasswordChecks(checks);
    return Object.values(checks).every(Boolean);
  };

  const handleChangePassword = async () => {
    if (!validatePassword(newPassword)) {
      toast.error('Please ensure your password meets all requirements.');
      return;
    }

    if (newPassword !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    try {
      const response = await changePasswordApi({ userId, newPassword });
      toast.success(response.data.msg); // Show success message from backend
      closeModal();
    } catch (error) {
      if (error.response && error.response.data && error.response.data.msg) {
        toast.error(error.response.data.msg);
      } else {
        toast.error('Failed to update password');
      }
    }
  };

  const renderPasswordChecks = () => (
    <ul className="text-sm text-gray-600 dark:text-gray-300 mt-2 space-y-1">
      <li className={`${passwordChecks.minLength ? 'text-green-600' : ''}`}>
        {passwordChecks.minLength ? '✔' : '✗'} Minimum 8 characters
      </li>
      <li className={`${passwordChecks.hasUpperCase ? 'text-green-600' : ''}`}>
        {passwordChecks.hasUpperCase ? '✔' : '✗'} At least one uppercase letter
      </li>
      <li className={`${passwordChecks.hasNumber ? 'text-green-600' : ''}`}>
        {passwordChecks.hasNumber ? '✔' : '✗'} At least one number
      </li>
      <li className={`${passwordChecks.hasSpecialChar ? 'text-green-600' : ''}`}>
        {passwordChecks.hasSpecialChar ? '✔' : '✗'} At least one special character
      </li>
      <li className={`${passwordChecks.passwordsMatch ? 'text-green-600' : ''}`}>
        {passwordChecks.passwordsMatch ? '✔' : '✗'} Passwords match
      </li>
    </ul>
  );

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
      <div className="bg-white dark:bg-gray-800 p-8 rounded-lg shadow-lg">
        <h2 className="text-2xl font-bold mb-4 text-gray-900 dark:text-gray-100">Change Password</h2>
        <div className="mb-4">
          <label className="block text-gray-700 dark:text-gray-300">New Password</label>
          <input
            type="password"
            className="w-full mt-2 p-3 border rounded-lg bg-gray-200 dark:bg-gray-700 focus:outline-none"
            value={newPassword}
            onChange={(e) => {
              setNewPassword(e.target.value);
              validatePassword(e.target.value);
            }}
          />
        </div>
        <div className="mb-4">
          <label className="block text-gray-700 dark:text-gray-300">Confirm Password</label>
          <input
            type="password"
            className="w-full mt-2 p-3 border rounded-lg bg-gray-200 dark:bg-gray-700 focus:outline-none"
            value={confirmPassword}
            onChange={(e) => {
              setConfirmPassword(e.target.value);
              setPasswordChecks((prevChecks) => ({
                ...prevChecks,
                passwordsMatch: newPassword === e.target.value,
              }));
            }}
          />
        </div>
        {renderPasswordChecks()}
        <div className="flex justify-end space-x-4 mt-4">
          <button
            className="px-6 py-3 bg-gray-600 text-white font-semibold rounded-lg hover:bg-gray-700 focus:outline-none"
            onClick={closeModal}
          >
            Cancel
          </button>
          <button
            className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 focus:outline-none"
            onClick={handleChangePassword}
          >
            Change Password
          </button>
        </div>
      </div>
    </div>
  );
};

export default ChangePasswordModal;
