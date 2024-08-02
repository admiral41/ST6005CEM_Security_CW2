import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-hot-toast';
import { CircularProgress } from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';

const UnlockAccount = () => {
  const { resetToken } = useParams();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('Click the button below to unlock your account.');
  const [status, setStatus] = useState('');

  const handleUnlock = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`https://localhost:5000/api/users/unlock/${resetToken}`);
      setMessage(response.data.msg);
      setStatus('success');
      toast.success('Account unlocked successfully!');
      setTimeout(() => {
        navigate('/login');
      }, 3000); // Redirect to login page after 3 seconds
    } catch (error) {
      const errorMsg = error.response?.data?.msg || 'Failed to unlock account. Invalid or expired link.';
      setMessage(errorMsg);
      setStatus('error');
      toast.error(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-r from-blue-600 to-indigo-700">
      <div className="max-w-md w-full bg-white dark:bg-gray-900 rounded-lg p-8 shadow-lg">
        <div className="flex flex-col items-center">
          {loading ? (
            <>
              <CircularProgress color="primary" />
              <h2 className="text-xl font-semibold text-center text-gray-900 dark:text-white mt-6">
                Unlocking your account...
              </h2>
            </>
          ) : (
            <>
              {status === 'success' ? (
                <CheckCircleIcon style={{ fontSize: 60, color: '#4caf50' }} />
              ) : status === 'error' ? (
                <ErrorIcon style={{ fontSize: 60, color: '#f44336' }} />
              ) : (
                <button
                  className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded mt-4 transition duration-150 ease-in-out"
                  onClick={handleUnlock}
                >
                  Verify Now
                </button>
              )}
              <h2 className="text-2xl font-semibold text-center text-gray-900 dark:text-white mt-6">
                {message}
              </h2>
              {status === 'success' && (
                <p className="text-center text-gray-600 dark:text-gray-400 mt-4">
                  You will be redirected to the login page shortly.
                </p>
              )}
              {status === 'error' && (
                <p className="text-center text-gray-600 dark:text-gray-400 mt-4">
                  Please ensure you have used a valid unlock link.
                </p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default UnlockAccount;
