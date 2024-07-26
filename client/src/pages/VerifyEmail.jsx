import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import axios from 'axios';

const VerifyEmail = () => {
  const { verificationToken } = useParams();
  const navigate = useNavigate();
  const [countdown, setCountdown] = useState(3); // Countdown timer

  useEffect(() => {
    const intervalId = setInterval(() => {
      setCountdown(prevCountdown => prevCountdown - 1);
    }, 1000);

    // When countdown reaches 0, trigger API call and redirect
    if (countdown === 0) {
      clearInterval(intervalId);
      verifyEmail();
    }

    return () => clearInterval(intervalId); // Clear interval on component unmount
  }, [countdown]);

  const verifyEmail = async () => {
    try {
      const response = await axios.get(`https://localhost:5000/api/users/verify/${verificationToken}`);
      toast.success(response.data.msg);
      navigate('/login');
    } catch (error) {
      toast.error('Invalid or expired verification link.');
      navigate('/');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center">
      <p>Verifying your email... You will be redirected to the login page in {countdown} seconds.</p>
    </div>
  );
};

export default VerifyEmail;
