import React, { useEffect, useState, useRef } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { Toaster, toast } from 'react-hot-toast';
import ApplicationTabs from '../component/ApplicationTabs';

const ApplicationLayout = () => {
  const [user, setUser] = useState(null);
  const [isLoaded, setIsLoaded] = useState(false);
  const navigate = useNavigate();
  const hasCheckedAuth = useRef(false);

  useEffect(() => {
    if (hasCheckedAuth.current) {
      return;
    }

    hasCheckedAuth.current = true;

    const checkAuth = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        toast.error("You need to be logged in to access this page");
        navigate("/");
        return;
      }

      try {
        const response = await fetch('https://localhost:5000/api/users/auth/check', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });

        if (!response.ok) {
          throw new Error('Authentication failed');
        }

        const data = await response.json();
        setUser(data.user);
        setIsLoaded(true);
      } catch (error) {
        toast.error("Please log in to view this page.");
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        navigate("/");
      }
    };

    checkAuth();
  }, [navigate]);

  if (!isLoaded) return "Loading...";

  return (
    <div className="p-5 px-8 md:px-28 max-sm:px-2">
      <ApplicationTabs user={user} />
      <Outlet />
      <Toaster position="top-center" />
    </div>
  );
};

export default ApplicationLayout;
