  import React, { useEffect } from 'react';
  import { RouterProvider, createBrowserRouter, useNavigate } from 'react-router-dom';
  import { Toaster } from 'react-hot-toast';
  import FileDownload from './pages/FileDownload';
  import ApplicationLayout from './pages/ApplicationLayout';
  import Login from './pages/Login';
  import Signup from './pages/Signup';
  import Landing from './pages/Landing';
  import ApplicationPage from './pages/ApplicationPage';
  import FileHistory from './pages/FileHistory';
  import UserProfilePage from './pages/UserProfilePage';
  import { AuthProvider, useAuth } from './context/AuthContext';
  import HomeLayout from './pages/homeLayout';
  import UnlockAccount from './pages/UnlockAccount';
  import VerifyEmail from './pages/VerifyEmail';
  import { checkTokenExpiration } from './utils/checkTokenUtils'; // Import the token check utility

  const ProtectedRoute = ({ element }) => {
    const { setIsLoggedIn, setUser } = useAuth();
    const navigate = useNavigate();

    useEffect(() => {
      const handleAuthCheck = () => {
        const user = JSON.parse(localStorage.getItem('user'));
        const token = localStorage.getItem('token');

        if (!token || !user || checkTokenExpiration()) {
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          setIsLoggedIn(false);
          setUser(null);
          navigate('/login');
          return;
        }
      };

      handleAuthCheck();

      const intervalId = setInterval(handleAuthCheck, 5 * 60 * 1000); // Re-check every 5 minutes

      return () => clearInterval(intervalId);
    }, [navigate, setIsLoggedIn, setUser]);

    return element;
  };

  const router = createBrowserRouter([
    {
      path: '/',
      element: <HomeLayout />,
      children: [
        {
          index: true,
          element: <Landing />,
        },
        {
          path: '/signup',
          element: <Signup />,
        },
        {
          path: '/login',
          element: <Login />,
        },
        {
          path: '/verify/:verificationToken',
          element: <VerifyEmail />,
        },
        {
          path: '/app',
          element: <ProtectedRoute element={<ApplicationLayout />} />, // Wrap protected routes
          children: [
            { path: '/app', element: <ApplicationPage /> },
            { path: '/app/file-history', element: <FileHistory /> },
            { path: '/app/user-profile', element: <UserProfilePage /> }
          ],
        },
        {
          path: '/download',
          element: <FileDownload />,
        },
        {
          path: '/unlock/:resetToken',
          element: <UnlockAccount />,
        },
      ],
    },
  ]);

  function App() {
    return (
      <AuthProvider>
        <RouterProvider router={router} />
        <Toaster position="top-center" />
      </AuthProvider>
    );
  }

  export default App;
