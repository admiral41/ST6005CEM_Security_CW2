import React, { createContext, useState, useEffect } from 'react';
import { checkTokenExpiration } from '../utils/checkTokenUtils';  // Import the token check utility

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');

    if (token && userData && !checkTokenExpiration()) {
      setIsLoggedIn(true);
      setUser(JSON.parse(userData));
    } else {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
    }
  }, []);

  return (
    <AuthContext.Provider value={{ isLoggedIn, setIsLoggedIn, user, setUser }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => React.useContext(AuthContext);
