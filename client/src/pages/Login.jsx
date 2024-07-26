import React, { useState, useContext } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { MdEmail, MdLock } from 'react-icons/md';
import { loginApi } from '../Apis/Api';
import { toast, Toaster } from 'react-hot-toast';
import { AuthContext } from '../context/AuthContext';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [errors, setErrors] = useState({ email: '', password: '' });
  const navigate = useNavigate();
  const { setIsLoggedIn, setUser } = useContext(AuthContext);

  const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const validatePassword = (password) => {
    return password.length >= 6;
  };

  const onChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
    if (name === 'email') {
      setErrors((prevErrors) => ({
        ...prevErrors,
        email: validateEmail(value) ? '' : 'Invalid email address',
      }));
    }
    if (name === 'password') {
      setErrors((prevErrors) => ({
        ...prevErrors,
        password: validatePassword(value) ? '' : 'Password must be at least 6 characters',
      }));
    }
  };

  const onSubmit = async (e) => {
    e.preventDefault();

    if (!formData.email || !formData.password) {
      setErrors({
        email: !formData.email ? 'Email is required' : '',
        password: !formData.password ? 'Password is required' : '',
      });
      return;
    }

    if (!validateEmail(formData.email) || !validatePassword(formData.password)) {
      toast.error('Please enter valid credentials');
      return;
    }

    try {
      const response = await loginApi(formData);
      if (response.data.token) {
        toast.success("Login successful!");
        localStorage.setItem("token", response.data.token);
        localStorage.setItem("user", JSON.stringify(response.data.user));
        setIsLoggedIn(true);
        setUser(response.data.user);
        navigate('/app');
      } else {
        toast.error(response.data.msg);
      }
    } catch (err) {
      toast.error(err.response?.data?.msg || 'Login failed');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900">
      <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg p-6 shadow-lg">
        <h2 className="text-3xl font-bold text-center text-gray-900 dark:text-white mb-4">Login</h2>
        <form onSubmit={onSubmit}>
          <div className="mb-4">
            <label className="block text-gray-700 dark:text-gray-200">Email</label>
            <div className="flex items-center border border-gray-300 dark:border-gray-600 rounded-lg p-2">
              <MdEmail className="text-gray-500 dark:text-gray-400" size={20} />
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={onChange}
                className={`w-full p-2 bg-transparent focus:outline-none dark:text-white ${errors.email ? 'border-red-500' : ''}`}
                placeholder="Enter your email"
                required
              />
            </div>
            {errors.email && <p className="text-red-500 text-sm">{errors.email}</p>}
          </div>
          <div className="mb-4">
            <label className="block text-gray-700 dark:text-gray-200">Password</label>
            <div className="flex items-center border border-gray-300 dark:border-gray-600 rounded-lg p-2">
              <MdLock className="text-gray-500 dark:text-gray-400" size={20} />
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={onChange}
                className={`w-full p-2 bg-transparent focus:outline-none dark:text-white ${errors.password ? 'border-red-500' : ''}`}
                placeholder="Enter your password"
                required
              />
            </div>
            {errors.password && <p className="text-red-500 text-sm">{errors.password}</p>}
          </div>
          <button
            type="submit"
            className="w-full text-white bg-blue-500 hover:bg-blue-600 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium text-sm px-4 py-3 rounded-lg text-center"
          >
            Login
          </button>
        </form>
        <p className="mt-4 text-center text-gray-600 dark:text-gray-400">
          Don't have an account?{' '}
          <Link to="/signup" className="text-blue-500 hover:underline">
            Sign up here
          </Link>
        </p>
      </div>
      <Toaster position="top-center" />
    </div>
  );
};

export default Login;
