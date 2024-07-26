import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { MdEmail, MdLock, MdPerson } from 'react-icons/md';
import { toast } from 'react-hot-toast';
import { registerApi } from '../Apis/Api';

const Signup = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: ''
  });
  const [errors, setErrors] = useState({});
  const [passwordStrength, setPasswordStrength] = useState(null); // Initially set to null to hide the bar
  const navigate = useNavigate();

  const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const validatePassword = (password) => {
    return password.length >= 8 && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[\W]/.test(password);
  };

  const getPasswordStrength = (password) => {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (password.length <= 12) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[\W]/.test(password)) strength++;
    return strength;
  };

  const getPasswordStrengthLabel = (strength) => {
    switch (strength) {
      case 6:
        return { label: 'Strong', color: 'bg-green-500' };
      case 5:
        return { label: 'Okay', color: 'bg-yellow-500' };
      case 4:
        return { label: 'Okay', color: 'bg-yellow-500' };
      case 3:
        return { label: 'Weak', color: 'bg-red-500' };
      default:
        return { label: 'Weak', color: 'bg-red-500' };
    }
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
        password: validatePassword(value) ? '' : 'Password must be 8-12 characters, include an uppercase letter, a number, and a special character',
      }));
      const strength = getPasswordStrength(value);
      setPasswordStrength(strength);
    }
  };

  const onSubmit = async (e) => {
    e.preventDefault();

    // Validate the input fields
    if (!formData.name || !formData.email || !formData.password) {
        setErrors({
            name: !formData.name ? 'Name is required' : '',
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
        // Call the API to register the user
        const response = await registerApi(formData);

        if (response.status === 201) {
            toast.success('Registration successful! Please check your email to verify your account.');
        } else {
            toast.error('Something went wrong. Please try again.');
        }
    } catch (error) {
        // Handle specific errors based on the response from the server
        if (error.response && error.response.status === 400) {
            const { msg } = error.response.data;
            toast.error(msg);
        } else {
            toast.error('An unexpected error occurred. Please try again later.');
        }
    }
};

  const renderPasswordStrengthBar = () => {
    if (passwordStrength === null) return null;

    const segments = ['bg-red-500', 'bg-yellow-500', 'bg-green-500'];
    const labels = ['Weak', 'Okay', 'Strong'];

    return (
      <div className="mb-4">
        <div className="flex space-x-1 w-full mb-1">
          {segments.map((segmentColor, index) => (
            <div
              key={index}
              className={`h-1 ${index < Math.floor(passwordStrength / 2) ? segmentColor : 'bg-gray-200'} transition-all duration-300 ease-in-out rounded-full`}
              style={{ width: '33.33%' }}
            />
          ))}
        </div>
        <div className="text-right text-sm font-medium text-gray-700 dark:text-gray-300">
          {labels[Math.min(Math.floor(passwordStrength / 2), labels.length - 1)]}
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900">
      <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg p-6 shadow-lg">
        <h2 className="text-3xl font-bold text-center text-gray-900 dark:text-white mb-4">Create Account</h2>
        <form onSubmit={onSubmit}>
          <div className="mb-4">
            <label className="block text-gray-700 dark:text-gray-200">Name</label>
            <div className="flex items-center border border-gray-300 dark:border-gray-600 rounded-lg p-2">
              <MdPerson className="text-gray-500 dark:text-gray-400" size={20} />
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={onChange}
                className="w-full p-2 bg-transparent focus:outline-none dark:text-white"
                placeholder="Enter your name"
                required
              />
            </div>
            {errors.name && <p className="text-red-500 text-sm">{errors.name}</p>}
          </div>
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
          {renderPasswordStrengthBar()}
          <button
            type="submit"
            className="w-full text-white bg-blue-500 hover:bg-blue-600 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium text-sm px-4 py-3 rounded-lg text-center"
          >
            Sign Up
          </button>
        </form>
        <p className="mt-4 text-center text-gray-600 dark:text-gray-400">
          Already have an account?{' '}
          <Link to="/login" className="text-blue-500 hover:underline">
            Login here
          </Link>
        </p>
      </div>
    </div>
  );
};

export default Signup;
