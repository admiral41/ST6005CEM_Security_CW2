import axios from "axios";
import toast from "react-hot-toast";

const Api = axios.create({
    baseURL: 'https://localhost:5000',
    withCredentials: true,
    headers: {
        'Content-Type': 'multipart/form-data',
    },
});

const ApiJson = axios.create({
    baseURL: 'https://localhost:5000',
    withCredentials: true, // This allows cookies to be sent
    headers: {
        'Content-Type': 'application/json',
    },
});

// Interceptor to add Authorization header to every request
Api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

ApiJson.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

// Interceptor for handling token expiration
Api.interceptors.response.use(
    response => response,
    error => {
        if (error.response.status === 401 && error.response.data.message === "Token expired") {
            localStorage.removeItem('token');
            window.location.href = '/login';
            toast.error("Session expired. Please login again.");
        }
        return Promise.reject(error);
    }
);

ApiJson.interceptors.response.use(
    response => response,
    error => {
        if (error.response.status === 401 && error.response.data.message === "Token expired") {
            localStorage.removeItem('token');
            window.location.href = '/login';
            toast.error("Session expired. Please login again.");
        }
        return Promise.reject(error);
    }
);

export const loginApi = (data) => ApiJson.post('/api/users/login', data);
export const registerApi = (data) => ApiJson.post('/api/users/register', data);
export const uploadFileApi = (data, options) => Api.post('/api/files/upload', data, options);
export const changePasswordApi = (data) => {
    return ApiJson.post('/api/users/change-password', data);
};
