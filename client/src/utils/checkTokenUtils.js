// src/utils/checkTokenUtils.js
export const checkTokenExpiration = () => {
    const token = localStorage.getItem("token");
  
    if (!token) {
      console.log("No token found, considered expired for safety.");
      return true;
    }
  
    try {
      const decodedToken = JSON.parse(atob(token.split(".")[1]));
      const expirationTime = decodedToken.exp * 1000;
      return Date.now() >= expirationTime;
    } catch (error) {
      console.error("Error decoding or parsing the token:", error);
      return true;
    }
  };
  