import React, { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "react-hot-toast";
import { FiCopy, FiTrash2 } from "react-icons/fi";
import { z } from "zod";

const Files = () => {
  const [files, setFiles] = useState([]);
  const [fileId, setFileId] = useState('');
  const [password, setPassword] = useState('');
  const downloadSchema = z.object({
    fileId: z.string().min(5, "File ID field must be valid length and value"),
    password: z.string().min(5, "Password field must be valid length and value")
});
  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const token = localStorage.getItem("token");
        const response = await axios.get("https://localhost:5000/api/files/getAllFiles", {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });

        // Ensure the response data is an array
        if (Array.isArray(response.data.files)) {
          setFiles(response.data.files);
        } else {
          console.error("Expected an array but got:", response.data.files);
          toast.error("Error fetching files");
        }
      } catch (error) {
        toast.error("Error fetching files");
        console.error(error);
      }
    };

    fetchFiles();
  }, []);

  const copyToClipboard = (downloadLink) => {
    const fileId = downloadLink.split('/').pop();
    navigator.clipboard.writeText(fileId);
    toast.success("Copied File ID to clipboard");
  };

  const downloadFileWithPassword = async () => {
      const validationResult = downloadSchema.safeParse({ fileId, password });
      if (!validationResult.success) {
          validationResult.error.issues.forEach(issue => {
              toast.error(issue.message);
          });
          return;
      }

      const token = localStorage.getItem("token");
      if (!token) {
          toast.error("User is not logged in");
          return;
      }

      try {
          const response = await axios.get(
              `https://localhost:5000/api/files/download/${fileId}`,
              {
                  responseType: "arraybuffer",
                  headers: {
                      'Authorization': `Bearer ${token}`,
                      'password': password
                  }
              }
          );

          const contentDisposition = response.headers["content-disposition"];
          const filename = contentDisposition
              ? contentDisposition.split("filename=")[1].replace(/['"]/g, "")
              : "downloaded_file";

          const blob = new Blob([response.data], { type: response.headers["content-type"] });
          const url = window.URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = url;
          link.setAttribute("download", filename);
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);

          toast.success("File successfully downloaded and decrypted");
      } catch (error) {
          toast.error("Error downloading or decrypting the file");
      }

  };

  const deleteFile = async (fileId) => {
    try {
      const token = localStorage.getItem("token");
      await axios.delete(`https://localhost:5000/api/files/delete/${fileId}`, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      setFiles(files.filter(file => file._id !== fileId));
      toast.success("File deleted successfully");
    } catch (error) {
      toast.error("Error deleting file");
      console.error(error);
    }
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <h2 className="text-2xl font-bold mb-6">Your Uploaded Files</h2>
      <div className="mb-6 p-6 border border-gray-300 rounded-lg shadow-md bg-white dark:bg-gray-800">
        <h3 className="text-lg font-semibold mb-4">Download File</h3>
        <div className="flex flex-col md:flex-row md:items-center md:space-x-4">
          <input
            type="text"
            placeholder="Enter File ID"
            value={fileId}
            onChange={(e) => setFileId(e.target.value)}
            className="block w-full p-2 mb-2 border border-gray-300 rounded md:mb-0"
          />
          <input
            type="password"
            placeholder="Enter Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="block w-full p-2 mb-2 border border-gray-300 rounded md:mb-0"
          />
          <button
            onClick={downloadFileWithPassword}
            className="bg-blue-500 text-white py-2 px-4 rounded"
          >
            Download
          </button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full bg-white dark:bg-gray-800">
          <thead>
            <tr>
              <th className="py-2 px-4 border-b border-gray-200 dark:border-gray-700 text-left">File Name</th>
              <th className="py-2 px-4 border-b border-gray-200 dark:border-gray-700 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            {files.map((file) => (
              <tr key={file._id}>
                <td className="py-2 px-4 border-b border-gray-200 dark:border-gray-700">{file.originalName}</td>
                <td className="py-2 px-4 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex space-x-4">
                    <button
                      className="text-blue-500 hover:text-blue-700"
                      onClick={() => copyToClipboard(file.downloadLink)}
                      title="Copy File ID"
                    >
                      <FiCopy size={20} />
                    </button>
                    <button
                      className="text-red-500 hover:text-red-700"
                      onClick={() => deleteFile(file._id)}
                      title="Delete File"
                    >
                      <FiTrash2 size={20} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Files;
