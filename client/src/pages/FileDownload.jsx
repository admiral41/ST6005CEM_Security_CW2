import React, { useState } from "react";
import axios from "axios";
import { toast } from 'react-hot-toast';
import { z } from "zod";
import AdvancedPasswordInput from "../component/AdvancedPasswordInput";
import PageHeader from "../component/PageHeader";

const FileDownload = () => {
    const [password, setPassword] = useState("");
    const [fileId, setFileId] = useState("");
    const [seePassword, setSeePassword] = useState(false);

    const downloadSchema = z.object({
        fileId: z.string().min(5, "File ID field must be valid length and value"),
        password: z.string().min(7, "Password field must be valid length and value")
    });

    const handleDownload = async () => {
        const validationResult = downloadSchema.safeParse({ fileId, password });
        if (!validationResult.success) {
            validationResult.error.issues.forEach(issue => {
                toast.error(issue.message);
            });
            return;
        }

        try {
            const response = await axios.get(
                `https://localhost:5000/api/files/download/${fileId}`,
                {
                    responseType: "arraybuffer",
                    headers: {
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

    return (
        <div className="px-8 md:px-28 max-sm:px-2">
            <PageHeader title="File Download Page" path="Home > File Download" />
            <div className="py-16">
                <div className="mb-6">
                    <label htmlFor="id-input" className="block mb-2 text-base font-medium text-gray-900 dark:text-white">
                        Enter File ID
                    </label>
                    <input
                        required={true}
                        type="text"
                        placeholder="Enter File ID"
                        value={fileId}
                        onChange={(e) => setFileId(e.target.value)}
                        id="id-input"
                        className="block w-full p-4 text-gray-900 border border-gray-300 rounded-lg bg-gray-50 sm:text-md focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                    />
                </div>
                <AdvancedPasswordInput seePassword={seePassword} setSeePassword={setSeePassword} filePassword={password} setFilePassword={setPassword} idValue="file-password-decrypt" placeValue="Enter File Password" />
                <button
                    onClick={handleDownload}
                    type="button"
                    className="w-full px-6 mt-5 py-3.5 text-lg font-medium text-white bg-blue-500 hover:bg-blue-600 focus:ring-4 focus:outline-none focus:ring-blue-300 rounded-lg text-center dark:bg-blue-500 dark:hover:bg-blue-600 dark:focus:ring-blue-600 uppercase max-sm:text-base"
                >
                    Download and decrypt
                </button>
            </div>
        </div>
    );
};

export default FileDownload;
