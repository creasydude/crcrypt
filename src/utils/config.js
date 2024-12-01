import fs from 'fs';
import path from 'path';

/**
 * Saves data to a JSON file in the specified folder within the project.
 *
 * @param {string} folderName - The folder within the project to save the file.
 * @param {string} fileName - The name of the JSON file.
 * @param {Object} data - The data to save (must be serializable to JSON).
 * @returns {Promise<void>} Resolves when the file is successfully written.
 */
async function saveDataToJsonFile(folderName, fileName, data) {
    try {
        // Resolve the folder path relative to the current project
        const folderPath = path.resolve(process.cwd(), folderName);

        // Ensure the folder exists
        if (!fs.existsSync(folderPath)) {
            fs.mkdirSync(folderPath, { recursive: true });
        }

        // Full path to the JSON file
        const filePath = path.join(folderPath, fileName);

        // Write data to the file
        await fs.promises.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
    } catch (error) {
        console.error('Error saving data to JSON file:', error);
        throw error; // Re-throw the error for upstream handling if necessary
    }
}

/**
 * Loads data from a JSON file in the specified folder within the project.
 *
 * @param {string} folderName - The folder within the project where the file is stored.
 * @param {string} fileName - The name of the JSON file.
 * @returns {Promise<Object>} Resolves to the parsed JSON data.
 */
async function loadDataFromJsonFile(folderName, fileName) {
    try {
        // Resolve the file path relative to the current project
        const filePath = path.resolve(process.cwd(), folderName, fileName);

        // Check if the file exists
        if (!fs.existsSync(filePath)) {
            throw new Error(`File not found: ${filePath}`);
        }

        // Read and parse the JSON file
        const fileContent = await fs.promises.readFile(filePath, 'utf-8');
        return JSON.parse(fileContent);
    } catch (error) {
        console.error('Error loading data from JSON file:', error);
        throw error; // Re-throw the error for upstream handling
    }
}

/**
 * Checks if a JSON file exists in the specified folder.
 *
 * @param {string} folderName - The folder within the project.
 * @param {string} fileName - The name of the file to check.
 * @returns {boolean} Returns true if the file exists, otherwise false.
 */
function doesConfigFileExist(folderName, fileName) {
    try {
        // Resolve the file path relative to the current project
        const filePath = path.resolve(process.cwd(), folderName, fileName);

        // Check if the file exists
        return fs.existsSync(filePath);
    } catch (error) {
        console.error('Error checking file existence:', error);
        return false; // Return false if any error occurs
    }
}

export { saveDataToJsonFile, loadDataFromJsonFile, doesConfigFileExist };