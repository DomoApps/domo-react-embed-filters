// Import the JSONFilePreset from the lowdb library for file-based database handling
import {JSONFilePreset} from "lowdb/node";

// Define the default data structure for the database (an empty users array)
const defaultData = {users: []};

// Initialize the database using the JSON file 'users.json' with the default data
const db = await JSONFilePreset('users.json', defaultData);

// Export the database instance for use in other modules
export default db;