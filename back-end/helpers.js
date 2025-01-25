// Import required modules
import jwt from "jsonwebtoken"; // Library for creating and verifying JSON Web Tokens (JWT)
import db from './db/db.js';     // Import the database module (LowDB)
import dotenv from 'dotenv';     // Library to load environment variables from a .env file

// Load environment variables from the .env file
dotenv.config();

// Destructure 'users' from the database's data object
const {users} = db.data;

// Set the secret key for JWT verification, using an environment variable or a default value
const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecretKey';

/**
 * Function to verify the JWT token from the request cookies
 * @param {Object} req - The request object containing cookies with the token
 * @returns {Object} Response object with status and message or user data
 */
export const verifyToken = async (req) => {
    // Get the token from the request cookies
    const token = req.cookies.token;
    // console.log(token); // Log the token for debugging

    // If token is not present, return an unauthorized response
    if (!token) {
        return {
            status: 401,  // HTTP status code for unauthorized
            message: "Invalid Token" // Message indicating token is missing or invalid
        };
    }

    // Verify the token using the secret key and decode the payload
    const decoded = jwt.verify(token, JWT_SECRET);

    // Find the user in the database whose ID matches the decoded token's ID
    const user = users.find((user) => user.id === decoded.id);

    // If the user is not found, return a not found response
    if (!user) {
        return {
            status: 404,  // HTTP status code for not found
            message: "User Not found" // Message indicating no user matches the token's ID
        };
    }

    // If the token is valid and user is found, return a success response with the user data
    return {
        status: 200,  // HTTP status code for success
        message: "Success",
        data: {user} // Return the user data
    };
};

/**
 * Function to process dashboard filters, ensuring the values for 'IN' operators are arrays
 * @param {Array} dashboards - Array of dashboard objects containing filters
 */
export const processDashboardFilters = (dashboards) => {
    dashboards.forEach((dashboard) => { // Iterate over each dashboard
        dashboard.filter.forEach((filter) => { // Iterate over each filter in the dashboard
            // If the filter operator is 'IN' and values is not an array, convert it to an array
            if (filter.operator === 'IN' && !Array.isArray(filter.values)) {
                filter.values = [filter.values]; // Wrap the single value in an array
            }
        });
    });
};