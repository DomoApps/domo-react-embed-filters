// Import required modules
import express from 'express';         // Web framework for building APIs
import cors from 'cors';               // Middleware for enabling CORS
import cookieParser from 'cookie-parser'; // Middleware for parsing cookies
import db from './db/db.js';           // Import LowDB database instance
import userCrudRoutes from './db/user_crud.js'; // Import user CRUD routes

const {users} = db.data;             // Destructure users collection from the database

import dotenv from 'dotenv';           // Library to load environment variables from .env file
dotenv.config();                       // Load environment variables

import bcrypt from 'bcrypt';           // Library for hashing and verifying passwords
import jwt from 'jsonwebtoken';        // Library for creating and verifying JWT tokens
import {verifyToken} from "./helpers.js"; // Helper function to verify JWT tokens
import {handleRequest} from "./embed.js"; // Function to handle embed requests
import {v4 as uuidv4} from "uuid";   // Library to generate unique IDs (UUID)

// Define the secret key for JWT, using an environment variable or a default value
const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecretKey';

// console.log(JWT_SECRET);               // Log the JWT secret key (for debugging purposes)
// console.log(users);                    // Log the users from the database (for debugging purposes)

const app = express();

// Middleware setup
app.use(express.json());               // Parse incoming JSON requests
app.use(cookieParser());               // Parse cookies from incoming requests
app.use(
    cors({
        origin: 'http://localhost:3000', // Allow requests from this origin
        credentials: true,               // Allow credentials (cookies) to be sent
    })
);
app.use('/', userCrudRoutes);          // Use user CRUD routes for the root path

// Login API Endpoint
app.post('/login', async (req, res) => {
    try {
        const {username, password} = req.body; // Extract username and password from request body

        // Check if both username and password are provided
        if (!username || !password) {
            return res.status(400).json({message: 'Username and password are required'}); // Bad request response
        }

        // Find the user by username in the database
        const loggedOnUser = users.find((user) => user.username === username);
        // console.log(loggedOnUser); // Log user details for debugging

        // If user not found, return unauthorized response
        if (!loggedOnUser) {
            return res.status(401).json({message: 'Invalid Credentials'});
        }

        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, loggedOnUser.password);
        if (!isMatch) {
            return res.status(402).json({message: 'Invalid Credentials'});
        }

        // console.log('move on'); // Debugging message

        // Generate a JWT token for the authenticated user
        const token = jwt.sign({id: loggedOnUser.id}, JWT_SECRET, {
            expiresIn: '1h', // Token expires in 1 hour
        });

        // Extract additional user data to include in the response
        const {instance, embedID, dashboards} = loggedOnUser;
        // console.log(instance, embedID, dashboards); // Log user details

        // Set the token as a cookie
        res.cookie('token', token, {
            httpOnly: true, // Prevent access to the cookie via JavaScript
            secure: false,  // Set to true for HTTPS in production
            sameSite: 'lax', // Cookie sent with same-site requests only
            maxAge: 3600000, // Cookie expires in 1 hour
        });

        // Respond with success message and user details
        res.json({message: 'Login successful', instance, embedId: embedID});
    } catch (error) {
        // console.error(error); // Log error for debugging
        res.status(500).json({message: 'Server error', error}); // Internal server error response
    }
});

// Logout API Endpoint
app.post('/api/logout', (req, res) => {
    res.clearCookie('token'); // Clear the token cookie
    res.status(200).json({message: 'Logged out successfully'}); // Respond with success message
});

// Get User Dashboards API Endpoint
app.get('/api/dashboards', async (req, res) => {
    try {
        let response = await verifyToken(req); // Verify the JWT token

        // If token verification fails, return the corresponding error response
        if (response.status !== 200) {
            return res.status(response.status).json({message: response.message});
        }

        let user = response.data.user; // Extract user data from the verified response

        // Extract dashboards and map them to include filter details
        const dashboardsWithFilters = user.dashboards.map((dashboard) => {
            return {
                name: dashboard.name,
                embedID: dashboard.embedID,
                filters: dashboard.filter || [], // Include filters or an empty array if none exist
            };
        });

        res.json({dashboards: dashboardsWithFilters}); // Respond with the dashboards
    } catch (error) {
        console.error('Error fetching dashboards:', error); // Log errors
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({message: 'Invalid token'}); // Handle invalid token
        }
        res.status(500).json({message: 'Server error'}); // Internal server error response
    }
});

// Get Embed Token API Endpoint
app.post('/api/getEmbedToken', async (req, res) => {
    const {embedID} = req.body; // Extract embedID from request body

    // Check if embedID is provided
    if (!embedID) {
        return res.status(400).json({message: 'Embed ID is required'});
    }

    try {
        let response = await verifyToken(req); // Verify the JWT token

        if (response.status !== 200) {
            return res.status(response.status).json({message: response.message});
        }

        let user = response.data.user; // Extract user data from the verified response

        // Find the dashboard corresponding to the provided embedID
        const dashboard = user.dashboards.find((dash) => dash.embedID === embedID);
        if (!dashboard) {
            return res.status(404).json({message: 'Dashboard not found for the given embedID'});
        }

        // Extract and format filters for the embed token request
        const filters = dashboard.filter?.map((filter) => {
            const {column, operator, values} = filter;
            return {column, operator, values};
        }) || [];

        // Configuration object for generating an embed token
        const config = {
            embedId: embedID,
            clientId: process.env.DOMO_CLIENT_ID,
            clientSecret: process.env.DOMO_CLIENT_SECRET,
            accessToken: null,
            accessTokenExpiration: 0,
            embedToken: null,
            embedTokenExpiration: 0,
            filters: filters,
            policies: [],
        };

        handleRequest(req, res, () => {
        }, config); // Call the embed token handler with the config
    } catch (error) {
        console.error('Error fetching embed token:', error); // Log errors
        res.status(500).json({message: 'Failed to fetch embed token', error}); // Internal server error response
    }
});

// Edit Embed API Endpoint
app.post('/api/editEmbed', async (req, res) => {
    const { embedID } = req.body; // Extract embedID from request body
    const token = req.cookies.token; // Extract token from cookies

    try {
        if (!token) {
            return res.status(401).json({ message: 'Unauthorized: Please log in' });
        }
        if (!embedID) {
            return res.status(400).json({ message: 'Missing embedID in the request' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Decode the token to get user ID
        const user = db.data.users.find(user => user.id === decoded.id); // Find user by ID

        // Check if mappingValue contains a comma and convert to list if needed
        let mappingValue = user.mappingValue;
        if (typeof mappingValue === 'string' && mappingValue.includes(',')) {
            mappingValue = mappingValue.split(',').map(item => item.trim()); // Convert to array and trim spaces
        }

        // Create the JWT body for the edit request
        const jwtBody = {
            sub: user.username,
            name: user.username,
            role: 'Admin',
            email: user.email,
            jti: uuidv4(), // Unique identifier for the token
        };
        jwtBody[process.env.KEY_ATTRIBUTE] = mappingValue;

        // console.log(jwtBody); // Log JWT body for debugging

        // Generate an edit token with a 5-minute expiration
        const edit_token = jwt.sign(jwtBody, process.env.JWT_SECRET, {
            expiresIn: '5m',
        });

        // Construct the edit URL with the token
        const editUrl = `${process.env.IDP_URL}/jwt?token=${edit_token}`;

        res.status(200).json(editUrl); // Respond with the edit URL
    } catch (error) {
        console.error('Error in /api/editEmbed:', error); // Log errors
        res.status(500).json({ message: 'Server error occurred' }); // Internal server error response
    }
});

// Handle CORS preflight requests (OPTIONS method)
app.options('/api/editEmbed', (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000'); // Allow your front-end origin
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.sendStatus(204); // Respond with 204 No Content for preflight requests
});
app.options('/api/getEmbedToken', (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000'); // Allow your front-end origin
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.sendStatus(204); // Respond with 204 No Content for preflight requests
});

// Start the server and listen on port 3003
app.listen(3003, () => {
    console.log('Server running on http://localhost:3003');
});