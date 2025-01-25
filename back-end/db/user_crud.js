import express from 'express';
import bcrypt from 'bcryptjs';
import {verifyToken, processDashboardFilters} from '../helpers.js';
import db from './db.js';
import {v4 as uuidv4} from 'uuid';

// Create a router for handling user-related routes
const router = express.Router();

// Add a new user **Create**
router.post('/api/users', async (req, res) => {
    const {username, email, mappingValue, password, dashboards} = req.body;

    // Ensure filter values in dashboards are arrays for the "IN" operator
    processDashboardFilters(dashboards);

    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password

    try {
        const newUser = {
            id: uuidv4(), // Generate a unique ID for the new user
            username,
            email,
            mappingValue,
            dashboards,
            password: hashedPassword, // Store the hashed password
        };

        db.data.users.push(newUser); // Add the new user to the database
        await db.write(); // Persist changes to the database

        res.status(201).json(newUser); // Respond with the newly created user
    } catch (err) {
        console.error(err); // Log any errors
        res.status(500).json({message: 'Error adding user'}); // Respond with server error
    }
});

// Retrieve all users **Read**
router.get('/api/users', async (req, res) => {
    try {
        let response = await verifyToken(req); // Verify the user token

        if (response.status !== 200) {
            return res.status(response.status).json({message: response.message}); // Handle invalid token
        }

        let user = response.data.user;

        // Only allow admin users to access the users list
        if (user && user.isAdmin === false) {
            return res.status(403).json({message: 'Unauthorized: Only Admins can access this page'});
        }

        const {users} = db.data; // Get users from the database
        res.json(users); // Respond with the list of users
    } catch (err) {
        res.status(500).json({message: err.message}); // Respond with server error
    }
});

// Update an existing user **Update**
router.put('/api/users/:id', async (req, res) => {
    const {id} = req.params; // Extract the user ID from request parameters
    const {username, email, mappingValue, dashboards, password, isAdmin} = req.body;

    try {
        processDashboardFilters(dashboards); // Process dashboard filters

        let updateData = {username, email, mappingValue, dashboards, isAdmin};

        // If a new password is provided, hash it before updating
        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }

        // Find the user by ID
        const userIndex = db.data.users.findIndex(user => user.id === id);

        if (userIndex === -1) {
            return res.status(404).json({message: 'User not found'}); // Handle user not found
        }

        // Update user data while retaining existing fields
        db.data.users[userIndex] = {...db.data.users[userIndex], ...updateData};
        await db.write(); // Persist changes to the database

        res.status(200).json(db.data.users[userIndex]); // Respond with the updated user data
    } catch (err) {
        console.error(err); // Log any errors
        res.status(500).json({message: 'Error updating user'}); // Respond with server error
    }
});

// Delete an existing user **Delete**
router.delete('/api/users/:id', async (req, res) => {
    const {id} = req.params; // Extract the user ID from request parameters

    try {
        // Find the user by ID
        const userIndex = db.data.users.findIndex(user => user.id === id);

        if (userIndex === -1) {
            return res.status(404).json({message: 'User not found'}); // Handle user not found
        }

        // Remove the user from the database
        db.data.users.splice(userIndex, 1);
        await db.write(); // Persist changes to the database

        res.status(200).json({message: 'User deleted successfully'}); // Respond with success message
    } catch (err) {
        console.error(err); // Log any errors
        res.status(500).json({message: 'Error deleting user'}); // Respond with server error
    }
});

export default router; // Export the router to be used in other modules