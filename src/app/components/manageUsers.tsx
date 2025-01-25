'use client' // Enable React's client-side rendering for Next.js

// Import required dependencies
import React, {useState, useEffect} from 'react'
import {omit} from 'lodash' // Import Lodash's omit function for object manipulation

// Define the Filter interface to structure dashboard filters
interface Filter {
    column: string // Column name for the filter
    operator: string // Operator used for filtering (e.g., IN, EQUALS)
    values: string | number | string[] // Allowed values: string, number, or array of strings
}

// Define the Dashboard interface to structure user dashboards
interface Dashboard {
    embedID: string // Unique identifier for the embedded dashboard
    name: string // Dashboard name
    filter: Filter[] // Array of filters applied to the dashboard
}

// Define the User interface to structure user data
interface User {
    id: string // Unique user ID
    username: string // Username
    email: string // User email
    mappingValue: string // Value used for mapping (custom business logic)
    password?: string // Optional password field
    dashboards: Dashboard[] // Array of dashboards assigned to the user
    isAdmin: boolean // Admin status flag
}

// List of operator options for filtering dashboards
const operatorOptions = [
    'IN',
    'NOT_IN',
    'EQUALS',
    'NOT_EQUALS',
    'GREATER_THAN',
    'GREATER_THAN_EQUALS_TO',
    'LESS_THAN',
    'LESS_THAN_EQUALS_TO',
]

// Main component for managing users
const ManageUsers = () => {
    // State to store the list of users
    const [users, setUsers] = useState<User[]>([])

    // State to track the ID of the user being edited
    const [editingUserId, setEditingUserId] = useState<string | null>(null)

    // States to toggle edit and create modes
    const [editMode, setEditMode] = useState(false)
    const [createMode, setCreateMode] = useState(false)

    // States to handle user deletion modal and target user
    const [showDeleteModal, setShowDeleteModal] = useState(false)
    const [userToDelete, setUserToDelete] = useState<string | null>(null)

    // State to store the user data being edited
    const [editUserData, setEditUserData] = useState<User>({
        id: '',
        username: '',
        email: '',
        mappingValue: '',
        password: '',
        dashboards: [],
        isAdmin: false,
    })

    // State to store the original user data for cancellation purposes
    const [originalUserData, setOriginalUserData] = useState<User>({
        id: '',
        username: '',
        email: '',
        mappingValue: '',
        password: '',
        dashboards: [],
        isAdmin: false,
    })

    // Fetch users from the backend when the component mounts
    useEffect(() => {
        const fetchUsers = async () => {
            const response = await fetch(`http://localhost:3003/api/users`, {
                method: 'GET',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include', // Include credentials for authentication
            })

            if (response.ok) {
                const data: User[] = await response.json()
                setUsers(data) // Set the fetched users in state
            } else {
                console.error('Failed to fetch users') // Log error if the request fails
            }
        }
        fetchUsers()
    }, [])

    // Enable edit mode for a specific user
    const handleEditMode = (user: User) => {
        setEditMode(true)
        setEditingUserId(user.id)

        // Remove the password field from the user object before editing
        const userWithoutPassword = omit(user, 'password')
        setOriginalUserData({...userWithoutPassword}) // Store the original data
        setEditUserData({...userWithoutPassword}) // Set the data for editing
    }

    // Handle changes to dashboard fields during editing
    const handleDashboardChange = (
        index: number,
        field: string,
        value: string
    ) => {
        const updatedDashboards = [...editUserData.dashboards]
        updatedDashboards[index] = {...updatedDashboards[index], [field]: value}
        setEditUserData((prevData) => ({
            ...prevData,
            dashboards: updatedDashboards,
        }))
    }

    // Handle changes to dashboard filters during editing
    const handleFilterChange = (
        dashboardIndex: number,
        filterIndex: number,
        field: string,
        value: string
    ) => {
        const updatedDashboards = [...editUserData.dashboards]
        updatedDashboards[dashboardIndex].filter[filterIndex] = {
            ...updatedDashboards[dashboardIndex].filter[filterIndex],
            [field]: value,
        }
        setEditUserData((prevData) => ({
            ...prevData,
            dashboards: updatedDashboards,
        }))
    }

    // Add a new dashboard to the user's data
    const handleAddDashboard = () => {
        setEditUserData((prevData) => ({
            ...prevData,
            dashboards: [
                ...prevData.dashboards,
                {embedID: '', name: '', filter: []},
            ],
        }))
    }

    // Remove a dashboard from the user's data
    const handleRemoveDashboard = (index: number) => {
        const updatedDashboards = editUserData.dashboards.filter(
            (_, i) => i !== index
        )
        setEditUserData((prevData) => ({
            ...prevData,
            dashboards: updatedDashboards,
        }))
    }

    // Add a new filter to a specific dashboard
    const handleAddFilter = (dashboardIndex: number) => {
        const updatedDashboards = [...editUserData.dashboards]
        updatedDashboards[dashboardIndex].filter.push({
            column: '',
            operator: 'IN',
            values: '',
        })
        setEditUserData((prevData) => ({
            ...prevData,
            dashboards: updatedDashboards,
        }))
    }

    // Remove a filter from a specific dashboard
    const handleRemoveFilter = (dashboardIndex: number, filterIndex: number) => {
        const updatedDashboards = [...editUserData.dashboards]
        updatedDashboards[dashboardIndex].filter.splice(filterIndex, 1)
        setEditUserData((prevData) => ({
            ...prevData,
            dashboards: updatedDashboards,
        }))
    }

    // Update the user data by sending a PUT request to the backend
    const handleUpdateUser = async () => {
        console.log('Updated User Data:', editUserData) // Log the updated data for debugging

        const response = await fetch(
            `http://localhost:3003/api/users/${editUserData.id}`,
            {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(editUserData),
            }
        )

        if (response.ok) {
            const updatedUser: User = await response.json()
            setUsers((prevUsers) =>
                prevUsers.map((user) =>
                    user.id === updatedUser.id ? updatedUser : user
                )
            )
            setEditingUserId(null) // Exit edit mode after updating
            setEditUserData({
                id: '',
                username: '',
                email: '',
                mappingValue: '',
                password: '',
                dashboards: [],
                isAdmin: false,
            })
        } else {
            console.error('Failed to update user') // Log error if the update fails
        }
    }

    // Create a new user by sending a POST request to the backend
    const handleCreateUser = async () => {
        console.log('Creating User Data:', editUserData) // Log the data for debugging

        const response = await fetch('http://localhost:3003/api/users', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(editUserData),
        })

        if (response.ok) {
            const newUser: User = await response.json()
            setUsers((prevUsers) => [...prevUsers, newUser]) // Add the new user to the list
            setCreateMode(false) // Exit create mode
        } else {
            console.error('Failed to create user') // Log error if the creation fails
        }
    }

    // Cancel editing or creating a user
    const handleCancelEdit = () => {
        setEditUserData(originalUserData) // Reset to original data
        setEditingUserId(null) // Clear the editing user ID
        setEditMode(false) // Exit edit mode
        setCreateMode(false) // Exit create mode
    }

    // Prepare to add a new user (enter create mode)
    const handleAddUser = () => {
        setEditingUserId(null) // Ensure no user is being edited
        setEditUserData({
            id: '',
            username: '',
            email: '',
            mappingValue: '',
            password: '',
            dashboards: [{embedID: '', name: '', filter: []}],
            isAdmin: false,
        })
        setCreateMode(true)
    }

    // Handle delete button click to show confirmation modal
    const handleDeleteClick = (userId: string) => {
        setUserToDelete(userId) // Store the target user ID
        setShowDeleteModal(true) // Show delete modal
    }

    // Confirm and execute user deletion
    const confirmDeleteUser = async () => {
        if (userToDelete) {
            const response = await fetch(
                `http://localhost:3003/api/users/${userToDelete}`,
                {method: 'DELETE'}
            )

            if (response.ok) {
                setUsers((prevUsers) =>
                    prevUsers.filter((user) => user.id !== userToDelete)
                ) // Remove the user
                setShowDeleteModal(false) // Close delete modal
                setUserToDelete(null) // Clear the target user ID
            } else {
                console.error('Failed to delete user') // Log error if the deletion fails
            }
        }
    }
    // Cancel user deletion
    const cancelDeleteUser = () => {
        setShowDeleteModal(false) // Hide delete modal
        setUserToDelete(null) // Clear the target user ID
    }

    return (
        // Main container with padding, background color, height, and width
        <div className="p-8 bg-[#F9F9F9] h-dvh pb-20 w-full">
            {/* Title */}
            <h1 className="text-4xl font-semibold mb-6 text-gray-900">Users List</h1>

            {/* Button to trigger user creation */}
            <button
                onClick={handleAddUser} // Handle user creation
                className="bg-blue-500 text-white py-2 px-6 rounded-full shadow-md mb-6 hover:bg-blue-600 transition-colors"
            >
                Create User
            </button>

            {/* Displaying list of users */}
            <div className="space-y-4">
                {users.map((user) => (
                    <div
                        key={user.id} // Unique key for each user
                        className="bg-white rounded-lg shadow-lg p-6 mb-4 border border-gray-200"
                    >
                        <div className="flex flex-col space-y-2">
                            {/* Displaying user information */}
                            <div className="text-xl font-semibold text-black">
                                {user.username}
                            </div>
                            <div className="text-sm text-gray-600">{user.email}</div>
                            <div className="text-sm text-gray-600">
                                Mapping Value: {user.mappingValue}
                            </div>

                            {/* Buttons for editing and deleting a user */}
                            <div className="flex space-x-4 mt-2">
                                <button
                                    className="text-blue-500 hover:text-blue-700 transition-colors"
                                    onClick={() => handleEditMode(user)} // Handle editing user
                                >
                                    Edit
                                </button>
                                <button
                                    className="text-red-500 hover:text-red-700 transition-colors"
                                    onClick={() => handleDeleteClick(user.id)} // Handle user deletion
                                >
                                    Delete
                                </button>
                            </div>
                        </div>
                    </div>
                ))}
            </div>

            {/* Modal for confirming deletion */}
            {showDeleteModal && (
                <div className="fixed inset-0 bg-gray-500 bg-opacity-50 flex justify-center items-center z-50">
                    <div className="bg-white p-8 rounded-lg shadow-xl w-[30%]">
                        <h2 className="text-2xl font-semibold mb-4 text-gray-800">
                            Confirm Deletion
                        </h2>
                        <p className="mb-6 text-gray-600">
                            Are you sure you want to delete this user?
                        </p>
                        <div className="flex justify-end gap-4">
                            <button
                                onClick={cancelDeleteUser} // Handle canceling deletion
                                className="bg-gray-400 text-white py-2 px-6 rounded-full hover:bg-gray-500 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={confirmDeleteUser} // Confirm the deletion
                                className="bg-red-500 text-white py-2 px-6 rounded-full hover:bg-red-600 transition-colors"
                            >
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Modal for editing or creating a user */}
            {(editingUserId || createMode) && (
                <div className="fixed inset-0 bg-gray-500 bg-opacity-50 flex justify-center items-center z-50">
                    <div
                        className="bg-white p-8 rounded-lg shadow-xl w-[50%] max-h-[80vh] overflow-y-auto flex flex-col">
                        <h2 className="text-3xl font-semibold mb-6 text-gray-800">
                            {createMode ? 'Create User' : 'Edit User'}
                        </h2>

                        {/* Input fields for editing/creating user */}
                        <div className="mb-6">
                            <label className="block text-lg font-medium mb-2 text-gray-600">
                                Username
                            </label>
                            <input
                                type="text"
                                value={editUserData.username} // Controlled input for username
                                onChange={(e) =>
                                    setEditUserData({
                                        ...editUserData,
                                        username: e.target.value, // Update username on change
                                    })
                                }
                                className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                            />
                        </div>
                        <div className="mb-6">
                            <label className="block text-lg font-medium mb-2 text-gray-600">
                                Email
                            </label>
                            <input
                                type="email"
                                value={editUserData.email} // Controlled input for email
                                onChange={(e) =>
                                    setEditUserData({
                                        ...editUserData,
                                        email: e.target.value, // Update email on change
                                    })
                                }
                                className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                            />
                        </div>

                        {/* Input for mapping value */}
                        <div className="mb-6">
                            <label className="block text-lg font-medium mb-2 text-gray-600">
                                Mapping Value
                                <span
                                    className="ml-2 text-blue-500 cursor-pointer bg-gray-200 rounded-full p-1 relative group">
                  ?
                  <span
                      className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 w-64 p-2 bg-gray-800 text-white text-sm rounded-lg opacity-0 group-hover:opacity-100 transition-opacity">
                    This is the mapping attribute for what instance the user is
                    directed to. For more information, visit the documentation.
                    <a
                        href="https://domo-support.domo.com/s/article/6523741250455?language=en_US#mapping"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block mt-1 text-blue-400 underline"
                    >
                      Learn more
                    </a>
                  </span>
                </span>
                            </label>
                            <input
                                type="text"
                                value={editUserData.mappingValue} // Controlled input for mapping value
                                onChange={(e) =>
                                    setEditUserData({
                                        ...editUserData,
                                        mappingValue: e.target.value, // Update mapping value on change
                                    })
                                }
                                className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                            />
                        </div>

                        {/* Input for password */}
                        <div className="mb-6">
                            <label className="block text-lg font-medium mb-2 text-gray-600">
                                Password
                            </label>
                            <input
                                type="password"
                                onChange={(e) => {
                                    const newPassword = e.target.value
                                    setEditUserData({
                                        ...editUserData,
                                        password: newPassword.trim()
                                            ? newPassword
                                            : editUserData.password, // Update password only if it has value
                                    })
                                }}
                                placeholder="Enter password"
                                className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                            />
                        </div>

                        {/* Section for managing dashboards */}
                        <h3 className="text-xl font-medium mt-6 text-gray-800">
                            Manage Dashboards
                        </h3>
                        <div className="space-y-4 mt-4">
                            {editUserData.dashboards.map((dashboard, index) => (
                                <div
                                    key={index}
                                    className="bg-gray-100 rounded-lg p-6 mb-4 border border-gray-300"
                                >
                                    <div className="flex justify-between items-center">
                                        <div className="text-lg font-medium text-black">
                                            Dashboard Name:
                                        </div>
                                        <input
                                            type="text"
                                            value={dashboard.name} // Controlled input for dashboard name
                                            onChange={
                                                (e) =>
                                                    handleDashboardChange(index, 'name', e.target.value) // Update dashboard name on change
                                            }
                                            className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                                        />
                                    </div>

                                    {/* Input for embed ID */}
                                    <div className="mt-4 flex items-center">
                                        <div className="text-lg font-medium text-black">
                                            Embed ID:
                                        </div>
                                        <input
                                            type="text"
                                            value={dashboard.embedID} // Controlled input for embed ID
                                            onChange={
                                                (e) =>
                                                    handleDashboardChange(
                                                        index,
                                                        'embedID',
                                                        e.target.value
                                                    ) // Update embed ID on change
                                            }
                                            className="ml-4 w-[60%] p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                                        />
                                    </div>

                                    {/* Filters management */}
                                    <div className="mt-4 space-y-2">
                                        <h4 className="text-lg text-gray-700">Filters</h4>
                                        {dashboard.filter.map((filter, filterIndex) => (
                                            <div
                                                key={filterIndex}
                                                className="flex justify-between items-center space-x-4"
                                            >
                                                <input
                                                    type="text"
                                                    placeholder="Column"
                                                    value={filter.column} // Controlled input for column filter
                                                    onChange={
                                                        (e) =>
                                                            handleFilterChange(
                                                                index,
                                                                filterIndex,
                                                                'column',
                                                                e.target.value
                                                            ) // Update column filter on change
                                                    }
                                                    className="w-[30%] p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                                                />
                                                <select
                                                    value={filter.operator} // Controlled select for operator filter
                                                    onChange={
                                                        (e) =>
                                                            handleFilterChange(
                                                                index,
                                                                filterIndex,
                                                                'operator',
                                                                e.target.value
                                                            ) // Update operator filter on change
                                                    }
                                                    className="w-[30%] p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                                                >
                                                    {operatorOptions.map((operator) => (
                                                        <option key={operator} value={operator}>
                                                            {operator}
                                                        </option>
                                                    ))}
                                                </select>
                                                <input
                                                    type="text"
                                                    placeholder="Values"
                                                    value={filter.values} // Controlled input for filter values
                                                    onChange={
                                                        (e) =>
                                                            handleFilterChange(
                                                                index,
                                                                filterIndex,
                                                                'values',
                                                                e.target.value
                                                            ) // Update filter values on change
                                                    }
                                                    className="w-[30%] p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-black"
                                                />
                                                <button
                                                    onClick={() => handleRemoveFilter(index, filterIndex)} // Remove filter
                                                    className="text-red-500 hover:text-red-700"
                                                >
                                                    Remove Filter
                                                </button>
                                            </div>
                                        ))}
                                        <button
                                            onClick={() => handleAddFilter(index)} // Add new filter
                                            className="bg-blue-500 text-white py-2 px-4 rounded-full mt-4 hover:bg-blue-600 transition-colors"
                                        >
                                            Add Filter
                                        </button>
                                    </div>

                                    {/* Button to remove dashboard */}
                                    <div className="mt-4">
                                        <button
                                            onClick={() => handleRemoveDashboard(index)} // Remove dashboard
                                            className="text-red-500 hover:text-red-700"
                                        >
                                            Remove Dashboard
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Button to add new dashboard */}
                        <button
                            onClick={handleAddDashboard} // Handle adding new dashboard
                            className="bg-blue-500 text-white py-2 px-4 rounded-full mt-4 hover:bg-blue-600 transition-colors"
                        >
                            Add Dashboard
                        </button>

                        {/* Buttons for canceling or saving changes */}
                        <div className="flex justify-end gap-4 mt-6 sticky bottom-0 right-0 mb-6 mr-6">
                            <button
                                onClick={handleCancelEdit} // Handle canceling user edit
                                className="bg-gray-400 text-white py-2 px-6 rounded-full hover:bg-gray-500 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={createMode ? handleCreateUser : handleUpdateUser} // Handle user creation or update
                                className="bg-blue-500 text-white py-2 px-6 rounded-full hover:bg-blue-600 transition-colors"
                            >
                                {createMode ? 'Create' : 'Save'}{' '}
                                {/* Show appropriate button text */}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}

export default ManageUsers
