// Enable React's client-side rendering
'use client'

// Import necessary dependencies
import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation' // Next.js router for navigation
import '../app/globals.css' // Import global styles

// Main Home component
export default function Login() {
  // State variables for storing user input and error messages
  const [username, setUsername] = useState('') // Stores the entered username
  const [password, setPassword] = useState('') // Stores the entered password
  const [error, setError] = useState('') // Stores error messages, if any
  const [isLoading, setIsLoading] = useState(false) //creates feedback on form submit

  // Initialize the Next.js router for navigation
  const router = useRouter()

  // Check for existing token cookie on component mount
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch('/api/dashboards', {
          credentials: 'include', // Include cookies in the request
        })

        if (response.ok) {
          // If we can access the dashboards endpoint, we're authenticated
          router.push('/home')
        }
      } catch (error) {
        console.error('Auth check failed:', error)
      }
    }

    checkAuth()
  }, [router])

  // Handle form submission
  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault() // Prevent the default form submission behavior
    setIsLoading(true)
    if (!username || !password) {
      setError('Both fields are required.')
      setIsLoading(false)
      return
    }
    try {
      // Make a POST request to the login API
      const response = await fetch('/api/login', {
        method: 'POST', // HTTP method
        headers: {
          'Content-Type': 'application/json', // Set the content type to JSON
        },
        body: JSON.stringify({ username, password }), // Send username and password in the request body
        credentials: 'include', // Include cookies in the request for authentication
      })

      // Parse the response JSON
      const data = await response.json()

      if (response.ok) {
        // If the response is successful, log the success message
        console.log('Login successful:', data)

        // Navigate to the '/home' route
        router.push('/home')
      } else {
        // If the response is not successful, display the error message
        setError(data.message)
      }
    } catch (err) {
      // Handle any errors during the request
      console.error('Error logging in:', err)
      setError('An error occurred during login.') // Set a generic error message
    } finally {
      setIsLoading(false)
    }
  }

  // Render the login form
  return (
    <div className="flex bg-[#DCE4EA] flex-col justify-center items-center min-h-screen">
      {/* Display the company logo */}

      <div className="mb-10">
        <img
          src={
            process.env.NEXT_PUBLIC_LOGO_URL ||
            'https://www.modocorp.co/images/modocorp.png'
          }
          alt="Modocorp Logo" // Alt text for accessibility
        />
      </div>
      {/* Login form */}
      <form onSubmit={handleSubmit} className="w-96">
        {/* Username input field */}
        <div className="mb-6">
          <label htmlFor="username" className="block text-gray-700 mb-2">
            Username
          </label>

          <input
            name="username"
            autoComplete="off" // Prevent auto-fill suggestions
            id="username"
            type="text" // Input type: text
            placeholder="Your username" // Placeholder text
            value={username} // Bind input value to state
            onChange={(e) => setUsername(e.target.value)} // Update state on input change
            className="block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring focus:ring-blue-300 text-black"
          />
        </div>

        {/* Password input field */}
        <div className="mb-6">
          <label htmlFor="password" className="block text-gray-700 mb-2">
            Password
          </label>
          <input
            name="password"
            id="password"
            type="password" // Input type: password (masked characters)
            placeholder="Your password" // Placeholder text
            value={password} // Bind input value to state
            onChange={(e) => setPassword(e.target.value)} // Update state on input change
            className="block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring focus:ring-blue-300 text-black"
          />
        </div>

        {/* Error message display */}
        {error && <div className="text-red-500 mb-4">{error}</div>}

        {/* Submit button */}
        <input
          type="submit" // Input type: submit
          value={isLoading ? 'Loading...' : 'Login'}
          className="w-full py-2 bg-[#FF9922] text-white font-semibold rounded-md hover:bg-[#E6891F] cursor-pointer mt-4"
          disabled={isLoading} // Disable button when loading
        />
      </form>
    </div>
  )
}
