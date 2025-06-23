// Enable React client-side rendering
'use client'

// Import necessary dependencies and components
import React, { useEffect, useState } from 'react'
import Sidebar from '../components/sidebar' // Import Sidebar component
import EmbedDashboard from '../components/EmbedDashboard' // Import EmbedDashboard component
import ManageUsers from '../components/manageUsers' // Import Header component

// Define the structure of a Dashboard object
interface Dashboard {
  name: string // Name of the dashboard
  embedID: string // Unique identifier for embedding the dashboard
}

// Main Test component
const Parent: React.FC = () => {
  // State to hold the list of dashboards fetched from the API
  const [dashboards, setDashboards] = useState<Dashboard[]>([])
  // State to hold the current embed ID for the selected dashboard
  const [currentEmbedID, setCurrentEmbedID] = useState<string | null>(null) // Shared state

  // useEffect to fetch dashboards when the component mounts
  useEffect(() => {
    const fetchDashboards = async () => {
      try {
        // Make a request to fetch a list of dashboards the user has access to
        const response = await fetch('/api/dashboards', {
          credentials: 'include', // Include cookies for authentication
        })

        // Check if the response is successful
        if (response.ok) {
          const data = await response.json() // Parse the JSON response
          setDashboards(data.dashboards) // Update the state with fetched dashboards

          // Set the default embed ID to the first dashboard's embedID if available
          if (data.dashboards.length > 0) {
            setCurrentEmbedID(data.dashboards[0].embedID)
          }
        } else {
          console.error('Failed to fetch dashboards') // Log error if the response is not OK
        }
      } catch (error) {
        console.error('Error fetching dashboards:', error) // Log errors during the fetch operation
      }
    }

    fetchDashboards() // Call the fetch function on component mount
  }, []) // Empty dependency array ensures this runs only once

  return (
    <div className="bg-white flex h-dvh p-2">
      {/* Render the Sidebar component, passing necessary props */}
      <Sidebar
        dashboards={dashboards} // Pass the dashboards
        setCurrentEmbedID={setCurrentEmbedID} // Pass the state updater
        currentEmbedID={currentEmbedID} // Pass the current state
      />

      {/*Dynamically render the EmbedDashboard component based on the current embed ID*/}
      {currentEmbedID === 'ManageUser' ? (
        // <ManageUsers/> // Render ManageUsers component
        <ManageUsers />
      ) : (
        currentEmbedID && <EmbedDashboard embedID={currentEmbedID} /> // Render EmbedDashboard component
      )}
    </div>
  )
}

// Export the Test component for use in other parts of the application
export default Parent
