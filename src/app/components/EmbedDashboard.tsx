import React, {useEffect, useState, useRef} from 'react'


// Props interface for the EmbedDashboard component
interface EmbedDashboardProps {
    embedID: string // The ID used to determine the dashboard's mode (read-only or edit)
}

const EmbedDashboard: React.FC<EmbedDashboardProps> = ({embedID}) => {
    // State variables to manage embed URL, token, and potential errors
    const [embedURL, setEmbedURL] = useState<string | null>(null) // URL for embedding the dashboard
    const [embedToken, setEmbedToken] = useState<string | null>(null) // Authentication token for embedding
    const [error, setError] = useState<string | null>(null) // Error messages (if any)
    const iframeRef = useRef<HTMLIFrameElement | null>(null) // Reference to the iframe element

    // Fetch the embed details whenever the embedID changes
    useEffect(() => {
        console.log("useEffect called with embedID:", embedID);
        const fetchEmbedDetails = async () => {
            try {
                // Default endpoint for fetching read-only embed details
                let endpoint = '/api/getEmbedToken'

                // Switch to the edit mode endpoint if embedID is "edit"
                if (embedID === 'edit') {
                    endpoint = '/api/editEmbed'
                }

                // API request to fetch embed details
                const response = await fetch(`http://localhost:3003${endpoint}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({embedID}), // Send the embedID in the request body
                    credentials: 'include', // Include cookies for authentication
                })

                if (!response.ok) {
                    throw new Error(
                        `Failed to fetch embed details: ${response.statusText}` // Error handling for unsuccessful requests
                    )
                }

                const data = await response.json()

                // Handle response differently for edit mode and read-only mode
                if (embedID === 'edit') {
                    setEmbedURL(data) // Use the URL directly for edit mode
                    setEmbedToken(null) // No token required for edit mode
                } else {
                    setEmbedURL(data.embedUrl) // Set URL for embedding
                    setEmbedToken(data.embedToken) // Set token for authentication
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : 'Unknown error') // Handle fetch errors
            }
        }
        // console.log("embedURL: ", embedURL)
        // console.log("embedToken: ", embedToken)
        fetchEmbedDetails()
    }, [embedID])// Run this effect whenever embedID changes

    // Submit the form automatically when embed details are ready (for read-only mode)
    useEffect(() => {

        if (embedID !== 'edit' && embedURL && embedToken) {
            handleFormSubmit()
        }
    }, [embedID, embedURL, embedToken]) // Re-run when embedID, URL, or token changes

    // Helper function to submit a form dynamically for POST-based embedding
    const handleFormSubmit = () => {
        if (iframeRef.current && embedURL && embedToken) {
            const form = document.createElement('form') // Create a new form element
            form.action = embedURL // Set form action to the embed URL
            form.method = 'POST' // Use POST method for the form
            form.target = iframeRef.current.name // Target the iframe
            console.log(embedToken)
            // Create a hidden input for the embed token
            const tokenInput = document.createElement('input')
            tokenInput.type = 'hidden'
            tokenInput.name = 'embedToken' // Input name for the embed token
            tokenInput.value = embedToken

            form.appendChild(tokenInput) // Add token input to the form
            document.body.appendChild(form) // Add form to the DOM temporarily
            form.submit() // Submit the form
            document.body.removeChild(form) // Remove the form after submission
        }
    }

    // Render an error message if any error occurs
    if (error) {
        return <div className="text-red-500">Error: {error}</div>
    }

    // Show a loading message while embed details are being fetched
    if (!embedURL) {
        return <div className="text-black">Loading embed details...</div>
    }

    // Render the dashboard in an iframe
    return (
        <div
            className="dashboard-container"
            style={{width: '100%', height: '100%'}} // Ensure full-width and full-height
        >
            <iframe
                ref={iframeRef} // Assign the iframe reference
                key={embedID} // Change key when embedID changes to force a re-render
                src={embedID === 'edit' ? embedURL : undefined} // Only set src for edit mode
                name="embedFrame" // Name to target in the form submission
                style={{width: '100%', height: '100%', border: 'none'}} // Styling for the iframe
                allow="fullscreen" // Allow fullscreen mode
            />
        </div>
    )
}

export default EmbedDashboard
