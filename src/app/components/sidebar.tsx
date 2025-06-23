import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation' // Next.js router for navigation

// Define the structure of a single dashboard object
interface Dashboard {
  name: string // The name of the dashboard
  embedID: string // The unique identifier for embedding the dashboard
}

// Props for the Sidebar component
interface SidebarProps {
  dashboards: Dashboard[] // Array of dashboards to display in the sidebar
  currentEmbedID: string | null // Current embed ID to highlight the active item
  setCurrentEmbedID: React.Dispatch<React.SetStateAction<string | null>> // Function to update the current embed ID
}

const Sidebar: React.FC<SidebarProps> = ({
  dashboards,
  currentEmbedID,
  setCurrentEmbedID,
}) => {
  const [editVisible, setEditVisible] = useState<boolean>(false)
  const [viewVisible, setViewVisible] = useState<boolean>(false)
  const [isOpen, setIsOpen] = useState(false) // State to control the visibility of the content

  useEffect(() => {
    if (currentEmbedID === 'edit') {
      setEditVisible(true)
      setViewVisible(false)
    } else {
      setEditVisible(false)
      setViewVisible(true)
    }
  }, [currentEmbedID]) // React to changes in the currentEmbedID prop

  const toggleAccordion = () => {
    setIsOpen((prevState) => !prevState) // Toggle the state on click
  }
  const router = useRouter()

  const handleLogout = async () => {
    try {
      const response = await fetch('/api/logout', {
        method: 'POST',
        credentials: 'include',
      }) // Call the backend logout API
      if (response.ok) {
        router.push('/') // Redirect to the login page
      } else {
        console.error('Logout failed')
      }
    } catch (error) {
      console.error('An error occurred during logout:', error)
    }
  }
  const handleModifyUsers = () => {
    setCurrentEmbedID('ManageUser') // Set the state to "ManageUser"
  }

  return (
    <div>
      {/* Logo */}
      <img
        src={
          process.env.NEXT_PUBLIC_LOGO_URL ||
          'https://www.modocorp.co/images/modocorp.png'
        }
        alt="Modocorp Logo" // Alt text for accessibility
        className="h-12"
      />

      {/* Navigation menu */}
      <nav className="flex flex-col w-64 bg-[#ededed] h-screen p-4 space-y-2">
        {dashboards.map((dashboard) => (
          <button
            key={dashboard.embedID}
            onClick={() => setCurrentEmbedID(dashboard.embedID)} // Update the state in Parent
            className={`flex items-center space-x-4 p-3 rounded-lg font-bold transition-colors ${
              currentEmbedID === dashboard.embedID
                ? 'bg-[#FC8A3E] text-white'
                : 'bg-[#DCDCDC] text-black'
            }`}
          >
            <span className="font-medium">{dashboard.name}</span>
          </button>
        ))}

        {/* Border Line */}
        <hr className="border-t border-gray-400 my-8 w-[90%] mx-auto" />

        {viewVisible && (
          <div className="nav-message">
            <div className="accordion">
              {/* Accordion Header */}
              <div
                className={`flex items-center justify-between p-4 rounded-lg cursor-pointer transition-colors ${
                  isOpen ? 'bg-[#FC8A3E] text-white' : 'bg-[#F5F5F5] text-black'
                }`}
                onClick={toggleAccordion}
              >
                <div className="flex items-center">
                  <div
                    className={`mr-3 flex items-center justify-center w-8 h-8 rounded-full text-lg font-bold transition-colors ${
                      isOpen
                        ? 'bg-white text-[#FC8A3E]'
                        : 'bg-gray-300 text-black'
                    }`}
                  >
                    ?
                  </div>
                  How does this work?
                </div>
                <span
                  className={`transition-transform ${
                    isOpen ? 'rotate-180' : ''
                  }`}
                >
                  ▼
                </span>
              </div>

              {/* Accordion Content */}
              {isOpen && (
                <div className="content bg-white border border-gray-200 rounded-b-lg shadow-md p-4 text-black">
                  <div className="header mb-2 text-lg font-semibold text-gray-800">
                    Details
                  </div>
                  <ul className="list-disc pl-6 space-y-2">
                    <li>
                      This is a view-only experience. End users do not need a
                      Domo account.
                    </li>
                    <li>
                      Domo authentication is handled on the back end with a
                      client ID + Secret.
                    </li>
                    <li>
                      Data is securely filtered based on rules defined within
                      the hosting application
                    </li>
                    <li>
                      <a
                        href="https://developer.domo.com/portal/ed061f0c295c0-embedded-capabilities"
                        className="text-blue-500 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Learn more
                      </a>
                    </li>
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}
        {editVisible && (
          <div className="nav-message ">
            <div className="accordion">
              {/* Accordion Header */}
              <div
                className={`flex items-center justify-between p-4 rounded-lg cursor-pointer transition-colors ${
                  isOpen ? 'bg-[#FC8A3E] text-white' : 'bg-[#F5F5F5] text-black'
                }`}
                onClick={toggleAccordion}
              >
                <div className="flex items-center">
                  <div
                    className={`mr-3 flex items-center justify-center w-8 h-8 rounded-full text-lg font-bold transition-colors ${
                      isOpen
                        ? 'bg-white text-[#FC8A3E]'
                        : 'bg-gray-300 text-black'
                    }`}
                  >
                    ?
                  </div>
                  How does this work?
                </div>
                <span
                  className={`transition-transform ${
                    isOpen ? 'rotate-90' : ''
                  }`}
                >
                  ▶
                </span>
              </div>

              {/* Accordion Content */}
              {isOpen && (
                <div className="content bg-white border border-gray-200 rounded-b-lg shadow-md p-4 text-black">
                  <div className="header mb-2 text-lg font-semibold text-gray-800">
                    Details
                  </div>
                  <ul className="list-disc pl-6 space-y-2">
                    <li>
                      Each customer is provided with a subscriber instance.
                    </li>
                    <li>Authentication is managed using a JWT token.</li>
                    <li>
                      Domo's identity broker maps the individual to that
                      instance.
                    </li>
                    <li>
                      Data is filtered based on the Publication rules defined in
                      Domo.
                    </li>
                    <li>
                      <a
                        href="https://developer.domo.com/portal/ed061f0c295c0-embedded-capabilities"
                        className="text-blue-500 hover:underline"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Learn more
                      </a>
                    </li>
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}
        <button
          onClick={handleModifyUsers}
          className="mt-auto mb-10 bg-[#FC8A3E] text-white py-2 px-4 rounded-lg font-bold hover:bg-[#e6782e] transition-transform absolute bottom-16 left-1 w-64 p-4 space-y-2"
        >
          Manage Users
        </button>
        {/* Logout Button */}
        <button
          onClick={handleLogout}
          className="mt-auto mb-10 bg-[#FC8A3E] text-white py-2 px-4 rounded-lg font-bold hover:bg-[#e6782e] transition-transform absolute bottom-3 left-1 w-64 p-4 space-y-2"
        >
          Logout
        </button>
      </nav>
    </div>
  )
}

export default Sidebar
