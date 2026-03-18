import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'

interface Dashboard {
  name: string
  embedID: string
}

interface SidebarProps {
  dashboards: Dashboard[]
  currentEmbedID: string | null
  setCurrentEmbedID: React.Dispatch<React.SetStateAction<string | null>>
}

const Sidebar: React.FC<SidebarProps> = ({
  dashboards,
  currentEmbedID,
  setCurrentEmbedID,
}) => {
  const [editVisible, setEditVisible] = useState<boolean>(false)
  const [viewVisible, setViewVisible] = useState<boolean>(false)
  const [isOpen, setIsOpen] = useState(false)

  useEffect(() => {
    if (currentEmbedID === 'edit') {
      setEditVisible(true)
      setViewVisible(false)
    } else {
      setEditVisible(false)
      setViewVisible(true)
    }
  }, [currentEmbedID])

  const toggleAccordion = () => {
    setIsOpen((prevState) => !prevState)
  }
  const router = useRouter()

  const handleLogout = async () => {
    try {
      const response = await fetch('/api/logout', {
        method: 'POST',
        credentials: 'include',
      })
      if (response.ok) {
        router.push('/')
      } else {
        console.error('Logout failed')
      }
    } catch (error) {
      console.error('An error occurred during logout:', error)
    }
  }
  const handleModifyUsers = () => {
    setCurrentEmbedID('ManageUser')
  }

  return (
    <div className="flex flex-col h-full">
      {/* G&A Partners Logo */}
      <div className="flex items-center px-4 py-3">
        <svg viewBox="0 0 200 50" className="h-10" xmlns="http://www.w3.org/2000/svg">
          <text x="0" y="35" fontFamily="Arial, Helvetica, sans-serif" fontSize="28" fontWeight="bold" fill="#C8102E">G&amp;A</text>
          <text x="76" y="35" fontFamily="Arial, Helvetica, sans-serif" fontSize="15" fontWeight="normal" fill="#555555"> Partners</text>
        </svg>
      </div>

      <nav className="flex flex-col w-64 bg-white h-full p-4 space-y-2 border-r border-ga-gray-light">
        {dashboards.map((dashboard) => (
          <button
            key={dashboard.embedID}
            onClick={() => setCurrentEmbedID(dashboard.embedID)}
            className={`flex items-center space-x-4 p-3 rounded-lg font-bold transition-colors ${
              currentEmbedID === dashboard.embedID
                ? 'bg-ga-red text-white'
                : 'bg-ga-gray-light text-ga-charcoal hover:bg-gray-200'
            }`}
          >
            <span className="font-medium">{dashboard.name}</span>
          </button>
        ))}

        <hr className="border-t border-ga-gray-light my-8 w-[90%] mx-auto" />

        {viewVisible && (
          <div className="nav-message">
            <div className="accordion">
              <div
                className={`flex items-center justify-between p-4 rounded-lg cursor-pointer transition-colors ${
                  isOpen ? 'bg-ga-red text-white' : 'bg-gray-100 text-ga-charcoal'
                }`}
                onClick={toggleAccordion}
              >
                <div className="flex items-center">
                  <div
                    className={`mr-3 flex items-center justify-center w-8 h-8 rounded-full text-lg font-bold transition-colors ${
                      isOpen
                        ? 'bg-white text-ga-red'
                        : 'bg-gray-300 text-ga-charcoal'
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

              {isOpen && (
                <div className="content bg-white border border-gray-200 rounded-b-lg shadow-md p-4 text-ga-charcoal">
                  <div className="header mb-2 text-lg font-semibold text-ga-charcoal">
                    Details
                  </div>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
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
                        className="text-ga-red hover:underline"
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
          <div className="nav-message">
            <div className="accordion">
              <div
                className={`flex items-center justify-between p-4 rounded-lg cursor-pointer transition-colors ${
                  isOpen ? 'bg-ga-red text-white' : 'bg-gray-100 text-ga-charcoal'
                }`}
                onClick={toggleAccordion}
              >
                <div className="flex items-center">
                  <div
                    className={`mr-3 flex items-center justify-center w-8 h-8 rounded-full text-lg font-bold transition-colors ${
                      isOpen
                        ? 'bg-white text-ga-red'
                        : 'bg-gray-300 text-ga-charcoal'
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

              {isOpen && (
                <div className="content bg-white border border-gray-200 rounded-b-lg shadow-md p-4 text-ga-charcoal">
                  <div className="header mb-2 text-lg font-semibold text-ga-charcoal">
                    Details
                  </div>
                  <ul className="list-disc pl-6 space-y-2 text-sm">
                    <li>
                      Each customer is provided with a subscriber instance.
                    </li>
                    <li>Authentication is managed using a JWT token.</li>
                    <li>
                      Domo&apos;s identity broker maps the individual to that
                      instance.
                    </li>
                    <li>
                      Data is filtered based on the Publication rules defined in
                      Domo.
                    </li>
                    <li>
                      <a
                        href="https://developer.domo.com/portal/ed061f0c295c0-embedded-capabilities"
                        className="text-ga-red hover:underline"
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
          className="mt-auto mb-10 bg-ga-red text-white py-2 px-4 rounded-lg font-bold hover:bg-ga-red-dark transition-colors absolute bottom-16 left-1 w-64 p-4 space-y-2"
        >
          Manage Users
        </button>
        <button
          onClick={handleLogout}
          className="mt-auto mb-10 bg-ga-charcoal text-white py-2 px-4 rounded-lg font-bold hover:bg-gray-700 transition-colors absolute bottom-3 left-1 w-64 p-4 space-y-2"
        >
          Logout
        </button>
      </nav>
    </div>
  )
}

export default Sidebar
