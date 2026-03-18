'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import '../app/globals.css'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  const router = useRouter()

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch('/api/dashboards', {
          credentials: 'include',
        })

        if (response.ok) {
          router.push('/home')
        }
      } catch (error) {
        console.error('Auth check failed:', error)
      }
    }

    checkAuth()
  }, [router])

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setIsLoading(true)
    if (!username || !password) {
      setError('Both fields are required.')
      setIsLoading(false)
      return
    }
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
        credentials: 'include',
      })

      const data = await response.json()

      if (response.ok) {
        console.log('Login successful:', data)
        router.push('/home')
      } else {
        setError(data.message)
      }
    } catch (err) {
      console.error('Error logging in:', err)
      setError('An error occurred during login.')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="flex flex-col justify-center items-center min-h-screen bg-[#F4F4F4]">
      <div className="bg-white rounded-lg shadow-lg w-full max-w-md p-10">
        {/* G&A Partners Logo */}
        <div className="flex justify-center mb-6">
          <svg
            viewBox="0 0 200 50"
            className="h-12"
            xmlns="http://www.w3.org/2000/svg"
          >
            <text
              x="0"
              y="35"
              fontFamily="Arial, Helvetica, sans-serif"
              fontSize="30"
              fontWeight="bold"
              fill="#C8102E"
            >
              G&amp;A
            </text>
            <text
              x="82"
              y="35"
              fontFamily="Arial, Helvetica, sans-serif"
              fontSize="16"
              fontWeight="normal"
              fill="#555555"
            >
              {' '}
              Partners
            </text>
          </svg>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="mb-5">
            <label
              htmlFor="username"
              className="block text-sm font-medium text-ga-gray-dark mb-1"
            >
              EMAIL
            </label>
            <input
              name="username"
              autoComplete="off"
              id="username"
              type="text"
              placeholder=""
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="block w-full px-3 py-2.5 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-ga-red focus:border-transparent text-black"
            />
          </div>

          <div className="mb-2">
            <label
              htmlFor="password"
              className="block text-sm font-medium text-ga-gray-dark mb-1"
            >
              PASSWORD
            </label>
            <input
              name="password"
              id="password"
              type="password"
              placeholder=""
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="block w-full px-3 py-2.5 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-ga-red focus:border-transparent text-black"
            />
          </div>

          {/* Utility Links */}
          <div className="flex justify-between mb-6 text-sm">
            <span className="text-ga-red cursor-pointer hover:underline">
              Forgot Password?
            </span>
            <span className="text-ga-red cursor-pointer hover:underline">
              Forgot Email/Change Email
            </span>
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-2 rounded mb-4 text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2.5 bg-ga-red text-white font-semibold rounded hover:bg-ga-red-dark cursor-pointer transition-colors disabled:opacity-60"
          >
            {isLoading ? 'Loading...' : 'Next'}
          </button>
        </form>

        {/* Bottom Link */}
        <p className="text-center text-sm text-ga-gray-dark mt-6">
          Don&apos;t have an account?{' '}
          <span className="text-ga-red cursor-pointer hover:underline">
            Create an account
          </span>
        </p>

        {/* Language Selector */}
        <div className="flex justify-center gap-4 mt-4 text-sm">
          <span className="text-ga-charcoal font-medium cursor-pointer hover:underline">
            English
          </span>
          <span className="text-ga-gray cursor-pointer hover:underline">
            Espa&ntilde;ol
          </span>
        </div>
      </div>

      {/* Security Note */}
      <p className="text-xs text-ga-gray mt-6 max-w-md text-center">
        * For security purposes, do not save your log in information on a shared
        computer.
      </p>
    </div>
  )
}
