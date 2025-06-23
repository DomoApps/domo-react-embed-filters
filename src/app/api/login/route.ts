import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import db from '@/lib/db/db'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import fs from 'fs'
import path from 'path'

const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecretKey'

// Add a User interface for type safety
interface User {
  id: string
  username: string
  password: string
  lastLogin?: Date
  instance?: any
  embedID?: any
  dashboards?: any
  role?: string
  email?: string
}

export async function POST(req: NextRequest) {
  try {
    const { username, password } = await req.json()
    if (!username || !password) {
      return NextResponse.json(
        { message: 'Username and password are required' },
        { status: 400 }
      )
    }
    // Add type annotation for users
    const users = db.data.users as User[]
    // Convert username to lowercase for case-insensitive comparison
    const normalizedUsername = username.toLowerCase()
    const loggedOnUser = users.find(
      (user) => user.username.toLowerCase() === normalizedUsername
    )
    if (!loggedOnUser) {
      return NextResponse.json(
        { message: 'Invalid Credentials' },
        { status: 401 }
      )
    }
    // Compare password (assuming bcrypt hash)
    const isMatch = await bcrypt.compare(password, loggedOnUser.password)
    if (!isMatch) {
      return NextResponse.json(
        { message: 'Invalid Credentials' },
        { status: 401 }
      )
    }
    loggedOnUser.lastLogin = new Date()
    await db.write()
    const token = jwt.sign({ id: loggedOnUser.id }, JWT_SECRET, {
      expiresIn: '1h',
    })
    const { instance, embedID, dashboards, lastLogin, role, email } =
      loggedOnUser

    // Set cookie
    const response = NextResponse.json({
      instance,
      embedID,
      dashboards,
      lastLogin,
      role,
      email,
    })
    response.cookies.set('token', token, { httpOnly: true, path: '/' })
    return response
  } catch (err) {
    return NextResponse.json(
      { message: 'An error occurred during login.' },
      { status: 500 }
    )
  }
}
