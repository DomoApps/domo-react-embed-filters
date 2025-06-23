import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import db from '../../../lib/db/db'
import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecretKey'

interface User {
  id: string
  username: string
  password: string
  lastLogin?: Date
  instance?: any
  embedID?: any
  dashboards?: any[]
  role?: string
  email?: string
  mappingValue?: string
}

export async function GET(req: NextRequest) {
  try {
    const token = req.cookies.get('token')?.value
    if (!token) {
      return NextResponse.json(
        { message: 'No token provided' },
        { status: 401 }
      )
    }
    let decoded: any
    try {
      decoded = jwt.verify(token, JWT_SECRET)
    } catch (err) {
      return NextResponse.json({ message: 'Invalid token' }, { status: 401 })
    }
    const users = db.data.users as User[]
    const user = users.find((u) => u.id === decoded.id)
    if (!user) {
      return NextResponse.json({ message: 'User not found' }, { status: 404 })
    }
    // Map dashboards to include filter details
    const dashboardsWithFilters = (user.dashboards || []).map(
      (dashboard: any) => ({
        name: dashboard.name,
        embedID: dashboard.embedID,
        filters: dashboard.filter || []
      })
    )
    return NextResponse.json({ dashboards: dashboardsWithFilters })
  } catch (err: any) {
    return NextResponse.json(
      { message: 'Server error', error: err?.message },
      { status: 500 }
    )
  }
}
